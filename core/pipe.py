"""
OpenBastion 核心 - 雙向字元串流水管與斷線接回引擎 (StreamPipe & Reattach Engine)
=============================================================================
依據 docs/SPEC.md §2.3 (Bidirectional Stream Pipe with Tap) 與 Phase 4 規格原生實作。
提供非阻塞雙向終端轉發、512KB 環形重繪緩衝區、帶內插播與 Ctrl + ] 逃逸返回選單。

核心職責 / Responsibilities:
  1. 雙向非同步轉發 (Bidirectional Pump): 客戶端 PTY 與遠端目標 SSH 通道間的高效字元轉發。
  2. 旁路分流採樣 (Tap / Fork): 輸入/輸出事件無阻塞推送至審計引擎與 asciinema 錄影模組。
  3. 512KB 環形重繪緩衝 (RingBuffer): 記憶終端最後畫面字元流，供斷線重連 (Reattach) 時重繪最後終端畫面。
  4. 帶內通知插播 (In-Band Injection): 在不中斷原始 SSH 通道下，動態注入警告或倒數訊息。
  5. 逃逸熱鍵攔截 (Escape Sequence): 偵測 Ctrl + ] (0x1D) 組合鍵，退出目標主機並返回選單。
"""

import asyncio
import collections
import logging
from typing import Any, Awaitable, Callable, Deque, Optional, Union

import asyncssh

logger = logging.getLogger("openbastion.pipe")

DEFAULT_RING_BUFFER_BYTES = 512 * 1024  # 512KB 環形重繪緩衝區
ESCAPE_KEY_CTRL_BRACKET = b"\x1d"  # Ctrl + ] 預設逃逸鍵 (RFC / Telnet 標準)


class RingBuffer:
    """
    固定容量位元組環形緩衝區 (Byte Ring Buffer)。
    採用 collections.deque 保留最新 N 位元組輸出，自動丟棄舊資料，避免記憶體無限制增長。
    """

    def __init__(self, max_bytes: int = DEFAULT_RING_BUFFER_BYTES) -> None:
        self.max_bytes = max(1, max_bytes)
        self._chunks: Deque[bytes] = collections.deque()
        self._current_size = 0

    def write(self, data: bytes) -> None:
        """
        寫入位元組資料塊並動態修剪舊資料以維持在容量上限內。
        Write byte chunk and prune oldest data to maintain within capacity limit.
        """
        if not data:
            return
        self._chunks.append(data)
        self._current_size += len(data)

        while self._current_size > self.max_bytes and self._chunks:
            popped = self._chunks.popleft()
            self._current_size -= len(popped)

    def get_snapshot(self) -> bytes:
        """
        取得當前緩衝區中所有累積位元組之快照 (用於斷線接回重繪畫面)。
        Get snapshot of all accumulated bytes in buffer for terminal reattach repaint.
        """
        return b"".join(self._chunks)

    def clear(self) -> None:
        """
        清空緩衝區。
        Clear ring buffer contents and reset size counter.
        """
        self._chunks.clear()
        self._current_size = 0

    @property
    def current_size(self) -> int:
        return self._current_size


class StreamPipe:
    """
    雙向非阻塞字元轉發水管。
    Bidirectional non-blocking stream pipe connecting client PTY and remote SSH channel.
    """

    def __init__(
        self,
        client_reader: Any,
        client_writer: Any,
        target_reader: Any,
        target_writer: Any,
        on_input: Optional[Callable[[bytes], None]] = None,
        on_output: Optional[Callable[[bytes], None]] = None,
        on_escape: Optional[Callable[[], None]] = None,
        buffer_size: int = DEFAULT_RING_BUFFER_BYTES,
        target_process: Optional[Any] = None,
    ) -> None:
        """
        初始化字元水管實例。
        Initialize stream pipe instance with I/O streams and callbacks.
        """
        self.client_reader = client_reader
        self.client_writer = client_writer
        self.target_reader = target_reader
        self.target_writer = target_writer
        self.target_process = target_process

        self.on_input = on_input
        self.on_output = on_output
        self.on_escape = on_escape

        self.ring_buffer = RingBuffer(max_bytes=buffer_size)
        self._is_running = False
        self._stop_event = asyncio.Event()
        self._tasks: list[asyncio.Task] = []
        self._write_lock = asyncio.Lock()

    async def run(self) -> str:
        """
        啟動雙向字元轉發，等待任意一方結束或使用者按下逃逸鍵。
        Start bidirectional character pumping, waiting for termination or escape key.
        回傳退出原因：'escape'、'target_closed'、'client_closed'、'error'。
        """
        self._is_running = True
        self._stop_event.clear()

        task_c2t = asyncio.create_task(self._pump_client_to_target(), name="pipe_c2t")
        task_t2c = asyncio.create_task(self._pump_target_to_client(), name="pipe_t2c")
        task_stop = asyncio.create_task(self._stop_event.wait(), name="pipe_stop")
        self._tasks = [task_c2t, task_t2c, task_stop]

        # 等待停止信號或任一幫浦結束
        done, pending = await asyncio.wait(
            [task_stop, task_c2t, task_t2c],
            return_when=asyncio.FIRST_COMPLETED,
        )

        exit_reason = "normal"
        if task_c2t.done() and not task_c2t.cancelled():
            res = task_c2t.result()
            if res == "escape":
                exit_reason = "escape"
            elif res == "client_eof":
                exit_reason = "client_closed"
        if task_t2c.done() and not task_t2c.cancelled() and exit_reason == "normal":
            exit_reason = "target_closed"

        # 安全終止尚未結束的非同步幫浦
        self._is_running = False
        for t in pending:
            t.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

        return exit_reason

    @staticmethod
    def _write_adaptive(writer: Any, data: Union[bytes, str]) -> None:
        """
        自適應字元串流寫入器，自動相容位元組通道與字元編碼通道。
        Adaptive stream writer supporting both byte and text encoded streams.
        """
        try:
            writer.write(data)
        except TypeError:
            if isinstance(data, bytes):
                writer.write(data.decode("utf-8", errors="replace"))
            elif isinstance(data, str):
                writer.write(data.encode("utf-8", errors="replace"))
            else:
                raise

    async def _pump_client_to_target(self) -> str:
        """
        客戶端輸入 -> 目標主機 PTY (兼具逃逸偵測與審計採樣)。
        Pump client keystrokes to target PTY with escape key detection and audit tap.
        """
        try:
            while self._is_running:
                # 讀取客戶端擊鍵 (捕捉 TerminalSizeChanged 轉發遠端 PTY)
                try:
                    if hasattr(self.client_reader, "read"):
                        data = await self.client_reader.read(4096)
                    elif hasattr(self.client_reader, "readline"):
                        data = await self.client_reader.read(4096)
                    else:
                        break
                except asyncssh.TerminalSizeChanged as exc:
                    logger.debug("[TERM_RESIZE] 終端視窗變更事件: %dx%d (%dx%d px) (Terminal window resize event)", exc.width, exc.height, exc.pixwidth, exc.pixheight)
                    if self.target_process and hasattr(self.target_process, "change_terminal_size"):
                        try:
                            self.target_process.change_terminal_size(exc.width, exc.height, exc.pixwidth, exc.pixheight)
                        except Exception as resize_err:
                            logger.debug("[RESIZE_FAILED] 轉發目標主機終端尺寸失敗: %s (Failed to forward terminal resize: %s)", resize_err, resize_err)
                    continue

                if not data:
                    return "client_eof"

                raw_bytes = data.encode("utf-8") if isinstance(data, str) else data

                # 偵測 Ctrl + ] 逃逸組合鍵
                if ESCAPE_KEY_CTRL_BRACKET in raw_bytes:
                    logger.info("[ESCAPE_TRIGGERED] 偵測到連線者按下 Ctrl + ] 逃逸鍵，請求返回跳板機選單 (Escape key Ctrl+] triggered, returning to menu)")
                    if self.on_escape:
                        try:
                            self.on_escape()
                        except Exception:
                            pass
                    self._stop_event.set()
                    return "escape"

                # 旁路分流至審計採樣孔
                if self.on_input:
                    try:
                        self.on_input(raw_bytes)
                    except Exception as err:
                        logger.warning("[AUDIT_INPUT_WARN] 審計輸入採樣時發生警告: %s (Warning during audit input tap: %s)", err, err)

                # 轉發至目標主機
                if hasattr(self.target_writer, "write"):
                    self._write_adaptive(self.target_writer, raw_bytes)
                    if hasattr(self.target_writer, "drain"):
                        await self.target_writer.drain()
        except asyncio.CancelledError:
            pass
        except Exception as err:
            logger.debug("[PUMP_CLOSED] 客戶端輸入幫浦關閉: %s (Client input pump closed: %s)", err, err)
        return "client_done"

    async def _pump_target_to_client(self) -> str:
        """
        目標主機輸出 -> 客戶端 PTY (兼具錄影分流與環形緩衝累積)。
        Pump target output to client PTY with recording tap and ring buffer snapshot.
        """
        try:
            while self._is_running:
                if hasattr(self.target_reader, "read"):
                    data = await self.target_reader.read(8192)
                else:
                    break

                if not data:
                    return "target_eof"

                raw_bytes = data.encode("utf-8") if isinstance(data, str) else data

                # 累積至 512KB 環形緩衝區供斷線重連重繪使用
                self.ring_buffer.write(raw_bytes)

                # 旁路分流至 asciinema 錄影採樣孔
                if self.on_output:
                    try:
                        self.on_output(raw_bytes)
                    except Exception as err:
                        logger.warning("[RECORDER_OUTPUT_WARN] 錄影輸出採樣時發生警告: %s (Warning during recorder output tap: %s)", err, err)

                # 轉發至連線者終端
                async with self._write_lock:
                    if hasattr(self.client_writer, "write"):
                        self._write_adaptive(self.client_writer, raw_bytes)
                        if hasattr(self.client_writer, "drain"):
                            await self.client_writer.drain()
        except asyncio.CancelledError:
            pass
        except Exception as err:
            logger.debug("[PUMP_CLOSED] 目標端輸出幫浦關閉: %s (Target output pump closed: %s)", err, err)
        return "target_done"

    async def inject_inband_message(self, message: str) -> None:
        """
        向連線者終端帶內插播動態訊息 (如管理員廣播、授權即將到期警告或 Banner)。
        Inject in-band dynamic message to client terminal safely under write lock.
        採用 write_lock 避免與目標主機字元流並行寫入時破壞終端格式。
        """
        if not message:
            return
        async with self._write_lock:
            try:
                if hasattr(self.client_writer, "write"):
                    self._write_adaptive(self.client_writer, message)
                    if hasattr(self.client_writer, "drain"):
                        await self.client_writer.drain()
            except Exception as err:
                logger.warning("[INBAND_INJECT_FAILED] 帶內通知插播失敗: %s (Failed to inject in-band message: %s)", err, err)

    def get_replay_snapshot(self) -> bytes:
        """
        取得當前環形緩衝區快照，供連線接回 (Reattach) 時回放畫面。
        Get current ring buffer snapshot for replaying terminal screen on session reattach.
        """
        return self.ring_buffer.get_snapshot()

    def stop(self) -> None:
        """
        主動觸發停止轉發。
        Stop character forwarding pump and signal stop event.
        """
        self._is_running = False
        self._stop_event.set()
