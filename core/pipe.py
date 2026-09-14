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
import time
from typing import Any, Awaitable, Callable, Deque, Optional, Union

import asyncssh

logger = logging.getLogger("openbastion.pipe")

DEFAULT_RING_BUFFER_BYTES = 512 * 1024  # 512KB 環形重繪緩衝區
ESCAPE_KEY_CTRL_BRACKET = b"\x1d"  # Ctrl + ] 預設逃逸鍵 (RFC / Telnet 標準)


def parse_escape_key(key_repr: Optional[Union[str, bytes]]) -> bytes:
    """
    解析逃逸鍵字串或位元組為標準單字節 ASCII 控制碼。
    Parse escape key representation string or bytes into single-byte ASCII control code.

    支援格式 / Supported formats:
        - "ctrl_]" | "ctrl-]" | "^]" -> b"\x1d" (預設)
        - "ctrl_\\" | "ctrl-\\" | "^\\" -> b"\x1c"
        - "ctrl_~" | "ctrl-~" | "^~" | "^^" -> b"\x1e"
        - "ctrl_@" | "ctrl-@" | "^@" -> b"\x00"
        - "ctrl_a".."ctrl_z" | "^a".."^z" -> b"\x01"..b"\x1a"
        - 原始 bytes (長度 1)
    """
    if isinstance(key_repr, bytes) and len(key_repr) == 1:
        return key_repr
    if not key_repr or not isinstance(key_repr, str):
        return ESCAPE_KEY_CTRL_BRACKET

    k = key_repr.strip().lower()
    mapping = {
        "ctrl_]": b"\x1d",
        "ctrl-]": b"\x1d",
        "^]": b"\x1d",
        "ctrl_\\": b"\x1c",
        "ctrl-\\": b"\x1c",
        "^\\": b"\x1c",
        "ctrl_~": b"\x1e",
        "ctrl-~": b"\x1e",
        "^~": b"\x1e",
        "^^": b"\x1e",
        "ctrl_@": b"\x00",
        "ctrl-@": b"\x00",
        "^@": b"\x00",
        "0x1d": b"\x1d",
        "\\x1d": b"\x1d",
        "0x1c": b"\x1c",
        "\\x1c": b"\x1c",
    }
    if k in mapping:
        return mapping[k]

    import re
    m = re.match(r"^(?:ctrl[_\-]|(?:\^))([a-z])$", k)
    if m:
        char = m.group(1)
        ascii_val = ord(char) - ord("a") + 1
        return bytes([ascii_val])

    return ESCAPE_KEY_CTRL_BRACKET


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
        max_ttl_seconds: int = 480 * 60,
        idle_timeout_seconds: int = 15 * 60,
        escape_key: Union[str, bytes] = ESCAPE_KEY_CTRL_BRACKET,
    ) -> None:
        """
        初始化字元水管實例 (配置雙向流、環形重繪區與雙軌時效看門狗)。
        Initialize stream pipe instance with I/O streams, callbacks, and dual-TTL watchdog.

        參數 / Args:
            client_reader: 客戶端輸入字元讀取流
            client_writer: 客戶端終端輸出寫入流
            target_reader: 目標主機 PTY 輸出讀取流
            target_writer: 目標主機 PTY 輸入寫入流
            on_input: 輸入字元採樣回調 (非同步推送錄影與審計)
            on_output: 輸出字元採樣回調 (推送錄影)
            on_escape: 偵測到逃逸按鍵時之回調
            buffer_size: 環形緩衝區大小 (預設 512KB)
            target_process: 目標端遠端進程實體 (支援終端大小自動重繪)
            max_ttl_seconds: 單次連線最大時效秒數 (0 代表無上限)
            idle_timeout_seconds: 閒置連續無操作中斷秒數 (0 代表無上限)
            escape_key: 脫離目標終端之逃逸按鍵 (預設 Ctrl + ])
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
        self.max_ttl_seconds = max_ttl_seconds
        self.idle_timeout_seconds = idle_timeout_seconds
        self.escape_key = parse_escape_key(escape_key)

        self._is_running = False
        self._stop_event = asyncio.Event()
        self._tasks: list[asyncio.Task] = []
        self._write_lock = asyncio.Lock()

        self._start_time: float = 0.0
        self._last_active_time: float = 0.0
        self._watchdog_exit_reason: Optional[str] = None
        self._warned_5m = False
        self._warned_1m = False

    async def run(self) -> str:
        """
        啟動雙向字元轉發與時效看門狗，等待任意一方結束、逾時或使用者按下逃逸鍵。
        Start bidirectional pumping and watchdog, waiting for termination, timeout, or escape.
        回傳退出原因：'escape'、'idle_timeout'、'max_ttl_expired'、'target_closed'、'client_closed'、'normal'。
        """
        self._is_running = True
        self._stop_event.clear()
        now = time.monotonic()
        self._start_time = now
        self._last_active_time = now
        self._watchdog_exit_reason = None
        self._warned_5m = False
        self._warned_1m = False

        task_c2t = asyncio.create_task(self._pump_client_to_target(), name="pipe_c2t")
        task_t2c = asyncio.create_task(self._pump_target_to_client(), name="pipe_t2c")
        task_stop = asyncio.create_task(self._stop_event.wait(), name="pipe_stop")
        task_watchdog = asyncio.create_task(self._watchdog_loop(), name="pipe_watchdog")
        self._tasks = [task_c2t, task_t2c, task_stop, task_watchdog]

        # 等待停止信號、任一幫浦結束或看門狗逾時
        done, pending = await asyncio.wait(
            [task_stop, task_c2t, task_t2c, task_watchdog],
            return_when=asyncio.FIRST_COMPLETED,
        )

        exit_reason = self._watchdog_exit_reason or "normal"
        if not self._watchdog_exit_reason:
            if task_c2t.done() and not task_c2t.cancelled():
                res = task_c2t.result()
                if res == "escape":
                    exit_reason = "escape"
                elif res == "client_eof":
                    exit_reason = "client_closed"
            if task_t2c.done() and not task_t2c.cancelled() and exit_reason == "normal":
                exit_reason = "target_closed"

        # 安全終止尚未結束的非同步協程
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

                # 收到使用者鍵盤敲擊，重設閒置活躍時間戳記
                self._last_active_time = time.monotonic()
                raw_bytes = data.encode("utf-8") if isinstance(data, str) else data

                # 偵測逃逸組合鍵
                if self.escape_key in raw_bytes:
                    logger.info("[ESCAPE_TRIGGERED] 偵測到連線者按下逃逸鍵，請求返回跳板機選單 (Escape key triggered, returning to menu)")
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

    async def _watchdog_loop(self) -> str:
        """
        時效看門狗協程：即時監控會話生命週期硬上限與閒置超時。
        Session lifecycle watchdog monitoring max TTL and idle timeout.
        """
        try:
            while self._is_running:
                await asyncio.sleep(0.5)
                now = time.monotonic()

                # 1. 閒置超時看門狗 (Idle Watchdog)
                if self.idle_timeout_seconds > 0:
                    idle_elapsed = now - self._last_active_time
                    if idle_elapsed >= self.idle_timeout_seconds:
                        idle_mins = int(self.idle_timeout_seconds // 60) or 1
                        warn_msg = f"\r\n\033[1;31m[TIMEOUT] 連線已連續閒置超過 {idle_mins} 分鐘，系統已主動安全中斷連線 (Idle timeout reached, session disconnected)\033[0m\r\n"
                        await self.inject_inband_message(warn_msg)
                        logger.warning(
                            "[IDLE_TIMEOUT] 連線連續閒置 %d 秒，達到上限 %d 秒，觸發主動斷線 (Idle timeout triggered)",
                            int(idle_elapsed),
                            self.idle_timeout_seconds,
                        )
                        self._watchdog_exit_reason = "idle_timeout"
                        self.stop()
                        return "idle_timeout"

                # 2. 單次會話生命週期硬上限 (Max Session TTL)
                if self.max_ttl_seconds > 0:
                    total_elapsed = now - self._start_time
                    remaining = self.max_ttl_seconds - total_elapsed

                    # 到期前 5 分鐘廣播提醒 (若總上限大於 5 分鐘且尚未廣播過)
                    if remaining <= 300 and remaining > 60 and not self._warned_5m and self.max_ttl_seconds > 300:
                        self._warned_5m = True
                        warn_msg = "\r\n\033[1;33m[系統通知] 本次連線將在 5 分鐘後達到時效硬上限，請儘速存檔並準備結束作業 (Session will reach max TTL in 5 mins)\033[0m\r\n"
                        await self.inject_inband_message(warn_msg)
                        logger.info("[TTL_WARN_5M] 發送 5 分鐘到期倒數廣播通知 (Sent 5-minute TTL warning broadcast)")

                    # 到期前 1 分鐘廣播提醒
                    if remaining <= 60 and remaining > 0 and not self._warned_1m and self.max_ttl_seconds > 60:
                        self._warned_1m = True
                        warn_msg = "\r\n\033[1;33m[系統通知] 本次連線將在 1 分鐘後達到時效硬上限，連線即將強制中斷 (Session will terminate in 1 min)\033[0m\r\n"
                        await self.inject_inband_message(warn_msg)
                        logger.info("[TTL_WARN_1M] 發送 1 分鐘到期倒數廣播通知 (Sent 1-minute TTL warning broadcast)")

                    # 達到硬上限強制終止
                    if total_elapsed >= self.max_ttl_seconds:
                        ttl_hours = round(self.max_ttl_seconds / 3600, 1)
                        warn_msg = f"\r\n\033[1;31m[TTL_EXPIRED] 本次連線已達到單次會話生命週期硬上限 ({ttl_hours} 小時)，系統已強制切斷 (Max session TTL reached, session terminated)\033[0m\r\n"
                        await self.inject_inband_message(warn_msg)
                        logger.warning(
                            "[MAX_TTL_EXPIRED] 連線累計時長 %d 秒，達到硬上限 %d 秒，強制切斷連線 (Max session TTL expired)",
                            int(total_elapsed),
                            self.max_ttl_seconds,
                        )
                        self._watchdog_exit_reason = "max_ttl_expired"
                        self.stop()
                        return "max_ttl_expired"
        except asyncio.CancelledError:
            pass
        except Exception as err:
            logger.debug("[WATCHDOG_ERR] 看門狗協程異常退出: %s (Watchdog loop error: %s)", err, err)
        return "watchdog_done"

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
