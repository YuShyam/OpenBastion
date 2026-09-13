"""
OpenBastion 核心 - asciinema v2 旁路錄影模組 (Session Recorder)
=============================================================
依據 docs/SPEC.md §3.4 與 Phase 4 規格實作。
產生符合 asciinema v2 (.cast) 開放標準之終端會話錄影檔案，具備不可變雜湊校驗與 0600 權限保護。

核心設計：
  1. 標準格式：首行寫入 v2 標頭，後續以串流追加 [timestamp, "o" | "i", data] 事件。
  2. 權限管控：產出檔案嚴格限制為 0600 權限，防止目標伺服器其他使用者讀取。
  3. 雜湊校驗：會話關閉時即時計算 SHA-256 雜湊值並回傳，供審計資料庫存證。
  4. 異常耐受：終端字元編碼異常時採替換原則，保證日誌不因特殊控制字元中斷。
"""

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("openbastion.recorder")

DEFAULT_RECORDINGS_DIR = Path("recordings")


class AsciinemaRecorder:
    """
    符合 asciinema v2 規範之非同步會話錄影器。
    Streams terminal I/O events into standardized .cast files with SHA-256 integrity seal.
    """

    def __init__(
        self,
        session_id: str,
        output_dir: Optional[Path] = None,
        width: int = 80,
        height: int = 24,
    ) -> None:
        """
        初始化會話錄影器實例。
        Initialize session recorder instance for asciinema v2 format.
        """
        self.session_id = session_id
        self.output_dir = output_dir or DEFAULT_RECORDINGS_DIR
        self.width = max(20, width)
        self.height = max(5, height)

        self._file = None
        self._file_path: Optional[Path] = None
        self._start_time: float = 0.0
        self._is_active = False

    def start(self) -> Path:
        """
        開啟錄影檔案並寫入 asciinema v2 標頭資訊。
        Open recording file and write asciinema v2 header metadata.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        date_str = time.strftime("%Y%m%d")
        safe_sid = self.session_id.replace("/", "_").replace("\\", "_")
        self._file_path = self.output_dir / f"{date_str}_{safe_sid}.cast"

        self._file = open(self._file_path, "w", encoding="utf-8", buffering=1)  # 行緩衝
        if os.name != "nt":
            try:
                os.chmod(self._file_path, 0o600)
            except Exception:
                pass

        self._start_time = time.time()
        self._is_active = True

        header = {
            "version": 2,
            "width": self.width,
            "height": self.height,
            "timestamp": int(self._start_time),
            "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"},
            "title": f"OpenBastion Session {self.session_id}",
        }
        self._file.write(json.dumps(header, ensure_ascii=False) + "\n")
        logger.info("[RECORDER_START] 已建立 asciinema v2 錄影檔: %s (Created asciinema v2 recording file: %s)", self._file_path, self._file_path)
        return self._file_path

    def record_output(self, data: bytes) -> None:
        """
        記錄目標主機輸出字元流事件 (Event Type: 'o')。
        Record target host output stream events.
        """
        if not self._is_active or not self._file or not data:
            return

        elapsed = round(time.time() - self._start_time, 6)
        text = data.decode("utf-8", errors="replace")
        event = [elapsed, "o", text]
        try:
            self._file.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception as err:
            logger.warning("[RECORDER_WARN] 寫入錄影輸出事件失敗: %s (Failed to write output event: %s)", err, err)

    def record_input(self, data: bytes) -> None:
        """
        記錄使用者鍵入之輸入字元流事件 (Event Type: 'i')。
        Record client input stream events.
        """
        if not self._is_active or not self._file or not data:
            return

        elapsed = round(time.time() - self._start_time, 6)
        text = data.decode("utf-8", errors="replace")
        event = [elapsed, "i", text]
        try:
            self._file.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception as err:
            logger.warning("[RECORDER_WARN] 寫入錄影輸入事件失敗: %s (Failed to write input event: %s)", err, err)

    def close(self) -> Tuple[Path, int, str, float]:
        """
        關閉錄影檔案，計算檔案大小與 SHA-256 雜湊摘要。
        Close recording file, calculate final file size and SHA-256 integrity hash.
        回傳: (檔案路徑, 檔案大小, SHA256雜湊, 總秒數)
        """
        if not self._is_active:
            return (self._file_path or Path(), 0, "", 0.0)

        duration = round(time.time() - self._start_time, 2)
        self._is_active = False

        if self._file:
            try:
                self._file.flush()
                self._file.close()
            except Exception:
                pass
            self._file = None

        file_size = 0
        sha256_hash = ""
        if self._file_path and self._file_path.is_file():
            file_size = self._file_path.stat().st_size
            hasher = hashlib.sha256()
            try:
                with open(self._file_path, "rb") as f:
                    while chunk := f.read(65536):
                        hasher.update(chunk)
                sha256_hash = hasher.hexdigest()
            except Exception as err:
                logger.error("[RECORDER_ERROR] 計算錄影檔案 SHA-256 失敗: %s (Failed to compute SHA-256 integrity hash: %s)", err, err)

        logger.info(
            "[RECORDER_CLOSED] 錄影會話結束 [ID: %s, 大小: %d 位元組, 耗時: %.2fs, SHA: %s...] (Recording session finished)",
            self.session_id,
            file_size,
            duration,
            sha256_hash[:16],
        )
        return (self._file_path or Path(), file_size, sha256_hash, duration)
