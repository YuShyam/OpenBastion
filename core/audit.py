"""
OpenBastion 核心 - 帶內指令審計與防禦引擎 (In-Band Audit & Enforcement Engine)
=============================================================================
依據 docs/SPEC.md §2.3、§2.6 與 Phase 4 規格實作。
負責 PTY 終端擊鍵還原、機敏資訊脫敏過濾、三級防禦規則判定與審計日誌原子落盤。

核心設計：
  1. 終端命令還原：解析退格鍵 (\x08/\x7F) 與換行符號 (\r/\n)，重組使用者輸入的命令列。
  2. 機敏資訊脫敏 (Sanitization)：自動遮蔽密碼、Token、資料庫連線字串，避免日誌洩漏敏感資訊。
  3. 三級防禦機制 (Three-Tier Enforcement):
     - LOG   (第 1 級): 常規操作直接追加記錄於 audit_logs。
     - ALERT (第 2 級): 敏感操作發送帶內警語提示，允許執行。
     - BLOCK (第 3 級): 高風險危險操作立即阻斷並中止連線。
"""

import logging
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.storage import StorageProvider

logger = logging.getLogger("openbastion.audit")

# 機敏參數遮蔽正規表達式 (Password & Token Sanitization)
SENSITIVE_PATTERNS = [
    re.compile(r"(-p\s*)([^\s]+)", re.IGNORECASE),
    re.compile(r"(--password[=\s]+)([^\s]+)", re.IGNORECASE),
    re.compile(r"(password[=\s]+)([^\s]+)", re.IGNORECASE),
    re.compile(r"(token[=\s]+)([^\s]+)", re.IGNORECASE),
    re.compile(r"(secret[=\s]+)([^\s]+)", re.IGNORECASE),
]

# 阻斷黑名單指令規則 (Destructive Commands - BLOCK)
BLOCK_PATTERNS = [
    re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/(?:\s|$|\*)"),  # rm -rf / 或 rm -rf /*
    re.compile(r"\bmkfs(?:\.[a-zA-Z0-9]+)?\s+"),                          # 格式化磁碟
    re.compile(r"\bdd\s+if=/dev/(?:zero|urandom)\s+of=/dev/"),            # 破壞磁區
    re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),              # Fork Bomb 炸彈
]

# 警告提醒指令規則 (Sensitive Operations - ALERT)
ALERT_PATTERNS = [
    re.compile(r"\bsudo\s+(?:su|bash|sh|zsh)\b"),                         # 切換 Root Shell
    re.compile(r"\buser(?:del|add)\b"),                                    # 異動系統帳號
    re.compile(r"\b(?:vi|vim|nano)\s+/etc/"),                              # 編輯核心設定檔
    re.compile(r"\b(?:iptables|ufw|firewall-cmd)\b"),                      # 防火牆策略變更
]


class CommandSanitizer:
    """
    終端指令脫敏與敏感字串遮蔽處理器。
    Terminal command sanitization and sensitive credential masking processor.
    """

    @staticmethod
    def sanitize(command: str) -> str:
        if not command:
            return ""
        clean_cmd = command
        for pattern in SENSITIVE_PATTERNS:
            clean_cmd = pattern.sub(r"\1***REDACTED***", clean_cmd)
        return clean_cmd


class AuditEngine:
    """
    OpenBastion 核心指令審計與即時防禦引擎。
    Keystroke stream reconstruction, sensitive data masking, and multi-tier security policy enforcement.
    """

    def __init__(
        self,
        storage: StorageProvider,
        session_id: str,
        user_id: str,
        username: str,
        host_id: str,
        host_ip: str = "",
        host_name: str = "",
        on_block_action: Optional[Callable[[str], None]] = None,
        on_alert_action: Optional[Callable[[str], None]] = None,
    ) -> None:
        """
        初始化審計引擎實例。
        Initialize audit engine instance with storage and security policy callbacks.
        """
        self.storage = storage
        self.session_id = session_id
        self.user_id = user_id
        self.username = username
        self.host_id = host_id
        self.host_ip = host_ip
        self.host_name = host_name
        self.on_block_action = on_block_action
        self.on_alert_action = on_alert_action

        self._input_buffer: List[str] = []

    def feed_keystroke(self, data: bytes) -> Optional[Tuple[str, str, str]]:
        """
        接收客戶端擊鍵位元組流，還原終端命令行。
        Reconstruct command line from interactive keystroke byte stream with backspace handling.
        若偵測到換行符 (\r 或 \n)，觸發指令審計評估並落盤。
        回傳: (command_raw, command_clean, action_taken) 或 None。
        """
        if not data:
            return None

        text = data.decode("utf-8", errors="ignore")
        for ch in text:
            # 處理退格鍵 (Backspace: \x08 or \x7F)
            if ch in ("\x08", "\x7f"):
                if self._input_buffer:
                    self._input_buffer.pop()
            # 處理 Enter 送出指令 (\r or \n)
            elif ch in ("\r", "\n"):
                raw_command = "".join(self._input_buffer).strip()
                self._input_buffer.clear()
                if raw_command:
                    return self._evaluate_and_log(raw_command)
            # 過濾控制字元，僅累積可見字元與空格
            elif ord(ch) >= 0x20:
                self._input_buffer.append(ch)

        return None

    def _evaluate_and_log(self, command_raw: str) -> Tuple[str, str, str]:
        """
        比對安全策略規則，判定 LOG / ALERT / BLOCK，並持久化至 SQLite 審計表。
        Evaluate command against security policy rules and persist audit record to SQLite.
        """
        clean_cmd = CommandSanitizer.sanitize(command_raw)
        action_taken = "LOG"

        # 1. 檢核阻斷黑名單 (BLOCK)
        for pattern in BLOCK_PATTERNS:
            if pattern.search(command_raw):
                action_taken = "BLOCK"
                logger.warning(
                    "[SECURITY_BLOCK] 使用者 '%s' 於主機 '%s' 觸發高危阻斷指令: %s (High-risk command blocked)",
                    self.username,
                    self.host_id,
                    clean_cmd,
                )
                if self.on_block_action:
                    try:
                        self.on_block_action(clean_cmd)
                    except Exception as err:
                        logger.error("[CALLBACK_ERROR] 執行 BLOCK 回呼失敗: %s (Failed to execute BLOCK callback: %s)", err, err)
                break

        # 2. 檢核警告規則 (ALERT)
        if action_taken == "LOG":
            for pattern in ALERT_PATTERNS:
                if pattern.search(command_raw):
                    action_taken = "ALERT"
                    logger.info(
                        "[SECURITY_ALERT] 使用者 '%s' 於主機 '%s' 執行敏感操作: %s (Sensitive operation alerted)",
                        self.username,
                        self.host_id,
                        clean_cmd,
                    )
                    if self.on_alert_action:
                        try:
                            self.on_alert_action(clean_cmd)
                        except Exception as err:
                            logger.error("[CALLBACK_ERROR] 執行 ALERT 回呼失敗: %s (Failed to execute ALERT callback: %s)", err, err)
                    break

        # 3. 追加寫入審計日誌表 (Append-Only with K-Sortable audit_id)
        try:
            self.storage.log_audit_event(
                session_id=self.session_id,
                user_id=self.user_id,
                username=self.username,
                host_id=self.host_id,
                host_ip=self.host_ip,
                host_name=self.host_name,
                event_type="COMMAND" if action_taken != "BLOCK" else "BLOCK",
                command_raw=command_raw,
                command_clean=clean_cmd,
                action_taken=action_taken,
            )
        except Exception as err:
            logger.error("[AUDIT_ERROR] 寫入審計日誌資料表失敗: %s (Failed to write audit event to database: %s)", err, err)

        return (command_raw, clean_cmd, action_taken)
