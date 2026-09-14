"""
OpenBastion Core - 身份驗證提供者與憑證管線抽象層 (Authentication Provider & Credential Pipeline)
========================================================================================
依據 docs/work/AUTH_EXPANSION_DESIGN.md §2 (身份認證管線) 規格書規範。
Authentication decoupling layer providing standard SPI interfaces and SQLite implementation.

核心職責 / Responsibilities:
  1. 認證領域模型 (AuthUser Domain Model)：標準化跨提供者之身分標識與安全上下文。
  2. 身份驗證 SPI (IAuthProvider)：宣告可外掛式認證提供者核心合約 (可同步或非同步)。
  3. 預設儲存驅動認證實作 (SqliteAuthProvider)：無縫接軌原 SQLite WAL 加鹽雜湊鑑權機制。
  4. 零依賴核心架構 (Zero External Dependency in Core)：核心純標準函式庫，保護架構純度。
"""

import base64
import hashlib
import hmac
import inspect
import logging
import secrets
import struct
import time
import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Awaitable, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("openbastion.auth")


@dataclass
class AuthUser:
    """
    標準認證使用者上下文模型 (Authenticated User Context Domain Model)。
    Standardized user identity entity returned upon successful authentication.
    """

    id: int
    username: str
    display_name: str
    role: str = "user"  # "admin" | "user" | "auditor"
    department: str = "default"
    user_id: Optional[str] = None
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None
    max_session_ttl_minutes: int = 480  # 預設單次會話生命週期硬上限 8 小時 (480 分鐘)
    raw_user: Optional[Dict[str, Any]] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """
        初始化後自動校驗與補齊預設值。
        Auto-populate defaults and validate fields after instantiation.
        """
        if self.user_id is None:
            self.user_id = self.username
        if not self.display_name:
            self.display_name = self.username
        if not self.role:
            self.role = "user"
        if not self.department:
            self.department = "default"


class IAuthProvider(ABC):
    """
    身份驗證提供者服務提供者介面 (Authentication Provider Service Provider Interface, SPI)。
    Extensible authentication provider SPI for validating credentials and resolving users.
    """

    @abstractmethod
    def authenticate(
        self, username: str, password: str
    ) -> Union[Tuple[bool, Optional[AuthUser]], Awaitable[Tuple[bool, Optional[AuthUser]]]]:
        """
        驗證連線者提供之主憑證 (帳號密碼)。
        Authenticate user credentials against the underlying identity store.

        參數 / Args:
            username: 欲登入之使用者名稱 (有效純帳號，不含穿透標的)
            password: 使用者鍵入之明文密碼

        回傳 / Returns:
            (is_authenticated, auth_user) 之元組或其非同步協程 (Tuple or Awaitable tuple).
        """
        pass

    def get_user(
        self, username: str
    ) -> Union[Optional[AuthUser], Awaitable[Optional[AuthUser]]]:
        """
        依使用者帳號查找其完整身分實體 (選用方法，預設回傳 None)。
        Resolve AuthUser identity entity by username if supported by the provider.

        參數 / Args:
            username: 欲查詢之使用者名稱

        回傳 / Returns:
            AuthUser 實體、None 或其非同步協程 (AuthUser, None or Awaitable).
        """
        return None


class SqliteAuthProvider(IAuthProvider):
    """
    預設 SQLite 儲存層身分驗證提供者。
    Default SQLite-backed authentication provider wrapping StorageProvider PBKDF2 verification.
    """

    def __init__(self, storage: Optional[Any] = None) -> None:
        """
        初始化 SQLite 認證提供者實例。
        Initialize SQLite authentication provider instance with storage reference.

        參數 / Args:
            storage: 既有 StorageProvider 實例；若未提供則延遲建立預設實例。
        """
        if storage is None:
            from core.storage import StorageProvider

            self.storage = StorageProvider()
        else:
            self.storage = storage

    def authenticate(
        self, username: str, password: str
    ) -> Tuple[bool, Optional[AuthUser]]:
        """
        使用 SQLite 儲存驅動之 PBKDF2 加鹽雜湊驗證密碼。
        Validate credentials against SQLite database using constant-time PBKDF2 comparison.

        參數 / Args:
            username: 使用者名稱
            password: 明文密碼

        回傳 / Returns:
            (True, AuthUser) 驗證成功；或 (False, None) 驗證失敗。
        """
        ok, user_dict = self.storage.authenticate(username, password)
        if not ok or not user_dict:
            return False, None

        auth_user = AuthUser(
            id=user_dict.get("id", 0),
            username=user_dict.get("username", username),
            display_name=user_dict.get("display_name", username),
            role=user_dict.get("role", "user"),
            department=user_dict.get("department", "default"),
            user_id=user_dict.get("user_id", username),
            mfa_enabled=bool(user_dict.get("mfa_enabled", False)),
            mfa_secret=user_dict.get("mfa_secret"),
            raw_user=user_dict,
        )
        return True, auth_user

    def get_user(self, username: str) -> Optional[AuthUser]:
        """
        自 SQLite 查詢使用者紀錄並封裝為 AuthUser。
        Fetch user record from SQLite storage and convert into AuthUser domain entity.

        參數 / Args:
            username: 使用者名稱

        回傳 / Returns:
            AuthUser 實體或 None。
        """
        user_dict = self.storage.get_user_by_username(username)
        if not user_dict:
            return None

        return AuthUser(
            id=user_dict.get("id", 0),
            username=user_dict.get("username", username),
            display_name=user_dict.get("display_name", username),
            role=user_dict.get("role", "user"),
            department=user_dict.get("department", "default"),
            user_id=user_dict.get("user_id", username),
            mfa_enabled=bool(user_dict.get("mfa_enabled", False)),
            mfa_secret=user_dict.get("mfa_secret"),
            raw_user=user_dict,
        )


# =============================================================================
# 第二因子驗證 SPI 插件體系與原生 TOTP (MFA SPI & Zero-Dependency RFC 6238)
# =============================================================================

class IMfaProvider(ABC):
    """
    第二因子驗證插件服務介面 (MFA Service Provider Interface, SPI)。
    Extensible MFA SPI supporting RFC 4256 Keyboard-Interactive challenge-response.
    """

    @abstractmethod
    def is_enabled_for_user(self, user: AuthUser) -> bool:
        """
        判定該使用者是否需要此 MFA 驗證。
        Determine whether MFA challenge is required for the user (fail-safe bypass if disabled).
        """
        pass

    @abstractmethod
    def get_challenge(
        self, user: AuthUser, lang: str = ""
    ) -> Tuple[str, str, str, List[Tuple[str, bool]]]:
        """
        發起 RFC 4256 挑戰規格：
        回傳: (name, instructions, lang, [(prompt_text, echo_boolean)])
        """
        pass

    @abstractmethod
    def verify_response(
        self, user: AuthUser, responses: List[str]
    ) -> Union[bool, Awaitable[bool]]:
        """
        校驗使用者回傳之驗證碼 (支援同步與非同步)。
        Validate client response against MFA backend (supports sync or async awaitable).
        """
        pass


class TotpMfaProvider(IMfaProvider):
    """
    零依賴原生 RFC 6238 TOTP (Time-Based One-Time Password) 驗證提供者。
    Zero-dependency RFC 6238 TOTP provider with dynamic truncation, clock drift window, and anti-replay.
    """

    def __init__(self, storage: Optional[Any] = None, interval: int = 30, digits: int = 6, window: int = 1) -> None:
        self.storage = storage
        self.interval = interval
        self.digits = digits
        self.window = window  # 前後容錯步長 (1 代表 -30s ~ +30s，共 90 秒有效區間)

    @staticmethod
    def generate_secret(byte_len: int = 20) -> str:
        """
        生成標準 Base32 隨機金鑰 (預設 160-bit)。
        Generate standard Base32-encoded random secret key (160 bits by default).
        """
        raw = secrets.token_bytes(byte_len)
        return base64.b32encode(raw).decode("ascii").rstrip("=")

    @staticmethod
    def generate_scratch_codes(count: int = 8, code_len: int = 8) -> List[str]:
        """
        生成一次性緊急備援碼 (Scratch Codes)。
        Generate random alphanumeric scratch codes for emergency break-glass login.
        """
        codes = []
        for _ in range(count):
            c = "".join(secrets.choice("23456789ABCDEFGHJKLMNPQRSTUVWXYZ") for _ in range(code_len))
            codes.append(f"{c[:4]}-{c[4:]}")
        return codes

    @staticmethod
    def generate_provisioning_uri(secret: str, username: str, issuer: str = "OpenBastion") -> str:
        """
        生成相容 Google Authenticator / 1Password 之 otpauth:// URI。
        Generate standard otpauth:// URI compatible with authenticator apps.
        """
        clean_issuer = urllib.parse.quote(issuer)
        clean_user = urllib.parse.quote(username)
        # 補齊 Base32 padding 供標準客戶端解析
        pad_len = (8 - len(secret) % 8) % 8
        padded_secret = secret + ("=" * pad_len)
        return f"otpauth://totp/{clean_issuer}:{clean_user}?secret={padded_secret}&issuer={clean_issuer}&algorithm=SHA1&digits=6&period=30"

    @classmethod
    def compute_totp(cls, secret: str, for_time: Optional[float] = None, interval: int = 30, digits: int = 6) -> str:
        """
        純標準函式庫實作 RFC 6238 TOTP 與 RFC 4226 Dynamic Truncation。
        Pure standard library implementation of RFC 6238 TOTP dynamic truncation algorithm.
        """
        t_val = time.time() if for_time is None else for_time
        time_step = int(t_val // interval)
        time_bytes = struct.pack(">Q", time_step)

        # Base32 解碼金鑰 (自適應補充等號 padding)
        clean_sec = secret.strip().replace(" ", "").upper()
        pad_needed = (8 - len(clean_sec) % 8) % 8
        key_bytes = base64.b32decode(clean_sec + ("=" * pad_needed), casefold=True)

        # HMAC-SHA1 運算
        h = hmac.new(key_bytes, time_bytes, hashlib.sha1).digest()

        # Dynamic Truncation 取低 4 位元作為偏移量
        offset = h[-1] & 0x0F
        binary_code = struct.unpack(">I", h[offset : offset + 4])[0] & 0x7FFFFFFF
        otp = binary_code % (10 ** digits)
        return str(otp).zfill(digits)

    def verify_totp_code(
        self, secret: str, code: str, current_time: Optional[float] = None, last_step: int = 0
    ) -> Tuple[bool, int]:
        """
        校驗 TOTP 驗證碼是否在時間容錯窗口內命中，並檢核防重放 (Anti-Replay)。
        Validate TOTP code within clock drift window with anti-replay step verification.
        回傳: (is_valid, matched_step)
        """
        clean_code = code.strip().replace(" ", "")
        if not clean_code.isdigit() or len(clean_code) != self.digits:
            return False, 0

        t_now = time.time() if current_time is None else current_time
        current_step = int(t_now // self.interval)

        # 遍歷容錯窗口：current_step - window .. current_step + window
        for offset in range(-self.window, self.window + 1):
            step = current_step + offset
            # 防重放：若該步長已曾被消費，拒絕重複利用
            if step <= last_step:
                continue

            test_time = step * self.interval
            expected_code = self.compute_totp(secret, for_time=test_time, interval=self.interval, digits=self.digits)
            if secrets.compare_digest(clean_code, expected_code):
                return True, step

        return False, 0

    def is_enabled_for_user(self, user: AuthUser) -> bool:
        """
        檢查使用者與部門是否啟用 MFA (貫徹防範但不禁止原則)。
        Check whether MFA is enabled for user considering department policy and personal settings.
        """
        # 1. 檢查部門強制或免除策略
        if self.storage and hasattr(self.storage, "get_department_by_id") and user.raw_user:
            dept_id = user.raw_user.get("department_id")
            if dept_id:
                dept = self.storage.get_department_by_id(dept_id)
                if dept and dept.get("policy"):
                    import json
                    try:
                        p_dict = json.loads(dept["policy"])
                        mfa_pol = p_dict.get("mfa_policy", "optional")
                        if mfa_pol == "disabled":
                            return False
                        elif mfa_pol == "required":
                            return True
                    except Exception:
                        pass

        # 2. 依個人偏好與是否已綁定金鑰判定
        return bool(user.mfa_enabled and user.mfa_secret)

    def get_challenge(
        self, user: AuthUser, lang: str = ""
    ) -> Tuple[str, str, str, List[Tuple[str, bool]]]:
        """
        發起二階動態驗證碼挑戰 (嚴格純 7-bit ASCII 說明，根除客戶端八進位轉義亂碼)。
        Issue second-step challenge with clean 7-bit ASCII prompt to prevent octal escape artifacts.
        """
        name = "OpenBastion MFA"
        instruction = "Enter 6-digit TOTP verification code or recovery code:"
        prompts = [("Verification code: ", False)]
        return name, instruction, lang, prompts

    def verify_response(
        self, user: AuthUser, responses: List[str]
    ) -> bool:
        """
        校驗使用者回傳之動態驗證碼或緊急備援碼。
        Verify entered verification code against TOTP algorithm and emergency scratch codes.
        """
        if not responses or not responses[0]:
            return False

        input_code = responses[0].strip()
        user_id = user.user_id or user.username
        last_step = 0
        if user.raw_user:
            last_step = int(user.raw_user.get("last_totp_step") or 0)

        # 1. 優先嘗試 TOTP 算法核對
        if user.mfa_secret:
            ok, matched_step = self.verify_totp_code(user.mfa_secret, input_code, last_step=last_step)
            if ok:
                if self.storage and hasattr(self.storage, "update_user_totp_step"):
                    self.storage.update_user_totp_step(user_id, matched_step)
                logger.info(
                    "[MFA_TOTP_OK] 使用者 '%s' TOTP 動態碼校驗成功 (步長: %d) (TOTP verification succeeded)",
                    user.username,
                    matched_step,
                )
                return True

        # 2. 次之嘗試緊急備援碼 (Scratch Codes) 核銷
        if self.storage and hasattr(self.storage, "verify_and_consume_scratch_code"):
            clean_scratch = input_code.upper().replace(" ", "")
            if self.storage.verify_and_consume_scratch_code(user_id, clean_scratch):
                logger.warning(
                    "[MFA_SCRATCH_USED] 使用者 '%s' 成功使用一次性緊急備援碼登入並核銷 (Emergency scratch code consumed)",
                    user.username,
                )
                return True

        logger.warning(
            "[MFA_FAILED] 使用者 '%s' 第二因子驗證碼比對失敗 (Invalid MFA verification code)",
            user.username,
        )
        return False


class DisabledMfaProvider(IMfaProvider):
    """
    空實作 MFA 提供者 (永遠略過第二因子挑戰)。
    Null MFA provider that always bypasses second-factor challenges.
    """

    def is_enabled_for_user(self, user: AuthUser) -> bool:
        return False

    def get_challenge(
        self, user: AuthUser, lang: str = ""
    ) -> Tuple[str, str, str, List[Tuple[str, bool]]]:
        return "Disabled MFA", "", lang, []

    def verify_response(
        self, user: AuthUser, responses: List[str]
    ) -> bool:
        return True

