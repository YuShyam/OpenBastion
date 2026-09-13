"""
OpenBastion 核心 - 憑證保管庫與硬體特徵繫結驅動 (Credential Vault & Hardware Binding)
===================================================================================
依據 docs/SPEC.md §3.5 與 ADR-001 架構規範原生實作。
原生支援 AES-256-GCM 認證加密、多維度硬體特徵金鑰派生、冪等防重複加密與加密備份封套。

設計原則：
  1. 金鑰衍生：以 HKDF 結合系統主金鑰 (Master Key) 與本機硬體特徵 (Hardware Traits) 派生加密金鑰。
  2. 冪等與平滑相容：防止重複加密，對歷史明文字串支援安全相容讀取。
  3. 防竄改完整性簽章：基於衍生金鑰計算 HMAC-SHA256 驗證標籤。
  4. 可攜性備份封套：管理員可透過高強度通行碼匯出加密封套，供跨機移轉使用。
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import platform
import secrets
import socket
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from core.i18n import t

logger = logging.getLogger("openbastion.vault")

# 備份封套格式識別碼與演算法參數
VAULT_MAGIC_HEADER = b"OBVAULT1"
BACKUP_KDF_ROUNDS = 600_000
CIPHER_PREFIX = "v1:"
DEFAULT_STORAGE_DIR = Path("data")


def collect_hardware_fingerprint() -> str:
    """
    採集本機系統環境的多維度硬體特徵，生成專屬雜湊摘要。
    Collect multi-dimensional hardware traits to generate a machine-specific hash digest.
    結合作業系統識別碼、主機板 UUID、網路節點與平台資訊。
    """
    traits: List[str] = []
    sys_name = platform.system().lower()

    # 1. 取得作業系統層級唯一識別碼
    if "windows" in sys_name:
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            ) as reg_key:
                guid, _ = winreg.QueryValueEx(reg_key, "MachineGuid")
                if guid:
                    traits.append(f"win_guid:{str(guid).strip()}")
        except Exception:
            pass

    elif "linux" in sys_name:
        for filepath in ("/etc/machine-id", "/var/lib/dbus/machine-id", "/sys/class/dmi/id/product_uuid"):
            p = Path(filepath)
            if p.is_file():
                try:
                    val = p.read_text(encoding="utf-8").strip()
                    if val:
                        traits.append(f"linux_id:{val}")
                        break
                except Exception:
                    continue

    # 2. 補充實體網卡節點識別 (MAC Node)
    try:
        traits.append(f"node:{hex(uuid.getnode())}")
    except Exception:
        pass

    # 3. 補充主機名與作業系統核心特徵
    try:
        traits.append(f"host:{socket.gethostname()}")
        traits.append(f"plat:{platform.platform(aliased=True)}")
    except Exception:
        pass

    # 若特定容器環境受限導致無任何特徵，使用基礎回退標記
    if not traits:
        traits.append("openbastion:default:container_fallback")

    raw_signature = "|".join(traits)
    return hashlib.sha256(raw_signature.encode("utf-8")).hexdigest()


class CredentialVault:
    """
    OpenBastion 憑證保管庫核心實作類別。
    OpenBastion hardware-bound credential vault with AES-256-GCM encryption and HMAC signing.
    提供受硬體保護的字串加解密、防竄改簽核與跨環境加密備份匯出匯入。
    """

    def __init__(
        self,
        master_key: Optional[str] = None,
        hardware_id: Optional[str] = None,
        key_storage_path: Optional[Path] = None,
    ) -> None:
        """
        初始化保管庫實例，載入主金鑰並派生專屬對稱加密金鑰。
        Initialize vault instance, load master key, and derive machine-bound symmetric key.
        """
        self.hardware_id = hardware_id or collect_hardware_fingerprint()
        self._key_path = key_storage_path or (DEFAULT_STORAGE_DIR / ".master_key")
        self._master_bytes = self._obtain_master_key(master_key)
        self._active_key = self._derive_symmetric_key(self._master_bytes, self.hardware_id)
        self._cipher = AESGCM(self._active_key)

    def _obtain_master_key(self, explicit_key: Optional[str]) -> bytes:
        """
        解析主金鑰來源：明確傳入 -> 環境變數 OPENBASTION_MASTER_KEY -> 檔案系統持久化金鑰。
        Resolve master key from explicit argument, environment variable, or persistent file.
        """
        if explicit_key:
            return hashlib.sha256(explicit_key.encode("utf-8")).digest()

        env_val = os.environ.get("OPENBASTION_MASTER_KEY")
        if env_val:
            return hashlib.sha256(env_val.encode("utf-8")).digest()

        # 從設定檔目錄載入已存在的本機金鑰
        if self._key_path.is_file():
            try:
                raw = self._key_path.read_bytes().strip()
                if len(raw) == 32:
                    return raw
                # 兼容 64 字元十六進位字串格式
                text = raw.decode("utf-8", errors="ignore").strip()
                if len(text) == 64:
                    return bytes.fromhex(text)
            except Exception as err:
                logger.warning("[VAULT_WARN] 載入本地主金鑰檔案失敗，即將重新生成: %s (Failed to load local master key, regenerating: %s)", err, err)

        # 初始啟動時自動生成 32 位元組高熵隨機金鑰
        self._key_path.parent.mkdir(parents=True, exist_ok=True)
        fresh_key = secrets.token_bytes(32)
        try:
            self._key_path.write_bytes(fresh_key)
            if os.name != "nt":
                os.chmod(self._key_path, 0o600)
            logger.info("[VAULT_KEY_GEN] 已生成並保存本地主金鑰至 %s (Generated and stored local master key: %s)", self._key_path, self._key_path)
        except Exception as err:
            logger.warning("[VAULT_WARN] 寫入本地主金鑰檔案時發生警告: %s (Warning writing master key file: %s)", err, err)

        return fresh_key

    def _derive_symmetric_key(self, master_bytes: bytes, hw_signature: str) -> bytes:
        """
        以 HKDF-SHA256 結合主金鑰與主機特徵摘要，派生 256 位元對稱金鑰。
        Derive 256-bit symmetric key using HKDF-SHA256 combining master key and hardware signature.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"openbastion_vault_hkdf_salt_v1",
            info=f"openbastion_hw:{hw_signature}".encode("utf-8"),
        )
        return hkdf.derive(master_bytes)

    def encrypt(self, plain_text: Optional[str]) -> Optional[str]:
        """
        以 AES-256-GCM 加密明文字串。
        Encrypt plaintext string using AES-256-GCM with idempotent prefix check.
        具備冪等性：若傳入值為 None、空字串或已帶有 'v1:' 前綴，直接返回原值避免重複加密。
        """
        if plain_text is None:
            return None
        text_val = str(plain_text)
        if not text_val or text_val.startswith(CIPHER_PREFIX):
            return text_val

        # 生成 12 位元組隨機 Nonce
        nonce = secrets.token_bytes(12)
        payload = text_val.encode("utf-8")
        ciphertext = self._cipher.encrypt(nonce, payload, None)

        combined = nonce + ciphertext
        encoded = base64.b64encode(combined).decode("ascii")
        return f"{CIPHER_PREFIX}{encoded}"

    def decrypt(self, cipher_text: Optional[str], strict: bool = False) -> Optional[str]:
        """
        解密字串憑證。
        Decrypt ciphertext credential with backward compatibility and tamper detection.
        平滑相容性：若傳入為 None 或無 'v1:' 前綴，視為歷史明文直接回傳。
        若 strict=True 且解密失敗（如硬體特徵不合），將拋出 ValueError；否則回傳 None 並記錄警示。
        """
        if cipher_text is None:
            return None
        c_str = str(cipher_text)
        if not c_str.startswith(CIPHER_PREFIX):
            return c_str

        b64_content = c_str[len(CIPHER_PREFIX) :]
        try:
            raw_blob = base64.b64decode(b64_content)
            if len(raw_blob) < 28:
                raise ValueError(t("vault.payload_too_short"))

            nonce = raw_blob[:12]
            actual_cipher = raw_blob[12:]

            decrypted_bytes = self._cipher.decrypt(nonce, actual_cipher, None)
            return decrypted_bytes.decode("utf-8")
        except InvalidTag:
            err_msg = t("vault.key_mismatch")
            logger.warning("[VAULT_MISMATCH] %s (可能資料庫遭拷貝至異地主機) (Database copied to different machine)", err_msg)
            if strict:
                raise ValueError(err_msg)
            return None
        except Exception as err:
            err_msg = f"解密處理異常: {err}"
            logger.error("[VAULT_ERROR] %s", err_msg)
            if strict:
                raise ValueError(err_msg)
            return None

    def sign_payload(self, message: Union[str, bytes]) -> str:
        """
        使用當前保管庫的派生金鑰計算防竄改 HMAC-SHA256 簽章。
        Compute HMAC-SHA256 tamper-evident signature using derived symmetric key.
        可用於重要審計紀錄、敏感設定或錄影檔案之完整性查核。
        """
        data_bytes = message.encode("utf-8") if isinstance(message, str) else message
        return hmac.new(self._active_key, data_bytes, hashlib.sha256).hexdigest()

    def verify_payload_signature(self, message: Union[str, bytes], expected_signature: str) -> bool:
        """
        以常數時間比對 HMAC-SHA256 簽章，驗證資料未經離線竄改。
        Verify HMAC-SHA256 signature in constant time to ensure data integrity.
        """
        if not expected_signature:
            return False
        calculated = self.sign_payload(message)
        return hmac.compare_digest(calculated, expected_signature)

    @staticmethod
    def export_backup_envelope(credentials_payload: Dict[str, Any], backup_passphrase: str) -> bytes:
        """
        以管理員通行碼封裝憑證資料為獨立的加密備份檔。
        Export credentials payload into an encrypted backup envelope using PBKDF2 and AES-GCM.
        採用 PBKDF2-HMAC-SHA256 (600,000 次) 與隨機 Salt 衍生獨立備份金鑰。
        """
        if not backup_passphrase or len(backup_passphrase) < 8:
            raise ValueError(t("vault.passphrase_too_short"))

        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=BACKUP_KDF_ROUNDS,
        )
        backup_key = kdf.derive(backup_passphrase.encode("utf-8"))

        data_bytes = json.dumps(credentials_payload, ensure_ascii=False).encode("utf-8")
        backup_cipher = AESGCM(backup_key)
        encrypted_data = backup_cipher.encrypt(nonce, data_bytes, None)

        # 封套格式：魔術標頭 (8) + 隨機鹽值 (16) + 隨機 Nonce (12) + 密文本體 (含 Tag)
        return VAULT_MAGIC_HEADER + salt + nonce + encrypted_data

    @staticmethod
    def import_backup_envelope(envelope_data: bytes, backup_passphrase: str) -> Dict[str, Any]:
        """
        解鎖並還原加密備份封套。
        Unlock and restore encrypted credentials envelope verifying header and passphrase.
        驗證標頭簽名與通行碼，若密碼錯誤或檔案遭竄改則拋出 ValueError。
        """
        if not envelope_data or len(envelope_data) < 36:
            raise ValueError(t("vault.envelope_corrupted"))

        header = envelope_data[:8]
        if header != VAULT_MAGIC_HEADER:
            raise ValueError(t("vault.header_invalid"))

        salt = envelope_data[8:24]
        nonce = envelope_data[24:36]
        ciphertext = envelope_data[36:]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=BACKUP_KDF_ROUNDS,
        )
        backup_key = kdf.derive(backup_passphrase.encode("utf-8"))

        backup_cipher = AESGCM(backup_key)
        try:
            decrypted_bytes = backup_cipher.decrypt(nonce, ciphertext, None)
            parsed = json.loads(decrypted_bytes.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise ValueError(t("vault.invalid_data_format"))
            return parsed
        except InvalidTag:
            raise ValueError(t("vault.passphrase_incorrect"))
        except json.JSONDecodeError:
            raise ValueError(t("vault.json_decode_error"))

