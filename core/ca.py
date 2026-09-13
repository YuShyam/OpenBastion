"""
OpenBastion 核心 - OpenSSH 雙軌 CA 短期憑證簽署引擎 (Dual-CA Certificate Engine)
================================================================================
依據 docs/SPEC.md §3.3 與 Phase 4 規格原生實作。
提供 Level 2 零侵入架構之 OpenSSH 雙軌 (Ed25519 + RSA-4096) 根金鑰生成、安全保管庫加密保存、
公鑰匯出指引、以及目標主機連線前夕 300 秒極短效期使用者憑證動態簽署。

核心設計 / Architectural Highlights:
  1. 雙軌根金鑰架構 (Dual-CA Hierarchy):
     - 軌道 1 (現代雲原生): Ed25519 根金鑰 (128-bit 強度)，極短密鑰、微秒級簽章、防側通道攻擊。
     - 軌道 2 (遺留相容): RSA-4096 根金鑰 (高強度加密)，簽發 ssh-rsa-cert-v01@openssh.com
       相容 CentOS 6 / OpenSSH 5.3p1 等早期版本。
  2. 根金鑰保管庫加密：雙軌私鑰一律透過 AES-256-GCM (CredentialVault) 加密後持久化於資料庫。
  3. 300 秒短期動態憑證：即簽即用，時鐘漂移容忍度 -60 秒，過期自動失效，免除撤銷黑名單負擔。
  4. 零密碼零私鑰下放：目標主機僅需信任 CA 公鑰，無須在主機上預埋任何個別使用者私鑰或密碼。
"""

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

import asyncssh

from core.storage import StorageProvider
from core.vault import CredentialVault

logger = logging.getLogger("openbastion.ca")

CA_ED25519_CONFIG_KEY = "ca_ed25519_encrypted"
CA_ED25519_LEGACY_KEY = "ca_private_key_encrypted"
CA_RSA4096_CONFIG_KEY = "ca_rsa4096_encrypted"

DEFAULT_VALID_SECONDS = 300  # 短期憑證預設 5 分鐘有效
CLOCK_SKEW_TOLERANCE_SECONDS = 60  # 時鐘漂移容忍 60 秒


class CertificateAuthorityManager:
    """
    OpenSSH 雙軌憑證授權簽署中心管理器 (Dual Certificate Authority Manager)。
    Manages dual-root CA private keys (Ed25519 + RSA-4096) lifecycle, database persistence via Vault,
    and dynamic user cert issuance with backward compatibility.
    """

    def __init__(
        self,
        storage: Optional[StorageProvider] = None,
        vault: Optional[CredentialVault] = None,
        default_algo: str = "ed25519",
        key_type: Optional[str] = None,
    ) -> None:
        """
        初始化雙軌 CA 憑證授權管理器。
        Initialize Dual CA manager with database storage and credential vault.
        """
        self.storage = storage or StorageProvider()
        self.vault = vault or CredentialVault()
        self.default_algo = key_type or default_algo
        self._ed_key: Optional[asyncssh.SSHKey] = None
        self._rsa_key: Optional[asyncssh.SSHKey] = None
        self._lock = asyncio.Lock()

    @property
    def key_type(self) -> str:
        """
        相容舊版呼叫之預設演算法屬性。
        Backward-compatible property returning default CA algorithm.
        """
        return self.default_algo

    def ensure_ca_key(self, algo: str = "ed25519") -> asyncssh.SSHKey:
        """
        同步確保並取得指定演算法 ('ed25519' 或 'rsa') 的 CA 根私鑰實例。
        Ensure and retrieve CA root private key instance for the specified algorithm (ed25519 or rsa).
        若資料庫中尚未建立，則自動生成並經 Vault (AES-256-GCM) 加密後存入資料庫。
        """
        normalized_algo = algo.lower().strip()
        if normalized_algo in ("rsa", "rsa4096", "ssh-rsa"):
            if self._rsa_key:
                return self._rsa_key

            encrypted_key = self.storage.get_config(CA_RSA4096_CONFIG_KEY)
            if encrypted_key:
                try:
                    decrypted_pem = self.vault.decrypt(encrypted_key, strict=False)
                    if decrypted_pem:
                        self._rsa_key = asyncssh.import_private_key(decrypted_pem)
                        logger.info("[CA_LOAD_OK] 已成功解密並載入 RSA-4096 CA 根金鑰 (Successfully loaded RSA-4096 CA root key)")
                        return self._rsa_key
                except Exception as err:
                    logger.warning("[CA_LOAD_FAILED] 解密 RSA CA 金鑰失敗，將重新生成: %s (Failed to decrypt RSA CA key, regenerating: %s)", err, err)

            logger.info("[CA_GEN_INIT] 正在生成全新 OpenSSH RSA-4096 CA 根金鑰 (4096 位元規格) ... (Generating new OpenSSH RSA-4096 CA root key)")
            new_rsa = asyncssh.generate_private_key("ssh-rsa", key_size=4096)
            exported = new_rsa.export_private_key("openssh")
            pem_str = exported.decode("utf-8") if isinstance(exported, bytes) else str(exported)
            self.storage.set_config(CA_RSA4096_CONFIG_KEY, self.vault.encrypt(pem_str))
            self._rsa_key = new_rsa
            logger.info("[CA_GEN_OK] OpenSSH RSA-4096 CA 根金鑰已生成並安全加密持久化至資料庫 (OpenSSH RSA-4096 CA root key generated and persisted)")
            return self._rsa_key

        else:  # ed25519
            if self._ed_key:
                return self._ed_key

            encrypted_key = self.storage.get_config(CA_ED25519_CONFIG_KEY) or self.storage.get_config(CA_ED25519_LEGACY_KEY)
            if encrypted_key:
                try:
                    decrypted_pem = self.vault.decrypt(encrypted_key, strict=False)
                    if decrypted_pem:
                        self._ed_key = asyncssh.import_private_key(decrypted_pem)
                        logger.info("[CA_LOAD_OK] 已成功解密並載入 Ed25519 CA 根金鑰 (Successfully loaded Ed25519 CA root key)")
                        return self._ed_key
                except Exception as err:
                    logger.warning("[CA_LOAD_FAILED] 解密 Ed25519 CA 金鑰失敗，將重新生成: %s (Failed to decrypt Ed25519 CA key, regenerating: %s)", err, err)

            logger.info("[CA_GEN_INIT] 正在生成全新 OpenSSH Ed25519 CA 根金鑰 ... (Generating new OpenSSH Ed25519 CA root key)")
            new_ed = asyncssh.generate_private_key("ssh-ed25519")
            exported = new_ed.export_private_key("openssh")
            pem_str = exported.decode("utf-8") if isinstance(exported, bytes) else str(exported)
            self.storage.set_config(CA_ED25519_CONFIG_KEY, self.vault.encrypt(pem_str))
            self._ed_key = new_ed
            logger.info("[CA_GEN_OK] OpenSSH Ed25519 CA 根金鑰已生成並安全加密持久化至資料庫 (OpenSSH Ed25519 CA root key generated and persisted)")
            return self._ed_key

    def ensure_all_ca_keys(self) -> Tuple[asyncssh.SSHKey, asyncssh.SSHKey]:
        """
        同時確保雙軌 CA (Ed25519 與 RSA-4096) 均已就緒。
        Ensure both Ed25519 and RSA-4096 dual CA root keys are initialized and ready.
        """
        ed_key = self.ensure_ca_key("ed25519")
        rsa_key = self.ensure_ca_key("rsa")
        return ed_key, rsa_key

    def get_ca_public_key(self, algo: str = "ed25519", comment: Optional[str] = None) -> str:
        """
        匯出指定演算法之 OpenSSH 格式 CA 根公鑰字串。
        Export OpenSSH formatted public key string for /etc/ssh/trusted_user_ca_keys.
        """
        normalized_algo = algo.lower().strip()
        is_rsa = normalized_algo in ("rsa", "rsa4096", "ssh-rsa")
        target_algo = "rsa" if is_rsa else "ed25519"
        default_comment = "openbastion-rsa-ca" if is_rsa else "openbastion-ca"
        actual_comment = comment or default_comment

        ca_key = self.ensure_ca_key(target_algo)
        pub_bytes = ca_key.export_public_key("openssh")
        pub_str = pub_bytes.decode("utf-8").strip() if isinstance(pub_bytes, bytes) else str(pub_bytes).strip()

        parts = pub_str.split()
        if len(parts) >= 2:
            return f"{parts[0]} {parts[1]} {actual_comment}"
        return f"{pub_str} {actual_comment}"

    def get_ca_public_keys(self) -> Dict[str, str]:
        """
        同時匯出 Ed25519 與 RSA-4096 雙軌公鑰。
        Export both Ed25519 and RSA-4096 dual CA public keys dictionary.
        """
        return {
            "ed25519": self.get_ca_public_key("ed25519"),
            "rsa": self.get_ca_public_key("rsa"),
        }

    def get_enroll_command(self) -> str:
        """
        產出目標主機一鍵完成雙軌 CA 信任之自適應 Shell 指令 (相容 CentOS 6 至現代 Linux)。
        Generate all-in-one adaptive shell command for enrolling dual CA keys on target hosts.
        在目標機執行時透過 ssh -V 自動識別 OpenSSH 版本：
          - 舊版 (<= OpenSSH 6.4，如 CentOS 6): 僅配置 RSA-4096 公鑰，防範舊版 parser 拋出 unsupported key type。
          - 現代版 (OpenSSH 6.5+): 同時配置 Ed25519 與 RSA-4096 雙軌公鑰。
        """
        ed_pub = self.get_ca_public_key("ed25519")
        rsa_pub = self.get_ca_public_key("rsa")

        cmd = (
            f"sudo bash -c '"
            f"R=\"{rsa_pub}\"; "
            f"E=\"{ed_pub}\"; "
            f"if ssh -V 2>&1 | grep -qE \"OpenSSH_[1-5]\\.|OpenSSH_6\\.[0-4]\"; then "
            f"echo \"$R\" > /etc/ssh/openbastion_ca.pub; "
            f"else "
            f"printf \"%s\\n%s\\n\" \"$E\" \"$R\" > /etc/ssh/openbastion_ca.pub; "
            f"fi && "
            f"chmod 644 /etc/ssh/openbastion_ca.pub && "
            f"(grep -q \"^[[:space:]]*TrustedUserCAKeys\" /etc/ssh/sshd_config || "
            f"echo \"TrustedUserCAKeys /etc/ssh/openbastion_ca.pub\" >> /etc/ssh/sshd_config) && "
            f"(systemctl reload sshd 2>/dev/null || service sshd reload 2>/dev/null || "
            f"systemctl restart ssh 2>/dev/null || service ssh restart 2>/dev/null || "
            f"/etc/init.d/sshd restart 2>/dev/null || true) && "
            f"echo \"[OpenBastion] OpenSSH 雙軌 CA 根憑證已成功配置並重載 sshd！\"'"
        )
        return cmd

    def sign_user_certificate(
        self,
        username: str,
        principals: Sequence[str],
        valid_seconds: int = DEFAULT_VALID_SECONDS,
        key_id: Optional[str] = None,
        algo: str = "ed25519",
    ) -> Tuple[asyncssh.SSHKey, Any]:
        """
        為連線動態生成暫態使用者金鑰對，並由指定演算法之 CA 簽發 300 秒極短期 OpenSSH 使用者憑證。
        Dynamically generate ephemeral user keypair and sign a short-lived OpenSSH user certificate.

        :param username: 操作者跳板機帳號 (Operator username)
        :param principals: 目標主機授權登入之帳號名單 (Authorized remote principals, e.g. ['root', 'app'])
        :param valid_seconds: 憑證有效時長秒數 (預設 300 秒)
        :param key_id: 審計識別碼 (Audit Key ID)
        :param algo: 簽署演算法 ('ed25519' 或 'rsa')
        :return: (user_private_key, certificate_object)
        """
        normalized_algo = algo.lower().strip()
        is_rsa = normalized_algo in ("rsa", "rsa4096", "ssh-rsa")

        now = int(time.time())
        valid_after = max(0, now - CLOCK_SKEW_TOLERANCE_SECONDS)
        valid_before = now + max(60, valid_seconds)
        actual_key_id = key_id or f"openbastion-{username}-{now}"

        if is_rsa:
            ca_key = self.ensure_ca_key("rsa")
            # 生成暫態 RSA-2048 使用者金鑰 (連線後銷毀，搭配 4096 CA 根簽章兼顧簽署速度與相容性)
            user_key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
            cert = ca_key.generate_user_certificate(
                user_key=user_key,
                key_id=actual_key_id,
                principals=principals,
                valid_after=valid_after,
                valid_before=valid_before,
                sig_alg="ssh-rsa",  # 強制指定 ssh-rsa 簽章以相容 OpenSSH 5.3p1 (CentOS 6)
                permit_pty=True,
                permit_port_forwarding=True,
                permit_agent_forwarding=True,
                permit_x11_forwarding=False,
                permit_user_rc=True,
            )
            logger.info(
                "[CA_CERT_ISSUED] 已為使用者 '%s' 簽發 RSA-4096 相容短期憑證 (Issued RSA-4096 short-lived certificate, KeyID: %s, principals: %s, TTL: %ds)",
                username,
                actual_key_id,
                list(principals),
                valid_seconds,
            )
        else:
            ca_key = self.ensure_ca_key("ed25519")
            user_key = asyncssh.generate_private_key("ssh-ed25519")
            cert = ca_key.generate_user_certificate(
                user_key=user_key,
                key_id=actual_key_id,
                principals=principals,
                valid_after=valid_after,
                valid_before=valid_before,
                permit_pty=True,
                permit_port_forwarding=True,
                permit_agent_forwarding=True,
                permit_x11_forwarding=False,
                permit_user_rc=True,
            )
            logger.info(
                "[CA_CERT_ISSUED] 已為使用者 '%s' 簽發 Ed25519 現代短期憑證 (Issued Ed25519 short-lived certificate, KeyID: %s, principals: %s, TTL: %ds)",
                username,
                actual_key_id,
                list(principals),
                valid_seconds,
            )

        return user_key, cert
