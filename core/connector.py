"""
OpenBastion 核心 - 目標主機連接器與 JIT 引擎 (Target Connector & Transport Adapter)
=============================================================================
依據 docs/SPEC.md §3.3 與 ADR-001 規範實作。
負責目標主機 SSH-2.0 連線發起、舊版演算法相容 (CentOS 6)、JIT 帳號動態確認與遠端 PTY 建立。

核心設計：
  1. 異質作業系統與舊演算法降級相容：
     - 原生向下相容 CentOS 6 (diffie-hellman-group14-sha1, ssh-rsa, aes128-cbc, 3des-cbc)。
     - 相容現代 Linux (ed25519, rsa-sha2-512) 與 Windows OpenSSH / ConPTY。
  2. 雙軌驗證支援 (Direct vs JIT):
     - Direct 模式：使用保管庫解密之固定帳號密碼或私鑰連線。
     - JIT 模式：連線前夕校驗獨立帳號與動態特權，以 CA 短期憑證或認證通道打通。
  3. 虛擬終端 (PTY) 分配：按連線者終端長寬動態請求遠端 xterm-256color 視窗。
  4. 連線異常捕捉與轉換：將底層連線超時、拒絕與憑證錯誤轉換為標準日誌標籤。
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import asyncssh

from core.ca import CertificateAuthorityManager
from core.i18n import t
from core.jit import JitProvisionError, JitProvisioner
from core.vault import CredentialVault

logger = logging.getLogger("openbastion.connector")

# 向下相容舊版 Linux (CentOS 6) 與新版伺服器之演算法清單
COMPAT_KEX_ALGS = [
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group1-sha1",
]

COMPAT_HOST_KEY_ALGS = [
    "ssh-ed25519",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
]

COMPAT_ENCRYPTION_ALGS = [
    "chacha20-poly1305@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-cbc",
    "aes256-cbc",
    "3des-cbc",
]


@dataclass
class TargetSession:
    """
    遠端目標主機連線會話載體。
    Target remote host session container encapsulating connection, process, and probe data.
    """

    conn: asyncssh.SSHClientConnection
    process: asyncssh.SSHClientProcess
    target_reader: Any
    target_writer: Any
    target_user: str
    endpoint: str
    probe_data: Dict[str, Any] = field(default_factory=dict)
    provision_mode: str = "direct"
    cert_info: Optional[Dict[str, Any]] = None
    session_id: Optional[str] = None
    host_id: Optional[str] = None
    storage: Optional[Any] = None
    jit_provisioner: Optional[JitProvisioner] = None
    ttl_minutes: int = 0

    async def close(self) -> None:
        """
        正常關閉目標連線與進程，並結清延遲補償佇列任務。
        Close target SSH connection and process gracefully, resolving pending cleanup task.
        """
        # 1. 補償佇列消帳 (若該會話曾登記 pending_cleanups)
        if self.session_id and self.storage:
            try:
                self.storage.resolve_cleanup(self.session_id)
                logger.info(
                    "[CLEANUP_RESOLVED] 會話 [ID: %s] 正常離線，補償佇列已消帳 (Session closed, cleanup resolved)",
                    self.session_id,
                )
            except Exception as err:
                logger.warning(
                    "[CLEANUP_RESOLVE_WARN] 會話 [ID: %s] 補償佇列消帳異常: %s (Warning resolving cleanup: %s)",
                    self.session_id,
                    err,
                    err,
                )

        # 2. 正常關閉遠端進程與連線
        try:
            if not self.process.is_closing():
                self.process.close()
        except Exception:
            pass
        try:
            if hasattr(self.conn, "close"):
                self.conn.close()
        except Exception:
            pass


class TargetConnector:
    """
    OpenBastion 目標主機連線轉接器。
    Manages outbound SSH connections to target servers with legacy algorithm fallback and PTY allocation.
    """

    def __init__(
        self,
        vault: Optional[CredentialVault] = None,
        ca_mgr: Optional[CertificateAuthorityManager] = None,
        storage: Optional[Any] = None,
        jit_provisioner: Optional[JitProvisioner] = None,
    ) -> None:
        self.vault = vault or CredentialVault()
        self.storage = storage
        self.ca_mgr = ca_mgr or CertificateAuthorityManager(storage=self.storage, vault=self.vault)
        self.jit_provisioner = jit_provisioner or JitProvisioner()

    @staticmethod
    def _parse_probe_output(stdout: str) -> Dict[str, Any]:
        """
        解析探針指令輸出，提取 CPU 負載、記憶體、磁碟、開機時長與系統版本。
        Parse probe command stdout into metrics dictionary.
        """
        res: Dict[str, Any] = {}
        sections: Dict[str, str] = {}
        curr_sec = "LOAD"
        curr_lines: List[str] = []

        for line in stdout.splitlines():
            line_s = line.strip()
            if line_s.startswith("---") and line_s.endswith("---"):
                sections[curr_sec] = "\n".join(curr_lines)
                curr_sec = line_s.replace("-", "")
                curr_lines = []
            else:
                curr_lines.append(line)
        sections[curr_sec] = "\n".join(curr_lines)

        # 1. 解析 CPU 負載 (Load Average)
        load_raw = sections.get("LOAD", "").strip()
        if load_raw:
            m = re.match(r"^([\d\.]+)", load_raw)
            if m:
                res["cpu_load"] = m.group(1)

        # 2. 解析記憶體使用率 (Memory Usage - 相容 CentOS 6 無 MemAvailable 狀況)
        mem_raw = sections.get("MEM", "")
        if mem_raw:
            mem_map: Dict[str, int] = {}
            for m_line in mem_raw.splitlines():
                parts = m_line.split(":")
                if len(parts) == 2:
                    k = parts[0].strip()
                    nums = re.findall(r"\d+", parts[1])
                    if nums:
                        mem_map[k] = int(nums[0])
            total = mem_map.get("MemTotal", 0)
            if total > 0:
                if "MemAvailable" in mem_map:
                    avail = mem_map["MemAvailable"]
                else:
                    free = mem_map.get("MemFree", 0)
                    buf = mem_map.get("Buffers", 0)
                    cache = mem_map.get("Cached", 0)
                    avail = free + buf + cache
                used = max(0, total - avail)
                pct = int((used / total) * 100)
                if total >= 1024 * 1024:
                    res["mem_usage"] = f"{used / 1024 / 1024:.1f}G/{total / 1024 / 1024:.1f}G ({pct}%)"
                else:
                    res["mem_usage"] = f"{used / 1024:.0f}M/{total / 1024:.0f}M ({pct}%)"

        # 3. 解析根目錄磁碟使用率 (Disk Usage)
        disk_raw = sections.get("DISK", "")
        if disk_raw:
            d_lines = [dl.strip() for dl in disk_raw.splitlines() if dl.strip()]
            if len(d_lines) >= 2:
                cols = re.split(r"\s+", d_lines[1])
                if len(cols) >= 5:
                    res["disk_usage"] = f"{cols[2]}/{cols[1]} ({cols[4]})"

        # 4. 解析開機時長 (Uptime)
        uptime_raw = sections.get("UPTIME", "").strip()
        if uptime_raw:
            try:
                up_sec = int(float(uptime_raw.split()[0]))
                days = up_sec // 86400
                hours = (up_sec % 86400) // 3600
                mins = (up_sec % 3600) // 60
                res["uptime_seconds"] = up_sec
                if days > 0:
                    res["uptime_zh"] = f"{days} 天 {hours} 小時 {mins} 分"
                    res["uptime_en"] = f"{days}d {hours}h {mins}m"
                elif hours > 0:
                    res["uptime_zh"] = f"{hours} 小時 {mins} 分"
                    res["uptime_en"] = f"{hours}h {mins}m"
                else:
                    res["uptime_zh"] = f"{mins} 分鐘"
                    res["uptime_en"] = f"{mins}m"
                res["uptime"] = res["uptime_zh"]
            except Exception:
                pass

        # 5. 解析最近登入歷史 (Last Login - 排除目前會話，提取最多 3 筆歷史紀錄)
        last_raw = sections.get("LAST", "")
        if last_raw:
            weekdays = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}
            records: List[Dict[str, str]] = []
            for line in last_raw.splitlines():
                ll = line.strip()
                if not ll or ll.startswith("wtmp") or ll.startswith("reboot"):
                    continue
                if "still logged in" in ll:
                    continue
                parts = re.split(r"\s+", ll)
                if len(parts) < 4:
                    continue
                user = parts[0]
                tty = parts[1]
                # 判斷第三欄是否為星期縮寫 (若為星期代表輸出無 IP 欄位)
                if len(parts) >= 6 and parts[2] in weekdays:
                    ip = "-"
                    dt_clean = " ".join(parts[2:6])
                elif len(parts) >= 7:
                    ip = parts[2]
                    dt_clean = " ".join(parts[3:7])
                else:
                    ip = "-"
                    dt_clean = " ".join(parts[2:])

                # 清理尾部可能殘留之區間減號
                dt_clean = re.sub(r"\s+-\s*$", "", dt_clean).strip()
                disp_str = f"{dt_clean} ({ip})" if ip != "-" else dt_clean
                records.append({
                    "user": user,
                    "tty": tty,
                    "ip": ip,
                    "time": dt_clean,
                    "display": disp_str,
                })
                if len(records) >= 3:
                    break

            if records:
                res["recent_login"] = records[0]["display"]
                res["last_login_ip"] = records[0]["ip"]
                res["last_login_user"] = records[0]["user"]
                res["last_login_time"] = records[0]["time"]
                res["recent_logins"] = [r["display"] for r in records]

        # 6. 解析作業系統發行版本 (OS Release)
        sys_raw = sections.get("SYS", "").strip()
        if sys_raw:
            sys_line = sys_raw.splitlines()[0]
            # 清理 /etc/issue 常見之 getty 轉義序列 (如 \n, \l, \d, \t 等)
            sys_clean = re.sub(r"\\[a-zA-Z]", "", sys_line)
            # 壓縮連續空格並去除頭尾引號
            sys_clean = re.sub(r"\s+", " ", sys_clean).strip().strip("\"'")
            if sys_clean:
                res["system"] = sys_clean[:32]

        return res

    async def probe_target_host(self, conn: asyncssh.SSHClientConnection) -> Dict[str, Any]:
        """
        採集目標主機系統指標與最近登入資訊。
        Execute lightweight commands to collect real-time system metrics.
        """
        probe_cmd = (
            "sh -c 'cat /proc/loadavg 2>/dev/null; "
            "echo \"---MEM---\"; cat /proc/meminfo 2>/dev/null; "
            "echo \"---DISK---\"; df -h / 2>/dev/null; "
            "echo \"---UPTIME---\"; cat /proc/uptime 2>/dev/null; "
            "echo \"---LAST---\"; (last -n 8 2>/dev/null); "
            "echo \"---SYS---\"; ((. /etc/os-release 2>/dev/null && echo \"$PRETTY_NAME\") || cat /etc/redhat-release 2>/dev/null || cat /etc/issue 2>/dev/null || uname -srm 2>/dev/null)'"
        )
        try:
            res = await asyncio.wait_for(conn.run(probe_cmd), timeout=1.5)
            if res.stdout:
                return self._parse_probe_output(res.stdout)
        except Exception as err:
            logger.debug("[PROBE_SKIPPED] 探針採集略過或非標準 Linux 平台: %s (Probe skipped or non-standard Linux platform: %s)", err, err)
        return {}

    async def _connect_with_ca_cert(
        self,
        host: str,
        port: int,
        target_user: str,
        login_username: str,
        system_hint: str = "",
        timeout: float = 10.0,
        valid_seconds: int = 300,
    ) -> Tuple[asyncssh.SSHClientConnection, Dict[str, Any]]:
        """
        使用雙軌 OpenSSH CA 短期憑證建立安全連線通道。
        Establish secure SSH connection using dual-track short-lived OpenSSH CA certificate.

        :param host: 目標主機位址 (Target host IP or FQDN)
        :param port: 目標主機 SSH 埠號 (Target SSH port)
        :param target_user: 登入目標之 POSIX 帳號 (Target login username)
        :param login_username: 跳板機操作者登入帳號 (Bastion operator username)
        :param system_hint: 作業系統特徵字串，用於演算法自適應 (OS signature string)
        :param timeout: 連線逾時秒數 (Connection timeout in seconds)
        :param valid_seconds: CA 憑證有效秒數 (Certificate validity in seconds)
        :return: (連線物件, 憑證中繼資訊字典) (Tuple of connection and cert metadata)
        """
        if not self.ca_mgr:
            self.ca_mgr = CertificateAuthorityManager(storage=self.storage, vault=self.vault)

        # 智慧雙軌序列：CentOS 6 / RHEL 6 優先走 RSA-4096，現代主機優先走 Ed25519
        target_sys = (system_hint or "").lower()
        is_legacy = any(kw in target_sys for kw in ("centos 6", "centos release 6", "rhel 6", "red hat 6"))
        algos_to_try = ["rsa", "ed25519"] if is_legacy else ["ed25519", "rsa"]

        last_err: Optional[Exception] = None
        conn: Optional[asyncssh.SSHClientConnection] = None
        cert_info: Optional[Dict[str, Any]] = None

        for attempt_idx, algo in enumerate(algos_to_try):
            logger.info(
                "[CA_SIGN_TRIGGER] 動態簽署 %d 秒短期憑證 (Dynamic CA signing short-lived certificate, user: %s, algo: %s, attempt: %d/%d)",
                valid_seconds,
                target_user,
                algo,
                attempt_idx + 1,
                len(algos_to_try),
            )
            u_key, cert = self.ca_mgr.sign_user_certificate(
                username=login_username,
                principals=[target_user],
                valid_seconds=valid_seconds,
                algo=algo,
            )
            curr_cert_info = {
                "key_id": getattr(cert, "_key_id", getattr(cert, "key_id", "")),
                "valid_after": getattr(cert, "_valid_after", getattr(cert, "valid_after", 0)),
                "valid_before": getattr(cert, "_valid_before", getattr(cert, "valid_before", 0)),
                "principals": list(getattr(cert, "principals", [])),
                "algorithm": algo,
            }
            connect_kwargs: Dict[str, Any] = {
                "host": host,
                "port": port,
                "username": target_user,
                "client_keys": [u_key],
                "client_certs": [cert],
                "known_hosts": None,
                "kex_algs": COMPAT_KEX_ALGS,
                "server_host_key_algs": COMPAT_HOST_KEY_ALGS,
                "encryption_algs": COMPAT_ENCRYPTION_ALGS,
            }
            try:
                logger.info(
                    "[CONNECTING] 正在建立通道至 %s:%d (帳號: %s, 憑證: %s) (Establishing channel to %s:%d)",
                    host,
                    port,
                    target_user,
                    algo.upper(),
                    host,
                    port,
                )
                conn = await asyncio.wait_for(
                    asyncssh.connect(**connect_kwargs),
                    timeout=timeout,
                )
                cert_info = curr_cert_info
                logger.info(
                    "[CA_CONNECTED_OK] 成功以 %s 憑證建立連線至 %s:%d (Successfully established connection with %s cert)",
                    algo.upper(),
                    host,
                    port,
                    algo.upper(),
                )
                break
            except (asyncssh.PermissionDenied, asyncssh.ProtocolError, ConnectionError, Exception) as err:
                last_err = err
                if attempt_idx < len(algos_to_try) - 1:
                    logger.warning(
                        "[CA_CASCADE_FALLBACK] 以 %s 憑證連線 %s:%d 被拒或失敗 (%s)，自動切換至下一軌演算法... (Falling back to next algorithm)",
                        algo,
                        host,
                        port,
                        err,
                    )
                else:
                    logger.error(
                        "[CA_CONNECT_EXHAUSTED] 雙軌 CA 憑證均無法連入 %s:%d: %s (Dual-track CA connection exhausted: %s)",
                        host,
                        port,
                        err,
                        err,
                    )

        if not conn:
            if isinstance(last_err, asyncssh.PermissionDenied):
                raise PermissionError(t("conn_err.denied", default="目標主機拒絕連線 (帳號不存在或憑證金鑰錯誤)"))
            elif isinstance(last_err, asyncio.TimeoutError):
                raise ConnectionError(
                    t("conn_err.timeout", timeout=timeout, endpoint=f"{host}:{port}", default=f"連線至目標主機超時 (超過 {timeout}s): {host}:{port}")
                )
            else:
                raise ConnectionError(t("conn_err.failed", error=str(last_err), default=f"目標主機連線失敗: {last_err}"))

        return conn, cert_info or {}

    async def _run_jit_bootstrap(
        self,
        host_info: Dict[str, Any],
        login_username: str,
        target_user: str,
        timeout: float = 10.0,
        session_id: Optional[str] = None,
        ttl_minutes: int = 0,
    ) -> None:
        """
        透過管理引導通道 (Bootstrap Channel) 執行 JIT 帳號建立、密碼鎖定與 RBAC 派發。
        Execute JIT provisioning, password lock, and RBAC setup via privileged bootstrap channel.

        :param host_info: 目標主機配置資料字典 (Host configuration metadata)
        :param login_username: 跳板機操作者帳號 (Bastion operator username)
        :param target_user: 即將建立之目標 JIT 帳號 (Target JIT username to provision)
        :param timeout: 連線與指令逾時秒數 (Connection and execution timeout)
        :param session_id: 當前連線會話 ID (Current session ID for cleanup tracking)
        :param ttl_minutes: 本次會話時效上限分鐘數 (Session TTL limit in minutes)
        :raises ConnectionError: 當管理引導通道無法建立時 (When bootstrap connection fails)
        :raises RuntimeError: 當 JIT 調度指令執行失敗時 (When JIT provisioning command fails)
        """
        host = host_info.get("host") or "127.0.0.1"
        port = int(host_info.get("port") or 22)
        cred_encrypted = host_info.get("credential_encrypted")
        auth_type = host_info.get("auth_type", "password")
        bootstrap_user = host_info.get("bootstrap_user") or "root"

        logger.info(
            "[JIT_BOOTSTRAP_START] 正在建立 JIT 管理引導通道至 %s:%d (目標帳號: %s) (Opening JIT bootstrap channel to %s:%d)",
            host,
            port,
            target_user,
            host,
            port,
        )

        bootstrap_conn: Optional[asyncssh.SSHClientConnection] = None
        try:
            if cred_encrypted:
                # 途徑 1：使用主機保險庫中託管的管理員憑證 (Host credential from vault)
                target_password: Optional[str] = None
                client_keys: Optional[List[Any]] = None
                decrypted_cred = self.vault.decrypt(cred_encrypted, strict=False)
                if decrypted_cred:
                    if auth_type == "password":
                        target_password = decrypted_cred
                    elif auth_type == "key":
                        client_keys = [asyncssh.import_private_key(decrypted_cred)]

                connect_kwargs: Dict[str, Any] = {
                    "host": host,
                    "port": port,
                    "username": bootstrap_user,
                    "password": target_password,
                    "client_keys": client_keys,
                    "known_hosts": None,
                    "kex_algs": COMPAT_KEX_ALGS,
                    "server_host_key_algs": COMPAT_HOST_KEY_ALGS,
                    "encryption_algs": COMPAT_ENCRYPTION_ALGS,
                }
                bootstrap_conn = await asyncio.wait_for(
                    asyncssh.connect(**connect_kwargs),
                    timeout=timeout,
                )
            else:
                # 途徑 2：使用 Level 2 CA 發行之 60 秒 root 短期憑證 (Root short-lived CA cert)
                bootstrap_conn, _ = await self._connect_with_ca_cert(
                    host=host,
                    port=port,
                    target_user=bootstrap_user,
                    login_username=login_username,
                    system_hint=host_info.get("system", ""),
                    timeout=timeout,
                    valid_seconds=60,
                )
        except Exception as err:
            logger.error(
                "[JIT_BOOTSTRAP_FAILED] JIT 管理引導通道連線失敗: %s (JIT bootstrap channel connection failed: %s)",
                err,
                err,
            )
            raise ConnectionError(
                t("jit.bootstrap_failed", error=str(err), default=f"JIT 管理引導通道連線失敗: {err}")
            )

        # 取得連線者之角色以派發對應 Sudoers (Fetch user role for RBAC)
        user_role = "user"
        if self.storage:
            try:
                u_rec = self.storage.get_user_by_username(login_username)
                if u_rec and isinstance(u_rec, dict):
                    user_role = u_rec.get("role", "user")
            except Exception as err:
                logger.warning(
                    "[JIT_ROLE_QUERY_WARN] 查詢使用者角色異常，降級為預設角色 user: %s (Role query failed, defaulting to user)",
                    err,
                )

        try:
            # 依序執行：1. 確保帳號存在 + 2. 強制鎖定密碼 + 3. 依角色配置 Sudoers
            custom_rule = host_info.get("custom_sudo_rule")
            await self.jit_provisioner.ensure_jit_user(bootstrap_conn, target_user)
            await self.jit_provisioner.configure_sudoers_rbac(
                bootstrap_conn, target_user, user_role, custom_rule=custom_rule
            )
            logger.info(
                "[JIT_PROVISION_OK] JIT 動態調度與 RBAC 派發成功 (目標: %s, 角色: %s) (JIT provisioning and RBAC success)",
                target_user,
                user_role,
            )

            # 4. 第 0 秒目標端自主定時自毀 (Target-side Autonomous Self-Lock)
            # 設計準則：防範但不禁止。若管理者/部門設定 ttl_minutes <= 0 (無上限)，
            # schedule_autonomous_self_lock 內部自動跳過定時器植入，完全尊重設定人。
            host_id_val = str(host_info.get("host_id") or host_info.get("id") or host_info.get("host", "unknown"))
            if session_id:
                if ttl_minutes > 0:
                    await self.jit_provisioner.schedule_autonomous_self_lock(
                        bootstrap_conn, target_user, session_id, ttl_minutes
                    )
                    # 登記至延遲補償佇列 (Pending Cleanups Queue)
                    if self.storage:
                        self.storage.enqueue_cleanup(
                            session_id=session_id,
                            host_id=host_id_val,
                            target_user=target_user,
                            ttl_minutes=ttl_minutes,
                        )
                else:
                    logger.info(
                        "[JIT_UNLIMITED_SESSION] 會話 [ID: %s] 時效設定為無上限 (ttl=%d)，跳過目標端自毀與補償佇列登記 (Unlimited session: skipping lock and queue)",
                        session_id,
                        ttl_minutes,
                    )
        except Exception as err:
            logger.error("[JIT_PROVISION_ERROR] JIT 調度執行失敗: %s (JIT provision execution error: %s)", err, err)
            if isinstance(err, (JitProvisionError, ValueError)):
                raise RuntimeError(t("jit.provision_failed", error=str(err), default=f"JIT 帳號動態調度失敗: {err}"))
            raise
        finally:
            try:
                bootstrap_conn.close()
            except Exception:
                pass

    async def connect(
        self,
        host_info: Dict[str, Any],
        login_username: str,
        term_width: int = 80,
        term_height: int = 24,
        term_type: str = "xterm-256color",
        timeout: float = 10.0,
        session_id: Optional[str] = None,
        ttl_minutes: int = 0,
    ) -> TargetSession:
        """
        建立與目標伺服器的非阻塞 SSH 通道並分配遠端 PTY。
        Establish non-blocking outbound SSH connection to target server and allocate remote PTY.
        """
        host = host_info.get("host") or "127.0.0.1"
        port = int(host_info.get("port") or 22)
        provision_mode = host_info.get("provision_mode", "direct")
        default_user_tpl = host_info.get("default_user", "{username}")
        auth_type = host_info.get("auth_type", "key")
        cred_encrypted = host_info.get("credential_encrypted")

        # 1. 決定遠端登入帳號名稱 (JIT 模式強制隔離個人帳號，Direct/CA 模式相容共用帳號)
        if provision_mode == "jit":
            if not default_user_tpl or default_user_tpl in ("{username}", "root"):
                target_user = login_username
            elif "{username}" in default_user_tpl:
                target_user = default_user_tpl.replace("{username}", login_username)
            else:
                target_user = default_user_tpl
        else:
            if default_user_tpl == "{username}":
                target_user = login_username
            else:
                target_user = default_user_tpl

        # 2. 解析生效之連線逾時 (優先採納主機個別自訂值)
        actual_timeout = timeout
        if host_info and host_info.get("connect_timeout"):
            try:
                ct = float(host_info["connect_timeout"])
                if ct > 0:
                    actual_timeout = ct
            except (ValueError, TypeError):
                pass

        # 3. 解析並解密連線憑證 (或動態簽署雙軌 CA 短期憑證)
        target_password: Optional[str] = None
        client_keys: List[Any] = []
        cert_info: Optional[Dict[str, Any]] = None
        conn: Optional[asyncssh.SSHClientConnection] = None

        if provision_mode == "jit":
            # Level 3 JIT 動態帳號治理模式 (JIT Dynamic Provisioning & RBAC)
            logger.info(
                "[JIT_CONNECT_START] 開始 Level 3 JIT 動態存取流程 (使用者: %s, 目標: %s) (Starting Level 3 JIT workflow)",
                login_username,
                target_user,
            )
            # 1. 建立管理引導通道並調度帳號與 Sudoers，注入第 0 秒自主自毀與延遲補償登記
            await self._run_jit_bootstrap(
                host_info=host_info,
                login_username=login_username,
                target_user=target_user,
                timeout=actual_timeout,
                session_id=session_id,
                ttl_minutes=ttl_minutes,
            )
            # 2. 簽發 300 秒專屬個人短期憑證並建立正式目標連線
            conn, cert_info = await self._connect_with_ca_cert(
                host=host,
                port=port,
                target_user=target_user,
                login_username=login_username,
                system_hint=host_info.get("system", ""),
                timeout=actual_timeout,
                valid_seconds=300,
            )

        elif provision_mode == "ca":
            # Level 2 CA 憑證免密模式 (CA-Based Agentless)
            conn, cert_info = await self._connect_with_ca_cert(
                host=host,
                port=port,
                target_user=target_user,
                login_username=login_username,
                system_hint=host_info.get("system", ""),
                timeout=actual_timeout,
                valid_seconds=300,
            )

        else:
            # 標準 Direct 密碼/私鑰託管代理模式
            if cred_encrypted:
                try:
                    decrypted_cred = self.vault.decrypt(cred_encrypted, strict=False)
                    if decrypted_cred:
                        if auth_type == "password":
                            target_password = decrypted_cred
                        elif auth_type == "key":
                            client_keys = [asyncssh.import_private_key(decrypted_cred)]
                except Exception as err:
                    logger.warning("[CRED_DECRYPT_FAILED] 解密主機憑證失敗，將嘗試以預設方式連線: %s (Failed to decrypt host credential, trying default: %s)", err, err)

            logger.info(
                "[CONNECTING] 正在建立通道至 %s:%d (帳號: %s, 模式: %s, 逾時: %.1fs) (Establishing channel to %s:%d)",
                host,
                port,
                target_user,
                provision_mode,
                actual_timeout,
                host,
                port,
            )
            try:
                connect_kwargs = {
                    "host": host,
                    "port": port,
                    "username": target_user,
                    "password": target_password,
                    "client_keys": client_keys if client_keys else None,
                    "known_hosts": None,  # 跳板機內部代管連線
                    "kex_algs": COMPAT_KEX_ALGS,
                    "server_host_key_algs": COMPAT_HOST_KEY_ALGS,
                    "encryption_algs": COMPAT_ENCRYPTION_ALGS,
                }
                conn = await asyncio.wait_for(
                    asyncssh.connect(**connect_kwargs),
                    timeout=actual_timeout,
                )
            except asyncio.TimeoutError:
                raise ConnectionError(t("conn_err.timeout", timeout=actual_timeout, endpoint=f"{host}:{port}", default=f"連線至目標主機超時 (超過 {actual_timeout}s): {host}:{port}"))
            except asyncssh.PermissionDenied as err:
                raise PermissionError(t("conn_err.denied", default="目標主機拒絕連線 (帳號不存在或憑證金鑰錯誤)"))
            except Exception as err:
                raise ConnectionError(t("conn_err.failed", error=str(err), default=f"目標主機連線失敗: {err}"))

        # 4. 採集主機系統指標並擷取跳板出口 IP
        probe_data = await self.probe_target_host(conn)
        try:
            sockname = conn.get_extra_info("sockname")
            if sockname and isinstance(sockname, tuple):
                probe_data["bastion_outbound_ip"] = sockname[0]
        except Exception:
            pass

        # 5. 請求分配遠端虛擬終端 (PTY) 與啟動互動式 Shell
        try:
            process = await conn.create_process(
                term_type=term_type,
                term_size=(term_width, term_height),
                encoding=None,  # 採用純位元組轉發，保留原始終端控制碼
            )
        except Exception as err:
            conn.close()
            raise RuntimeError(f"分配遠端虛擬終端 (PTY) 失敗: {err}")

        endpoint_str = f"{host}:{port}"
        logger.info("[CONNECTED] 已成功建立遠端通道並分配 PTY: %s (使用者: %s) (Remote channel and PTY allocated)", endpoint_str, target_user)

        return TargetSession(
            conn=conn,
            process=process,
            target_reader=process.stdout,
            target_writer=process.stdin,
            target_user=target_user,
            endpoint=endpoint_str,
            probe_data=probe_data,
            provision_mode=provision_mode,
            cert_info=cert_info,
            session_id=session_id,
            host_id=str(host_info.get("host_id") or host_info.get("id") or host),
            storage=self.storage,
            jit_provisioner=self.jit_provisioner,
            ttl_minutes=ttl_minutes,
        )
