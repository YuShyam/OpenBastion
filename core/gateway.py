"""
OpenBastion Core - Gateway Listener (SSH-2.0 通道監聽與協定握手)
=============================================================
依據 docs/SPEC.md §2.1 (Gateway Listener & Handshake) 與 RFC 4253 / RFC 4252 / RFC 4254 規範。
Standard RFC 4253 non-blocking SSH-2.0 gateway listener powered by asyncssh & SQLite WAL.

核心職責 / Responsibilities:
  1. 基於 asyncssh 實裝標準非阻塞 SSH-2.0 協定監聽服務。
  2. 無實體金鑰檔案持久化：伺服器主機金鑰自 SQLite (system_config) 記憶體直載。
  3. 接軌 SQLite 儲存驅動，以 PBKDF2 加鹽雜湊驗證登入憑證 (嚴格遵循 Fail-Closed 原則)。
  4. 記錄連線會話生命週期 (Session Lifecycle)，支援連線建立登記與正常結束結算。
  5. 個人化偏好載入與即時回寫：登入時載入視圖與語系，操作切換時即刻持久化至資料庫。
  6. 終端命令列輸入長度防衛 (MAX_INPUT_LENGTH) 與 process.stdout.drain() 即時刷新保證。
"""

import asyncio
import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import asyncssh

from core.audit import AuditEngine
from core.banner import (
    BannerContext,
    DefaultTemplateBannerProvider,
    IBannerProvider,
    render_banner_safe,
)
from core.ca import CertificateAuthorityManager
from core.connector import TargetConnector, TargetSession
from core.i18n import get_locale, get_supported_locales_info, set_locale, t
from core.menu import TerminalMenu
from core.pipe import StreamPipe
from core.recorder import AsciinemaRecorder
from core.storage import StorageProvider
from core.vault import CredentialVault

logger = logging.getLogger("openbastion.gateway")
MAX_INPUT_LENGTH = 256


@dataclass
class DetachedSession:
    """
    暫掛連線會話載體 (Detached Session)。
    每個會話享有獨立之 512KB RingBuffer (嚴禁共用)，記憶體物理隔離。
    """

    slot: int
    session_id: str
    username: str
    target_session: TargetSession
    pipe: StreamPipe
    recorder: AsciinemaRecorder
    audit_engine: AuditEngine
    host_info: Dict[str, Any]
    target_user: str
    detached_at: float
    idle_timeout: float = 900.0  # 15 分鐘 TTL

    def is_expired(self) -> bool:
        """
        判定會話是否已超出 15 分鐘閒置上限。
        Determine whether the detached session has exceeded the 15-minute idle TTL.
        """
        return (time.time() - self.detached_at) > self.idle_timeout

    def is_alive(self) -> bool:
        """
        判定會話是否仍存活有效且未逾時。
        Check if the detached session is still alive and not expired.
        """
        if self.is_expired():
            return False
        try:
            if hasattr(self.target_session.conn, "is_closing") and self.target_session.conn.is_closing():
                return False
        except Exception:
            return False
        return True


class DetachedSessionPool:
    """
    使用者連線會話暫掛池 (Detached Session Pool)。
    每位使用者上限 3 個槽位 (Slot 1..3)，每個槽位獨立配置 512KB RingBuffer (嚴禁共用)，
    支援 Ctrl + ] 抽離、[r] 或 [r1..r3] 接回終端畫面重繪、以及 15 分鐘 Idle TTL 逾時保護。
    """

    MAX_SLOTS = 3

    def __init__(self, storage: Optional[StorageProvider] = None) -> None:
        self.storage = storage
        self._slots: Dict[str, Dict[int, DetachedSession]] = {}
        self._lock = asyncio.Lock()

    async def put_session(
        self,
        username: str,
        session_id: str,
        target_session: TargetSession,
        pipe: StreamPipe,
        recorder: AsciinemaRecorder,
        audit_engine: AuditEngine,
        host_info: Dict[str, Any],
        target_user: str,
    ) -> int:
        """
        將連線抽離暫掛至 1..3 槽位。若已達 3 個槽位上限，則按先進先出 (FIFO) 清理最舊會話。
        Detach session into available slot 1..3 with FIFO eviction when capacity is reached.
        """
        async with self._lock:
            user_pool = self._slots.setdefault(username, {})
            await self._prune_dead(username)

            # 尋找 1..3 空閒槽位
            slot_to_use = None
            for s in range(1, self.MAX_SLOTS + 1):
                if s not in user_pool:
                    slot_to_use = s
                    break

            # 若無空槽位，淘汰最舊者 (FIFO)
            if slot_to_use is None:
                oldest_slot = min(user_pool.keys(), key=lambda k: user_pool[k].detached_at)
                logger.warning(
                    "[SLOT_EVICTED] 使用者 '%s' 暫掛槽位已滿 (3/3)，自動淘汰最舊會話 (槽位 %d)",
                    username,
                    oldest_slot,
                )
                old_sess = user_pool.pop(oldest_slot)
                await self._close_detached(old_sess)
                slot_to_use = oldest_slot

            detached = DetachedSession(
                slot=slot_to_use,
                session_id=session_id,
                username=username,
                target_session=target_session,
                pipe=pipe,
                recorder=recorder,
                audit_engine=audit_engine,
                host_info=host_info,
                target_user=target_user,
                detached_at=time.time(),
            )
            user_pool[slot_to_use] = detached
            logger.info(
                "[SESSION_DETACHED] 會話 [ID: %s] 已成功抽離至暫掛池 (Session detached to pool, slot: %d, user: %s)",
                session_id,
                slot_to_use,
                username,
            )
            return slot_to_use

    async def pop_session(
        self,
        username: str,
        slot: Optional[int] = None,
    ) -> Optional[DetachedSession]:
        """
        取出暫掛會話以執行接回 (Reattach)。若未指定 slot，預設取出最近抽離之會話。
        Retrieve detached session for reattachment, defaulting to the most recently detached slot.
        """
        async with self._lock:
            user_pool = self._slots.setdefault(username, {})
            await self._prune_dead(username)
            if not user_pool:
                return None

            if slot is not None:
                target = user_pool.pop(slot, None)
                if target and target.is_alive():
                    return target
                elif target:
                    await self._close_detached(target)
                return None

            # 預設取出最新抽離之會話
            latest_slot = max(user_pool.keys(), key=lambda k: user_pool[k].detached_at)
            target = user_pool.pop(latest_slot)
            if target.is_alive():
                return target
            await self._close_detached(target)
            return None

    async def get_active_sessions(self, username: str) -> List[DetachedSession]:
        """
        取得指定使用者目前所有存活之暫掛會話清單。
        Get list of active detached sessions for the specified user.
        """
        async with self._lock:
            user_pool = self._slots.setdefault(username, {})
            await self._prune_dead(username)
            return sorted(user_pool.values(), key=lambda s: s.slot)

    async def _prune_dead(self, username: str) -> None:
        """
        清理已逾時或連線中斷之暫掛會話。
        Prune expired or disconnected detached sessions.
        """
        user_pool = self._slots.get(username, {})
        dead_slots = [s for s, sess in user_pool.items() if not sess.is_alive()]
        for s in dead_slots:
            sess = user_pool.pop(s)
            logger.info(
                "[SESSION_PRUNED] 暫掛會話已逾時或斷線，執行清理 (Detached session expired or disconnected, user: %s, slot: %d)",
                username,
                s,
            )
            await self._close_detached(sess)

    async def _close_detached(self, detached: DetachedSession) -> None:
        """
        正常收尾暫掛會話資源並結算錄影。
        Properly release detached session resources and finalize asciinema recording.
        """
        try:
            await detached.target_session.close()
        except Exception:
            pass
        rec_path, rec_size, rec_sha, rec_duration = detached.recorder.close()
        if rec_sha and self.storage:
            try:
                self.storage.save_recording_metadata(
                    session_id=detached.session_id,
                    file_path=str(rec_path),
                    file_size=rec_size,
                    sha256_hash=rec_sha,
                    duration_seconds=rec_duration,
                )
            except Exception as err:
                logger.error("[STORAGE_ERROR] 儲存淘汰暫掛會話錄影元資料失敗: %s (Failed to save detached recording metadata: %s)", err, err)

    async def close_all_for_user(self, username: str) -> None:
        """
        使用者離線時清空並關閉該使用者所有暫掛會話。
        Close and clean up all detached sessions for a user upon disconnection.
        """
        async with self._lock:
            user_pool = self._slots.pop(username, {})
            for s, sess in user_pool.items():
                await self._close_detached(sess)

    async def close_all(self) -> None:
        """
        伺服器停機時清空並關閉所有暫掛會話。
        Close and release all detached sessions across all users upon gateway shutdown.
        """
        async with self._lock:
            all_users = list(self._slots.keys())
            for u in all_users:
                user_pool = self._slots.pop(u, {})
                for s, sess in user_pool.items():
                    await self._close_detached(sess)


class OpenBastionSSHServer(asyncssh.SSHServer):
    """
    OpenBastion 核心 SSH-2.0 伺服器回呼處理器。
    SSH-2.0 protocol callback handler for client authentication and session setup.
    """

    def __init__(self, gateway: "GatewayListener") -> None:
        """
        初始化 SSH 伺服器回呼實例。
        Initialize the SSH server callback handler instance.
        """
        self.gateway = gateway
        self.authenticated_user: Optional[Dict[str, Any]] = None

    def password_auth_supported(self) -> bool:
        """
        宣告本閘道支援密碼認證回呼。
        Declare that password authentication callback is supported by this gateway.
        """
        return True

    def validate_password(self, username: str, password: str) -> bool:
        """
        驗證連線者之帳號密碼 (接軌 SQLite PBKDF2 加鹽雜湊比對)。
        Validate client credentials against SQLite using PBKDF2 constant-time verification.
        支援使用者名稱穿透直連語法 (如: admin#192.168.31.129 或 admin#3)。
        """
        effective_user = username.split("#", 1)[0] if "#" in username else username
        ok, user = self.gateway.storage.authenticate(effective_user, password)
        if ok and user:
            logger.info("[AUTH_OK] 使用者 '%s' [連線標的: '%s'] 密碼加鹽鑑權成功 (Password authentication succeeded)", effective_user, username)
            self.authenticated_user = user
            return True

        logger.warning("[AUTH_DENIED] 使用者 '%s' 憑證驗證失敗或查無帳號 (Authentication failed or user not found)", username)
        return False


class GatewayListener:
    """
    非阻塞標準 SSH-2.0 閘道監聽器。
    Non-blocking SSH-2.0 gateway listener managing RFC 4253 handshakes, DB authentication, and sessions.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 2222,
        storage: Optional[StorageProvider] = None,
        host_key_path: Optional[Any] = None,
        vault: Optional[CredentialVault] = None,
        banner_provider: Optional[IBannerProvider] = None,
        connector: Optional[TargetConnector] = None,
        recordings_dir: Optional[Path] = None,
        ca_mgr: Optional[CertificateAuthorityManager] = None,
    ) -> None:
        """
        初始化 SSH-2.0 閘道監聽實例。
        Initialize the non-blocking SSH-2.0 gateway listener instance.
        """
        self.host = host
        self.port = port
        self.storage = storage or StorageProvider()
        self._host_key_path_compat = host_key_path
        self.vault = vault or CredentialVault()
        self.banner_provider = banner_provider or DefaultTemplateBannerProvider()
        self.ca_mgr = ca_mgr or CertificateAuthorityManager(storage=self.storage, vault=self.vault)
        self.connector = connector or TargetConnector(vault=self.vault, ca_mgr=self.ca_mgr, storage=self.storage)
        self.recordings_dir = recordings_dir or Path("recordings")
        self._server: Optional[asyncssh.SSHServerAcceptor] = None
        self._active_connections: Dict[str, asyncssh.SSHServerProcess] = {}
        self.session_pool = DetachedSessionPool(storage=self.storage)

    def kill_session(self, session_id: str) -> bool:
        """
        管理員手動緊急中斷連線 (Kill Switch)。
        Forcefully terminate an active session process by administrator.
        """
        proc = self._active_connections.pop(session_id, None)
        if proc and not proc.is_closing():
            killed_msg = t("gateway.session_killed")
            try:
                proc.stdout.write(killed_msg)
            except Exception:
                pass
            proc.exit(1)

        ok = self.storage.kill_session(session_id)
        if ok:
            logger.warning("[KILL_SWITCH] 管理員強制中斷會話 [ID: %s] (Admin forcefully terminated session)", session_id)
        return ok

    def _ensure_host_key(self) -> asyncssh.SSHKey:
        """
        自資料庫載入伺服器主機金鑰，若無則自動生成並持久化至 DB。
        Load server host key from database memory, or generate and persist to DB if absent.
        """
        key_str = self.storage.get_config("server_host_key")
        if key_str:
            try:
                key = asyncssh.import_private_key(key_str)
                logger.info("[KEY_LOAD_OK] 已自資料庫記憶體載入伺服器主機金鑰 (Server host key loaded from database)")
                return key
            except Exception as e:
                logger.warning("[KEY_PARSE_ERR] 解析資料庫金鑰字串失敗，重新生成: %s (Failed to parse key, regenerating)", e)

        # 自動生成 ED25519 金鑰字串並寫入 DB
        logger.info("[KEY_GEN_OK] 未偵測到主機金鑰，已生成 ED25519 金鑰並存入資料庫 (Generated and persisted ED25519 key to DB)")
        key = asyncssh.generate_private_key("ssh-ed25519")
        exported = key.export_private_key("openssh")
        exported_str = exported.decode("utf-8") if isinstance(exported, bytes) else str(exported)
        self.storage.set_config("server_host_key", exported_str)
        return key

    async def _read_menu_input(
        self,
        process: asyncssh.SSHServerProcess,
        state: Dict[str, bool],
    ) -> Optional[str]:
        """
        從連線者終端讀取選單指令，相容 CR/LF (\r, \n, \r\n) 換行符號、支援即時字元回顯與退格鍵 Backspace。
        Read interactive menu input supporting CR/LF handling, character echo, and backspace.
        """
        buf: list[str] = []
        while not process.is_closing():
            try:
                ch = await process.stdin.read(1)
            except (asyncio.IncompleteReadError, asyncssh.TerminalSizeChanged):
                return None
            except Exception:
                return None

            if not ch:
                return None

            # 若前次以 \r 換行，忽略緊隨其後的 \n (相容 Windows CRLF)
            if ch == "\n" and state.get("last_cr"):
                state["last_cr"] = False
                continue
            state["last_cr"] = False

            if ch in ("\r", "\n"):
                if ch == "\r":
                    state["last_cr"] = True
                process.stdout.write("\r\n")
                await process.stdout.drain()
                return "".join(buf)
            elif ch in ("\x08", "\x7f"):  # 退格鍵 Backspace / DEL
                if buf:
                    buf.pop()
                    process.stdout.write("\b \b")
                    await process.stdout.drain()
            elif ch == "\x03":  # Ctrl+C 取消當前行輸入
                buf.clear()
                process.stdout.write("^C\r\n")
                await process.stdout.drain()
                return ""
            elif ord(ch) >= 0x20:  # 可見字元與空格
                if len(buf) < MAX_INPUT_LENGTH:
                    buf.append(ch)
                    process.stdout.write(ch)
                    await process.stdout.drain()

        return None

    async def _wait_for_any_key(
        self,
        process: asyncssh.SSHServerProcess,
        state: Optional[Dict[str, bool]] = None,
    ) -> None:
        """
        等待連線者按下任意單一按鍵 (包含空白、字母、數字、Enter 或 Esc) 即刻返回。
        Wait for any single keypress from the client terminal and return immediately.
        """
        if process.is_closing():
            return
        try:
            ch = await process.stdin.read(1)
            # 若為換行符號且伴隨 CRLF，消耗成對換行符
            if ch == "\r":
                if state is not None:
                    state["last_cr"] = True
            elif ch == "\n":
                if state is not None:
                    state["last_cr"] = False
            process.stdout.write("\r\n")
            await process.stdout.drain()
        except Exception:
            pass

    async def _handle_client(self, process: asyncssh.SSHServerProcess) -> None:
        """
        處理連線後之客戶端 PTY 互動字元流與偏好狀態機。
        Handle connected client PTY interactive character stream and preference state machine.
        """
        raw_username = process.get_extra_info("username") or "unknown"
        direct_target = None
        if "#" in raw_username:
            username, direct_target = raw_username.split("#", 1)
        else:
            username = raw_username
        peername = process.get_extra_info("peername")
        client_ip = peername[0] if peername else "unknown"

        # 自儲存層取得使用者資訊 (角色、部門)
        user_info = self.storage.get_user_by_username(username) or {}
        role = user_info.get("role", "user")
        dept = user_info.get("department", "default")
        user_id = user_info.get("user_id", username)

        # 登記連線會話
        session_id = self.storage.create_session(
            user_id=user_id,
            username=username,
            client_ip=client_ip,
        )
        self._active_connections[session_id] = process
        logger.info("[SESSION_START] 使用者 '%s' (角色: %s) 從 %s 建立會話 [ID: %s] (Session established)", username, role, client_ip, session_id)

        # 自資料庫讀取真實主機資產清單注入選單！
        db_hosts = self.storage.list_hosts(role=role, department=dept)
        menu = TerminalMenu(servers=db_hosts)

        # 讀取使用者專屬個人偏好 (Preferences)
        user_prefs = self.storage.get_user_preferences(user_id)
        current_page = 1
        view_mode = user_prefs.get("view", "system")
        search_query = None
        current_locale = user_prefs.get("locale", get_locale())
        set_locale(current_locale)

        # 輔助函式：解析穿透直連目標主機
        def find_direct_host(target_str: str) -> Tuple[Optional[Dict[str, Any]], Optional[int]]:
            query = target_str.strip()
            # 1. 依序號查找 (如 #3 或 3)
            num_str = query[1:] if query.startswith("#") else query
            if num_str.isdigit():
                idx = int(num_str)
                if 1 <= idx <= len(db_hosts):
                    return db_hosts[idx - 1], idx
            # 2. 依主機 IP、名稱、別名或 IP:PORT 精確比對
            for idx, h in enumerate(db_hosts, 1):
                h_ip = h.get("internal_ip") or h.get("host")
                h_port = str(h.get("port", 22))
                h_name = h.get("name")
                h_alias = h.get("alias")
                h_host_id = h.get("host_id")
                if query in (h_ip, f"{h_ip}:{h_port}", h.get("host"), f"{h.get('host')}:{h_port}", h_name, h_alias, h_host_id):
                    return h, idx
            return None, None

        is_direct_connect = direct_target is not None
        direct_executed = False
        direct_host_index: Optional[int] = None

        # 輔助函式：動態取得當前暫掛會話狀態並繪製選單
        async def render_current_menu() -> str:
            d_list = await self.session_pool.get_active_sessions(username)
            d_count = len(d_list)
            d_slots = [
                f"[r{s.slot}] {s.host_info.get('name', s.host_info.get('host'))} ({s.target_user})"
                for s in d_list
            ]
            return menu.render(
                page=current_page,
                view_mode=view_mode,
                search_query=search_query,
                locale=current_locale,
                detached_count=d_count,
                detached_slots=d_slots if d_count > 0 else None,
            )

        # 初始繪製選單 (若為穿透直連模式則跳過選單繪製)
        if not is_direct_connect:
            process.stdout.write(await render_current_menu())
            await process.stdout.drain()

        # 終端命令列互動回環 (Terminal interactive loop with UX actions)
        input_state = {"last_cr": False}
        try:
            while not process.is_closing():
                if is_direct_connect:
                    if direct_executed:
                        break
                    direct_executed = True
                    matched_host, direct_idx = find_direct_host(direct_target)
                    if not matched_host:
                        not_found_msg = t("gateway.direct_target_not_found", locale=current_locale, default=f"查無指定之直連目標主機: {direct_target} (Target host not found)")
                        process.stdout.write(f"\r\n\033[1;31m[ERROR] {not_found_msg}\033[0m\r\n")
                        await process.stdout.drain()
                        break
                    action = "connect"
                    payload = matched_host
                    direct_host_index = direct_idx
                else:
                    process.stdout.write("openbastion> ")
                    await process.stdout.drain()

                    line = await self._read_menu_input(process, input_state)
                    if line is None:
                        break

                    raw_cmd = line.strip()
                    if not raw_cmd:
                        continue

                    if len(raw_cmd) > MAX_INPUT_LENGTH:
                        toolong_msg = t("gateway.cmd_too_long", locale=current_locale)
                        process.stdout.write(f"{toolong_msg}\r\n")
                        await process.stdout.drain()
                        continue

                    # 管理員緊急會話管理指令 (Admin Kill Switch & Sessions inspection)
                    if raw_cmd == "sessions":
                        if role != "admin":
                            perm_msg = t("gateway.permission_denied", locale=current_locale)
                            process.stdout.write(f"{perm_msg}\r\n")
                            await process.stdout.drain()
                            continue
                        active_list = self.storage.list_active_sessions()
                        header = t("gateway.sessions_header", locale=current_locale)
                        process.stdout.write(f"\r\n{header}\r\n")
                        if not active_list:
                            process.stdout.write(f"  {t('gateway.no_other_sessions', locale=current_locale)}\r\n")
                        else:
                            for s in active_list:
                                process.stdout.write(
                                    f"  * [{s['session_id']}] {s['username']} ({s['client_ip']}) - {s['started_at']}\r\n"
                                )
                        process.stdout.write("\r\n")
                        await process.stdout.drain()
                        continue

                    if raw_cmd.startswith("kill "):
                        if role != "admin":
                            perm_msg = t("gateway.permission_denied", locale=current_locale)
                            process.stdout.write(f"{perm_msg}\r\n")
                            await process.stdout.drain()
                            continue
                        parts = raw_cmd.split()
                        if len(parts) >= 2:
                            target_sid = parts[1]
                            success = self.kill_session(target_sid)
                            if success:
                                msg = t("gateway.kill_success", locale=current_locale, session_id=target_sid)
                            else:
                                msg = t("gateway.kill_failed", locale=current_locale, session_id=target_sid)
                            process.stdout.write(f"{msg}\r\n")
                            await process.stdout.drain()
                        continue

                    action, payload = menu.resolve_action(
                        raw_cmd,
                        current_page=current_page,
                        view_mode=view_mode,
                        search_query=search_query,
                    )

                if action == "exit":
                    bye_msg = t("gateway.bye", locale=current_locale)
                    process.stdout.write(f"{bye_msg}\r\n")
                    await process.stdout.drain()
                    break
                elif action == "show_locales":
                    header = t("gateway.locales_header", locale=current_locale)
                    process.stdout.write(f"\r\n{header}\r\n")
                    for item in get_supported_locales_info():
                        line_str = t(
                            "gateway.locales_item",
                            locale=current_locale,
                            code=item["code"],
                            name=item["name"],
                            hint=item["hint"],
                        )
                        process.stdout.write(f"{line_str}\r\n")
                    process.stdout.write("\r\n")
                    await process.stdout.drain()
                elif action == "unsupported_locale":
                    err_msg = t("gateway.locale_not_supported", locale=current_locale, query=payload)
                    process.stdout.write(f"{err_msg}\r\n")
                    await process.stdout.drain()
                elif action == "set_locale":
                    current_locale = payload
                    set_locale(current_locale)
                    self.storage.update_user_preference(user_id, "locale", current_locale)
                    process.stdout.write(await render_current_menu())
                    await process.stdout.drain()
                elif action == "toggle_view":
                    view_mode = payload
                    self.storage.update_user_preference(user_id, "view", view_mode)
                    process.stdout.write(await render_current_menu())
                    await process.stdout.drain()
                elif action in ("next_page", "prev_page"):
                    current_page = payload
                    process.stdout.write(await render_current_menu())
                    await process.stdout.drain()
                elif action == "search":
                    search_query = payload
                    current_page = 1
                    process.stdout.write(await render_current_menu())
                    await process.stdout.drain()
                elif action == "clear_search":
                    search_query = None
                    current_page = 1
                    process.stdout.write(await render_current_menu())
                    await process.stdout.drain()
                elif action == "reattach":
                    slot_target = payload
                    detached = await self.session_pool.pop_session(username, slot=slot_target)
                    if not detached:
                        no_sess_msg = t("gateway.no_detached_session", locale=current_locale, default="無可接回的暫掛會話或該槽位連線已結束")
                        process.stdout.write(f"\r\n\033[1;33m>>> {no_sess_msg}\033[0m\r\n\r\n")
                        await process.stdout.drain()
                        process.stdout.write(await render_current_menu())
                        await process.stdout.drain()
                        continue

                    # 恢復雙向通道
                    pipe = detached.pipe
                    pipe.client_reader = process.stdin
                    pipe.client_writer = process.stdout
                    target_session = detached.target_session
                    recorder = detached.recorder

                    # 1. 終端畫面即時重繪 (512KB RingBuffer Snapshot)
                    snapshot = pipe.get_replay_snapshot()
                    if snapshot:
                        process.stdout.write("\033[2J\033[H")
                        pipe._write_adaptive(process.stdout, snapshot)
                        await process.stdout.drain()

                    # 2. 恢復轉發執行
                    exit_reason = "normal"
                    try:
                        exit_reason = await pipe.run()
                    except Exception as run_err:
                        logger.warning("[PIPE_ERROR] 暫掛接回水管異常: %s (Reattach pipe forwarding exception: %s)", run_err, run_err)
                        exit_reason = "error"

                    if exit_reason == "escape":
                        slot_id = await self.session_pool.put_session(
                            username=username,
                            session_id=detached.session_id,
                            target_session=target_session,
                            pipe=pipe,
                            recorder=recorder,
                            audit_engine=detached.audit_engine,
                            host_info=detached.host_info,
                            target_user=detached.target_user,
                        )
                        detach_hint = t(
                            "gateway.session_detached",
                            locale=current_locale,
                            slot=slot_id,
                            default=f"會話已暫掛至槽位 [{slot_id}]，按 [r{slot_id}] 或 [r] 可隨時接回",
                        )
                        process.stdout.write(f"\r\n\033[1;32m>>> {detach_hint}\033[0m\r\n\r\n")
                        await process.stdout.drain()
                    else:
                        await target_session.close()
                        rec_path, rec_size, rec_sha, rec_duration = recorder.close()
                        if rec_sha:
                            try:
                                self.storage.save_recording_metadata(
                                    session_id=detached.session_id,
                                    file_path=str(rec_path),
                                    file_size=rec_size,
                                    sha256_hash=rec_sha,
                                    duration_seconds=rec_duration,
                                )
                            except Exception as save_err:
                                logger.error("[STORAGE_ERROR] 儲存錄影元資料失敗: %s (Failed to save recording metadata: %s)", save_err, save_err)

                        exit_hint = t("gateway.session_ended", locale=current_locale, default="已結束目標主機連線，正在返回選單...")
                        process.stdout.write(f"\r\n\033[0m\033[1;33m>>> {exit_hint} [{exit_reason}]\033[0m\r\n\r\n")
                        await process.stdout.drain()

                    process.stdout.write("\033[2J\033[H\033[0m")
                    process.stdout.write(await render_current_menu())
                    await process.stdout.drain()
                elif action in ("connect", "auto_connect"):
                    target = payload
                    host_id = target.get("host_id") or target.get("id")
                    full_target = self.storage.get_host_by_id(host_id) if host_id else None
                    host_info = full_target or target

                    # 計算目標主機在目前選單中之序號
                    host_idx = direct_host_index if is_direct_connect and direct_host_index else None
                    if host_idx is None:
                        for i, h in enumerate(db_hosts, 1):
                            if (host_id and h.get("host_id") == host_id) or (h.get("host") == host_info.get("host") and str(h.get("port", 22)) == str(host_info.get("port", 22))):
                                host_idx = i
                                break

                    term_size = process.get_terminal_size() or (80, 24)
                    term_width, term_height = term_size[0], term_size[1]
                    term_type = process.get_terminal_type() or "xterm-256color"

                    # 1. 清屏並發送連線進行中提示
                    process.stdout.write("\033[2J\033[H\033[0m")
                    conn_hint = t("gateway.connecting_target", locale=current_locale, default="正在連線至目標主機並獲取系統狀態...")
                    h_display = host_info.get("name") or host_info.get("host")
                    process.stdout.write(f"\033[1;36m>>> {conn_hint} ({h_display})\033[0m\r\n")
                    await process.stdout.drain()

                    # 2. 建立與目標主機的 SSH 連線、採集主機指標與分配 PTY
                    try:
                        target_session = await self.connector.connect(
                            host_info=host_info,
                            login_username=username,
                            term_width=term_width,
                            term_height=term_height,
                            term_type=term_type,
                            timeout=10.0,
                        )
                        if host_id:
                            self.storage.update_session_host(session_id, str(host_id))
                    except Exception as err:
                        logger.warning("[TARGET_CONN_FAILED] 連線至目標主機失敗: %s (Failed to connect to target host: %s)", err, err)
                        err_title = t("gateway.conn_failed", locale=current_locale, default="連線至目標主機失敗")
                        err_str = str(err)
                        diag_hint = ""
                        if "1225" in err_str or "ConnectionRefused" in err_str or "refused" in err_str.lower():
                            diag_hint = "\r\n\033[1;33m" + t("gateway.diag_conn_refused", locale=current_locale) + "\033[0m"
                        elif "timeout" in err_str.lower() or "10060" in err_str:
                            diag_hint = "\r\n\033[1;33m" + t("gateway.diag_conn_timeout", locale=current_locale) + "\033[0m"
                        elif "permission" in err_str.lower() or "denied" in err_str.lower():
                            diag_hint = "\r\n\033[1;33m" + t("gateway.diag_conn_denied", locale=current_locale) + "\033[0m"

                        process.stdout.write(f"\r\n\033[1;31m[ERROR] {err_title}: {err}\033[0m{diag_hint}\r\n")
                        await process.stdout.drain()
                        if is_direct_connect:
                            break

                        press_hint = t("gateway.press_any_key", locale=current_locale, default="請按任意鍵返回主選單...")
                        process.stdout.write(f"\r\n{press_hint}\r\n")
                        await process.stdout.drain()
                        await self._wait_for_any_key(process, input_state)
                        process.stdout.write("\033[2J\033[H\033[0m")
                        process.stdout.write(await render_current_menu())
                        await process.stdout.drain()
                        continue

                    # 3. 提取探針指標與歷史登入，組裝連線 Banner
                    probe = target_session.probe_data or {}
                    cpu_load = probe.get("cpu_load") or host_info.get("cpu_load")
                    mem_usage = probe.get("mem_usage") or host_info.get("mem_usage")
                    disk_usage = probe.get("disk_usage") or host_info.get("disk_usage")
                    up_sec = probe.get("uptime_seconds")
                    if "en" in current_locale.lower() and probe.get("uptime_en"):
                        uptime = probe.get("uptime_en")
                    else:
                        uptime = probe.get("uptime_zh") or probe.get("uptime") or host_info.get("uptime")
                    sys_name = probe.get("system") or host_info.get("system") or "-"

                    # 查詢最近登入紀錄（核對目標主機 last 紀錄與跳板機連線紀錄）
                    recent_login_str: Optional[str] = None
                    recent_logins_list: Optional[List[str]] = None
                    audit_anomaly = False
                    probe_logins = probe.get("recent_logins") or []
                    bastion_ip = probe.get("bastion_outbound_ip")
                    recent_record = self.storage.get_recent_login_for_user(username, host_id)

                    if probe_logins:
                        tagged_logins: List[str] = []
                        for item in probe_logins:
                            # 提取括號內的 IP 位址
                            ip_match = re.search(r"\(([^)]+)\)", item)
                            rec_ip = ip_match.group(1).strip() if ip_match else "-"

                            # 判定是否為合規跳板會話 (來源為跳板機出口 IP、本機環回、或資料庫紀錄相符)
                            is_bastion_session = False
                            if bastion_ip and rec_ip == bastion_ip:
                                is_bastion_session = True
                            elif rec_ip in ("127.0.0.1", "::1", "localhost"):
                                is_bastion_session = True
                            elif recent_record and recent_record.get("client_ip") == rec_ip:
                                is_bastion_session = True

                            if is_bastion_session:
                                tag = " " + t("banner.audit_match", locale=current_locale, default="[稽核一致]")
                                tagged_logins.append(f"{item}{tag}")
                            else:
                                tag = " " + t("banner.unaudited", locale=current_locale, default="[未經審計]")
                                tagged_logins.append(f"{item}{tag}")
                                audit_anomaly = True

                        if audit_anomaly:
                            # 偵測到未經跳板之登入：展開歷史紀錄供查驗
                            recent_logins_list = tagged_logins
                            recent_login_str = tagged_logins[0]
                        else:
                            # 紀錄一致：僅保留最新 1 筆，保持單行緊湊
                            recent_login_str = tagged_logins[0]
                            recent_logins_list = [recent_login_str]
                    elif recent_record and recent_record.get("started_at"):
                        r_started = recent_record.get("started_at")
                        r_ip = recent_record.get("client_ip") or "gateway"
                        tag_bastion = " " + t("banner.bastion_record", locale=current_locale, default="[跳板備案]")
                        recent_login_str = f"{r_started} ({r_ip}) {tag_bastion}"
                        recent_logins_list = [recent_login_str]

                    user_record = self.storage.get_user_by_id(user_id) if hasattr(self.storage, "get_user_by_id") else None
                    raw_display = (user_record.get("display_name") if user_record else None)
                    if username == "admin" and (not raw_display or raw_display in ("系統初始管理員", "系統管理員", "admin")):
                        op_name = t("banner.admin_display", locale=current_locale, default="系統管理員")
                    else:
                        op_name = raw_display or username
                    op_dept = (user_record.get("department") if user_record else None) or host_info.get("dept", "default")
                    target_user_val = target_session.target_user or host_info.get("default_user", "{username}").replace("{username}", username)

                    banner_ctx = BannerContext(
                        hostname=host_info.get("name") or host_info.get("host"),
                        ip=host_info.get("internal_ip") or host_info.get("host"),
                        port=int(host_info.get("port", 22)),
                        host_index=host_idx,
                        system=sys_name,
                        dept=host_info.get("dept") or "default",
                        service_desc=host_info.get("alias"),
                        status=host_info.get("status") or "online",
                        cpu_load=cpu_load,
                        mem_usage=mem_usage,
                        disk_usage=disk_usage,
                        uptime=uptime,
                        uptime_seconds=up_sec,
                        listen_ports=str(host_info.get("port", 22)),
                        operator_username=username,
                        operator_name=op_name,
                        operator_dept=op_dept,
                        target_user=target_user_val,
                        account_expires_at="forever",
                        provision_mode=host_info.get("provision_mode", "direct"),
                        sudo_perms="all" if (user_record and user_record.get("role") == "admin") or username == "admin" else None,
                        recent_login=recent_login_str,
                        recent_logins=recent_logins_list,
                        session_id=session_id,
                        locale=current_locale,
                        audit_anomaly=audit_anomaly,
                    )
                    banner_text = await render_banner_safe(self.banner_provider, banner_ctx)
                    process.stdout.write("\033[2J\033[H\033[0m" + banner_text)
                    await process.stdout.drain()

                    # 4. 初始化 asciinema v2 錄影器
                    recorder = AsciinemaRecorder(
                        session_id=session_id,
                        output_dir=self.recordings_dir,
                        width=term_width,
                        height=term_height,
                    )
                    recorder.start()

                    # 5. 初始化即時指令審計防禦引擎 (注入雙軸審計主機 IP 與名稱)
                    pipe_ref: Dict[str, Optional[StreamPipe]] = {"pipe": None}

                    def handle_block(blocked_cmd: str) -> None:
                        p = pipe_ref.get("pipe")
                        if p:
                            alert_msg = t("gateway.security_alert_blocked", locale=current_locale, blocked_cmd=blocked_cmd)
                            asyncio.create_task(
                                p.inject_inband_message(
                                    f"\r\n\033[1;41;37m {alert_msg} \033[0m\r\n"
                                )
                            )

                    audit_engine = AuditEngine(
                        storage=self.storage,
                        session_id=session_id,
                        user_id=user_id,
                        username=username,
                        host_id=str(host_id or host_info.get("host")),
                        host_ip=str(host_info.get("internal_ip") or host_info.get("host") or ""),
                        host_name=str(host_info.get("name") or host_info.get("host") or ""),
                        on_block_action=handle_block,
                    )

                    # 6. 建立雙向非阻塞字元水管 (Stream Pipe)
                    pipe = StreamPipe(
                        client_reader=process.stdin,
                        client_writer=process.stdout,
                        target_reader=target_session.target_reader,
                        target_writer=target_session.target_writer,
                        target_process=target_session.process,
                        on_input=lambda data: (recorder.record_input(data), audit_engine.feed_keystroke(data)),
                        on_output=lambda data: recorder.record_output(data),
                    )
                    pipe_ref["pipe"] = pipe

                    exit_reason = "normal"
                    try:
                        exit_reason = await pipe.run()
                    except Exception as run_err:
                        logger.warning("[PIPE_ERROR] 轉發水管執行異常: %s (Forwarding pipe execution exception: %s)", run_err, run_err)
                        exit_reason = "error"

                    if exit_reason == "escape":
                        slot_id = await self.session_pool.put_session(
                            username=username,
                            session_id=session_id,
                            target_session=target_session,
                            pipe=pipe,
                            recorder=recorder,
                            audit_engine=audit_engine,
                            host_info=host_info,
                            target_user=target_user_val,
                        )
                        detach_hint = t(
                            "gateway.session_detached",
                            locale=current_locale,
                            slot=slot_id,
                            default=f"會話已暫掛至槽位 [{slot_id}]，按 [r{slot_id}] 或 [r] 可隨時接回",
                        )
                        process.stdout.write(f"\r\n\033[1;32m>>> {detach_hint}\033[0m\r\n\r\n")
                        await process.stdout.drain()
                        if is_direct_connect:
                            break
                    else:
                        await target_session.close()
                        rec_path, rec_size, rec_sha, rec_duration = recorder.close()
                        if rec_sha:
                            try:
                                self.storage.save_recording_metadata(
                                    session_id=session_id,
                                    file_path=str(rec_path),
                                    file_size=rec_size,
                                    sha256_hash=rec_sha,
                                    duration_seconds=rec_duration,
                                )
                            except Exception as save_err:
                                logger.error("[STORAGE_ERROR] 儲存錄影元資料失敗: %s (Failed to save recording metadata: %s)", save_err, save_err)

                        if is_direct_connect:
                            exit_hint = t(
                                "gateway.direct_session_ended",
                                locale=current_locale,
                                default="已結束目標主機連線，跳板會話已正常關閉...",
                            )
                        else:
                            exit_hint = t(
                                "gateway.session_ended",
                                locale=current_locale,
                                default="已結束目標主機連線，正在返回選單...",
                            )
                        process.stdout.write(f"\r\n\033[0m\033[1;33m>>> {exit_hint} [{exit_reason}]\033[0m\r\n\r\n")
                        await process.stdout.drain()

                    if is_direct_connect:
                        break

                    process.stdout.write("\033[2J\033[H\033[0m")
                    process.stdout.write(await render_current_menu())
                    await process.stdout.drain()
                else:
                    invalid_msg = t("gateway.invalid_cmd", locale=current_locale)
                    process.stdout.write(f"{invalid_msg}\r\n")
                    await process.stdout.drain()
        except Exception as client_err:
            logger.error(
                "[CLIENT_ERROR] 處理客戶端連線時發生未預期異常: %s (Unexpected client connection error)",
                client_err,
                exc_info=True,
            )
            try:
                err_msg = t(
                    "gateway.internal_error",
                    locale=current_locale,
                    default=f"伺服器內部異常: {client_err}",
                )
                process.stdout.write(f"\r\n\033[1;31m[ERROR] {err_msg}\033[0m\r\n")
                await process.stdout.drain()
            except Exception:
                pass
        finally:
            await self.session_pool.close_all_for_user(username)
            self._active_connections.pop(session_id, None)
            self.storage.close_session(session_id)
            process.exit(0)
            logger.info("[SESSION_CLOSED] 使用者 '%s' 會話已正常關閉 [ID: %s] (Session closed normally)", username, session_id)

    async def start(self) -> None:
        """
        啟動非阻塞 SSH 伺服器監聽服務。
        Start non-blocking SSH server listening on configured host and port.
        """
        host_key = self._ensure_host_key()

        self._server = await asyncssh.create_server(
            lambda: OpenBastionSSHServer(self),
            self.host,
            self.port,
            server_host_keys=[host_key],
            process_factory=self._handle_client,
            encoding="utf-8",
            line_editor=False,
        )
        logger.info("[GATEWAY_READY] OpenBastion SSH-2.0 閘道已啟動，監聽於 %s:%s (Gateway listening on %s:%s)", self.host, self.port, self.host, self.port)

    async def stop(self, timeout: float = 30.0, force: bool = False) -> None:
        """
        停止 SSH 伺服器並釋放監聽埠。
        Stop SSH server and release listening port with grace period client broadcast.
        """
        await self.session_pool.close_all()
        if self._server:
            logger.info("[GATEWAY_STOPPING] 正在停止 SSH-2.0 閘道伺服器 (Stopping SSH-2.0 gateway server...)")
            self._server.close()

            active_procs = list(self._active_connections.values())
            if active_procs and not force:
                logger.info(
                    "[SHUTDOWN_WAIT] 目前尚有 %d 個連線，已發送停機通知，等待最多 %d 秒... (Waiting for %d active connections to terminate up to %d seconds)",
                    len(active_procs),
                    int(timeout),
                    len(active_procs),
                    int(timeout),
                )
                for proc in active_procs:
                    try:
                        warn_msg = t("gateway.shutdown_warning", seconds=int(timeout), default=f"\r\n\u001b[1;33m[系統通知] 跳板機伺服器即將關閉，連線將在 {int(timeout)} 秒後結束...\u001b[0m\r\n")
                        proc.stdout.write(warn_msg)
                    except Exception:
                        pass

                try:
                    await asyncio.wait_for(self._server.wait_closed(), timeout=timeout)
                except (asyncio.TimeoutError, TimeoutError):
                    logger.warning(
                        "[SHUTDOWN_TIMEOUT] 等待逾時，正在關閉剩餘連線... (Shutdown wait timed out, terminating remaining connections)"
                    )
                    for proc in list(self._active_connections.values()):
                        try:
                            proc.exit(0)
                        except Exception:
                            pass
            else:
                for proc in active_procs:
                    try:
                        proc.exit(0)
                    except Exception:
                        pass

            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=2.0)
            except Exception:
                pass

            self._server = None
            logger.info("[GATEWAY_STOPPED] SSH-2.0 閘道伺服器已安全停止 (SSH-2.0 gateway server safely stopped)")
