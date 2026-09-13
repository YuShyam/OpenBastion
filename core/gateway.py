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
from pathlib import Path
from typing import Any, Dict, Optional

import asyncssh

from core.i18n import get_locale, get_supported_locales_info, set_locale, t
from core.menu import TerminalMenu
from core.storage import StorageProvider

logger = logging.getLogger("openbastion.gateway")
MAX_INPUT_LENGTH = 256


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
        """
        ok, user = self.gateway.storage.authenticate(username, password)
        if ok and user:
            logger.info("[AUTH_OK] 使用者 '%s' 密碼加鹽鑑權成功 (Password authentication succeeded)", username)
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
    ) -> None:
        """
        初始化 SSH-2.0 閘道監聽實例。
        Initialize the non-blocking SSH-2.0 gateway listener instance.
        """
        self.host = host
        self.port = port
        self.storage = storage or StorageProvider()
        self._host_key_path_compat = host_key_path
        self._server: Optional[asyncssh.SSHServerAcceptor] = None
        self._active_connections: Dict[str, asyncssh.SSHServerProcess] = {}

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

    async def _handle_client(self, process: asyncssh.SSHServerProcess) -> None:
        """
        處理連線後之客戶端 PTY 互動字元流與偏好狀態機。
        Handle connected client PTY interactive character stream and preference state machine.
        """
        username = process.get_extra_info("username") or "unknown"
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

        # 初始繪製選單
        process.stdout.write(menu.render(page=current_page, view_mode=view_mode, search_query=search_query, locale=current_locale))
        await process.stdout.drain()

        # 終端命令列互動回環 (Terminal interactive loop with UX actions)
        try:
            while not process.is_closing():
                process.stdout.write("openbastion> ")
                await process.stdout.drain()

                try:
                    line = await process.stdin.readline()
                except (asyncio.IncompleteReadError, asyncssh.TerminalSizeChanged):
                    break

                if not line:
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
                    process.stdout.write(menu.render(page=current_page, view_mode=view_mode, search_query=search_query, locale=current_locale))
                    await process.stdout.drain()
                elif action == "toggle_view":
                    view_mode = payload
                    self.storage.update_user_preference(user_id, "view", view_mode)
                    process.stdout.write(menu.render(page=current_page, view_mode=view_mode, search_query=search_query, locale=current_locale))
                    await process.stdout.drain()
                elif action in ("next_page", "prev_page"):
                    current_page = payload
                    process.stdout.write(menu.render(page=current_page, view_mode=view_mode, search_query=search_query, locale=current_locale))
                    await process.stdout.drain()
                elif action == "search":
                    search_query = payload
                    current_page = 1
                    process.stdout.write(menu.render(page=current_page, view_mode=view_mode, search_query=search_query, locale=current_locale))
                    await process.stdout.drain()
                elif action == "clear_search":
                    search_query = None
                    current_page = 1
                    process.stdout.write(menu.render(page=current_page, view_mode=view_mode, search_query=search_query, locale=current_locale))
                    await process.stdout.drain()
                elif action in ("connect", "auto_connect"):
                    target = payload
                    ep = f"{target.get('host')}:{target.get('port', 22)}"
                    msg_key = "gateway.auto_connected_to" if action == "auto_connect" else "gateway.connected_to"
                    header_msg = t(msg_key, locale=current_locale, name=target.get("name"), endpoint=ep)
                    sys_msg = t("gateway.system_type", locale=current_locale, system=target.get("system"), dept=target.get("dept"))

                    process.stdout.write(f"\r\n{header_msg}\r\n{sys_msg}\r\n\r\n")
                    await process.stdout.drain()
                else:
                    invalid_msg = t("gateway.invalid_cmd", locale=current_locale)
                    process.stdout.write(f"{invalid_msg}\r\n")
                    await process.stdout.drain()
        finally:
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
        )
        logger.info("[GATEWAY_READY] OpenBastion SSH-2.0 閘道已啟動，監聽於 %s:%s (Gateway listening on %s:%s)", self.host, self.port, self.host, self.port)

    async def stop(self) -> None:
        """
        優雅停止 SSH 伺服器並釋放監聽埠。
        Gracefully stop SSH server and release listener sockets.
        """
        if self._server:
            logger.info("[GATEWAY_STOPPING] 正在停止 SSH-2.0 閘道伺服器 (Stopping SSH-2.0 gateway server...)")
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            logger.info("[GATEWAY_STOPPED] SSH-2.0 閘道伺服器已安全停止 (SSH-2.0 gateway server safely stopped)")
