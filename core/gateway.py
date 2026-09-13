"""
OpenBastion Core - Gateway Listener (SSH-2.0 通道監聽與協定握手)
=============================================================
依據 docs/SPEC.md §2.1 (Gateway Listener & Handshake) 與 RFC 4253 / RFC 4252 / RFC 4254 規範。
Standard RFC 4253 non-blocking SSH-2.0 gateway listener powered by asyncssh.

核心職責 / Responsibilities:
  1. 基於 asyncssh 實裝標準非阻塞 SSH-2.0 協定監聽服務。
     (Standard non-blocking SSH-2.0 server listener powered by asyncssh).
  2. 自動管理與持久化主機 ED25519 金鑰 (data/ssh_host_key)。
     (Auto-generate and persist ED25519 server host key).
  3. 實裝真實密碼鑑權 (Password Authentication) 回呼。
     (Validate incoming credentials against system authentication baseline).
  4. 分配 PTY 虛擬終端字元流，並保證 process.stdout.drain() 即時刷新時序。
     (Handle terminal I/O streaming with guaranteed stdout drain timing).
"""

import asyncio
import logging
import os
from pathlib import Path
from typing import Optional

import asyncssh

from core.i18n import get_locale, set_locale, t
from core.menu import TerminalMenu

logger = logging.getLogger("openbastion.gateway")

DEFAULT_HOST_KEY_PATH = Path("data/ssh_host_key")


class OpenBastionSSHServer(asyncssh.SSHServer):
    """
    OpenBastion 核心 SSH-2.0 伺服器回呼處理器。
    SSH-2.0 protocol callback handler for client authentication and session setup.
    """

    def __init__(self, gateway: "GatewayListener") -> None:
        """
        初始化 SSH 伺服器回呼。
        Initialize SSH server callback instance.
        """
        self.gateway = gateway

    def password_auth_supported(self) -> bool:
        """
        宣告支援密碼認證。
        Declare password authentication is supported.
        """
        return True

    def validate_password(self, username: str, password: str) -> bool:
        """
        驗證連線者之帳號密碼。
        嚴格遵守 Fail-Closed (Default Deny) 原則：
        在 Phase 3 使用者資料庫就位前，系統無合法憑證，一律嚴格拒絕連線。
        """
        logger.warning(t("log.auth_denied_no_db", username=username))
        return False


MAX_INPUT_LENGTH = 256


class GatewayListener:
    """
    非阻塞標準 SSH-2.0 閘道監聽器。
    Non-blocking SSH-2.0 gateway listener managing RFC 4253 handshakes and terminal sessions.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 2222,
        host_key_path: Optional[Path] = None,
    ) -> None:
        """
        初始化閘道監聽器設定。
        Initialize gateway listener settings.
        """
        self.host = host
        self.port = port
        self.host_key_path = host_key_path or DEFAULT_HOST_KEY_PATH
        self._server: Optional[asyncssh.SSHServerAcceptor] = None

    def _ensure_host_key(self) -> asyncssh.SSHKey:
        """
        檢查並載入主機金鑰，若不存在則自動生成持久化 ED25519 金鑰。
        Load server host key, auto-generating and persisting ED25519 key if missing.
        """
        self.host_key_path.parent.mkdir(parents=True, exist_ok=True)

        if self.host_key_path.exists():
            try:
                key = asyncssh.read_private_key(str(self.host_key_path))
                logger.info(t("log.host_key_loaded", path=str(self.host_key_path)))
                return key
            except Exception as e:
                logger.warning(t("log.host_key_load_failed", error=str(e)))

        # 自動生成 ED25519 私鑰
        logger.info(t("log.host_key_generating"))
        key = asyncssh.generate_private_key("ssh-ed25519")
        key.write_private_key(str(self.host_key_path))
        try:
            os.chmod(self.host_key_path, 0o600)
        except OSError:
            pass
        logger.info(t("log.host_key_persisted", path=str(self.host_key_path)))
        return key

    async def _handle_client(self, process: asyncssh.SSHServerProcess) -> None:
        """
        處理連線後之客戶端 PTY 互動字元流。
        Handle connected client PTY interactive character stream.
        """
        username = process.get_extra_info("username") or "unknown"
        peername = process.get_extra_info("peername")
        client_ip = peername[0] if peername else "unknown"

        menu = TerminalMenu()
        current_page = 1
        view_mode = "system"
        search_query = None
        current_locale = get_locale()

        # 初始繪製選單
        process.stdout.write(menu.render(page=current_page, view_mode=view_mode, search_query=search_query, locale=current_locale))
        await process.stdout.drain()

        # 終端命令列互動回環 (Terminal interactive loop with UX actions)
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
            elif action == "set_locale":
                current_locale = payload
                set_locale(current_locale)
                process.stdout.write(menu.render(page=current_page, view_mode=view_mode, search_query=search_query, locale=current_locale))
                await process.stdout.drain()
            elif action == "toggle_view":
                view_mode = payload
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

        process.exit(0)
        logger.info(t("log.session_end", username=username))

    async def start(self) -> None:
        """
        啟動非阻塞 SSH 伺服器監聽服務。
        Start non-blocking SSH server listening.
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
        logger.info(t("log.gateway_listening", host=self.host, port=self.port))

    async def stop(self) -> None:
        """
        優雅停止 SSH 伺服器。
        Gracefully stop SSH server.
        """
        if self._server:
            logger.info(t("log.server_stopping"))
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            logger.info(t("log.server_stopped"))
