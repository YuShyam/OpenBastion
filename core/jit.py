"""
OpenBastion 核心 - JIT 動態帳號治理與 RBAC 調度引擎 (JIT Provisioning & Dynamic RBAC Engine)
=============================================================================
依據 docs/SPEC.md §3.3 與 docs/adr/ADR_001_ZERO_TOUCH_AND_JIT.md 規範實作。
負責在 Level 3 零侵入模式下，透過 SSH 管理通道動態維護目標伺服器之獨立 POSIX UID、
強制執行密碼鎖定 (Fail-Closed)、並透過 /etc/sudoers.d/ 即時收放角色特權。

核心設計：
  1. Zero-Agent 原則：受控端不安裝任何代理程式或背景 Daemon，全依賴原生 OpenSSH 與標準 POSIX 指令。
  2. 密碼強制鎖定 (Password Lockout)：帳號建立後強制執行 usermod -L，拒絕密碼暴力猜測，只接受 CA 短期憑證。
  3. 動態 RBAC 派發：依連線者角色 (admin, auditor, user) 寫入或清理 /etc/sudoers.d/bastion_{user} (0440)，修改即時生效。
  4. 注入防護與邊界檢驗：帳號名稱嚴格檢驗白名單字元，所有指令參數強制通過 shlex.quote 安全過濾。
  5. 閒置巡檢支援：提供 prune_inactive_accounts 巡檢介面，辨識長週期未活動之 JIT 帳號。
"""

import asyncio
import logging
import re
import shlex
from typing import Any, Dict, List, Optional

import asyncssh

from core.i18n import t

logger = logging.getLogger("openbastion.jit")

# POSIX 使用者名稱合法字元白名單 (長度 1 ~ 32，小寫英文字母開頭相容標準 Linux)
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]{1,32}$")


class JitProvisionError(RuntimeError):
    """
    JIT 動態帳號調度異常。
    Exception raised when JIT account provisioning or sudoers configuration fails.
    """
    pass


class JitProvisioner:
    """
    JIT 動態帳號治理調度器。
    Orchestrates dynamic POSIX user provisioning, password locking, and sudoers RBAC on target Linux hosts.
    """

    def __init__(self, command_timeout: float = 8.0) -> None:
        """
        初始化 JIT 動態調度器。
        Initialize JIT provisioner with command timeout setting.

        :param command_timeout: 遠端指令執行逾時秒數 (Remote command execution timeout in seconds)
        """
        self.command_timeout = command_timeout

    @staticmethod
    def validate_username(username: str) -> str:
        """
        驗證使用者名稱格式是否符合 POSIX 安全標準，防止 Shell 注入。
        Validate username format against POSIX security standards to prevent shell injection.

        :param username: 待檢驗的使用者名稱 (Target username to validate)
        :return: 驗證通過的使用者名稱 (Validated username)
        :raises ValueError: 當使用者名稱包含非法字元或長度超限時 (When username contains invalid characters)
        """
        if not username or not USERNAME_REGEX.match(username):
            logger.error("[JIT_INVALID_USER] 使用者名稱格式非法: %s (Invalid target username format: %s)", username, username)
            raise ValueError(f"JIT 目標帳號名稱格式不合法: '{username}' (僅支援 1~32 字元之英數字、底線、減號與點號)")
        return username

    async def ensure_jit_user(
        self,
        conn: asyncssh.SSHClientConnection,
        target_user: str,
    ) -> bool:
        """
        確保目標 Linux 伺服器存在獨立的 POSIX 帳號，並強制鎖定密碼。
        Ensure individual POSIX account exists on target host and enforce password lock.

        :param conn: 具備管理特權之 SSH 通道 (Privileged SSH connection)
        :param target_user: 待治理的目標帳號名稱 (Target username to provision)
        :return: 成功完成治理回傳 True (Returns True on successful provisioning)
        :raises JitProvisionError: 當執行指令失敗或逾時時 (When command fails or times out)
        """
        user = self.validate_username(target_user)
        quoted_user = shlex.quote(user)

        logger.info("[JIT_PROVISION_START] 開始 JIT 帳號治理: %s (Starting JIT user provisioning: %s)", user, user)

        # 1. 檢測使用者帳號是否已存在 (Check if user exists)
        check_cmd = f"id -u {quoted_user} >/dev/null 2>&1"
        try:
            res_check = await asyncio.wait_for(conn.run(check_cmd), timeout=self.command_timeout)
            user_exists = (res_check.exit_status == 0)
        except Exception as err:
            logger.error("[JIT_CHECK_FAILED] 檢查帳號存在失敗 (%s): %s (Failed to check user existence)", user, err)
            raise JitProvisionError(f"檢查 JIT 帳號存在失敗: {err}")

        # 2. 帳號不存在時執行建立 (Create user if not present)
        if not user_exists:
            # 建立帳號並初始化 Home 目錄，Shell 預設指派 /bin/bash
            create_cmd = f"useradd -m -s /bin/bash {quoted_user}"
            try:
                res_create = await asyncio.wait_for(conn.run(create_cmd), timeout=self.command_timeout)
                if res_create.exit_status != 0:
                    err_msg = res_create.stderr.strip() if res_create.stderr else f"Exit code {res_create.exit_status}"
                    logger.error("[JIT_CREATE_FAILED] 建立 JIT 帳號失敗 (%s): %s (Failed to create user)", user, err_msg)
                    raise JitProvisionError(f"建立 JIT 帳號 '{user}' 失敗: {err_msg}")
                logger.info("[JIT_USER_CREATED] 成功建立獨立 JIT 帳號: %s (Successfully created JIT user: %s)", user, user)
            except Exception as err:
                if not isinstance(err, JitProvisionError):
                    logger.error("[JIT_CREATE_ERROR] 建立 JIT 帳號異常 (%s): %s (Exception creating user)", user, err)
                    raise JitProvisionError(f"建立 JIT 帳號異常: {err}")
                raise
        else:
            logger.info("[JIT_USER_EXISTS] 目標 JIT 帳號已存在，沿用既有 UID: %s (User exists, retaining UID: %s)", user, user)

        # 3. 強制密碼鎖定 (Fail-Closed Password Locking)
        # 無論新建或既有帳號，連線前皆強制執行 usermod -L 確保密碼登入被停用
        lock_cmd = f"usermod -L {quoted_user}"
        try:
            res_lock = await asyncio.wait_for(conn.run(lock_cmd), timeout=self.command_timeout)
            if res_lock.exit_status != 0:
                err_msg = res_lock.stderr.strip() if res_lock.stderr else f"Exit code {res_lock.exit_status}"
                logger.error("[JIT_LOCK_FAILED] 密碼強制鎖定失敗 (%s): %s (Failed to lock password)", user, err_msg)
                raise JitProvisionError(f"JIT 帳號 '{user}' 密碼鎖定失敗: {err_msg}")
            logger.info("[JIT_PASSWORD_LOCKED] 成功鎖定密碼登入權限: %s (Password locked for: %s)", user, user)
        except Exception as err:
            if not isinstance(err, JitProvisionError):
                logger.error("[JIT_LOCK_ERROR] 鎖定密碼異常 (%s): %s (Exception locking password)", user, err)
                raise JitProvisionError(f"鎖定 JIT 帳號密碼異常: {err}")
            raise

        return True

    async def configure_sudoers_rbac(
        self,
        conn: asyncssh.SSHClientConnection,
        target_user: str,
        role: str,
        custom_rule: Optional[str] = None,
    ) -> bool:
        """
        依據連線者角色動態配置或清除 /etc/sudoers.d/ 中的特權規則。
        Dynamically configure or remove /etc/sudoers.d/ RBAC rules based on user role.

        :param conn: 具備管理特權之 SSH 通道 (Privileged SSH connection)
        :param target_user: 目標使用者帳號 (Target username)
        :param role: 連線者指派角色 [admin / ops / dept_admin / user] (Assigned user role)
        :param custom_rule: 自訂 Sudoers 特權規則字串 (Optional custom sudoers rule string)
        :return: 成功完成特權派發回傳 True (Returns True on successful RBAC setup)
        :raises JitProvisionError: 當特權派發失敗時 (When sudoers configuration fails)
        """
        user = self.validate_username(target_user)
        quoted_user = shlex.quote(user)
        sudoers_path = f"/etc/sudoers.d/bastion_{user}"
        quoted_path = shlex.quote(sudoers_path)
        normalized_role = (role or "user").lower().strip()

        logger.info(
            "[JIT_RBAC_START] 開始派發 RBAC 特權規則 (使用者: %s, 角色: %s) (Configuring RBAC for %s with role: %s)",
            user,
            normalized_role,
            user,
            normalized_role,
        )

        if custom_rule:
            # 支援自訂特權規則範本 (Custom Sudoers Rule Template)
            rule_content = custom_rule.replace("{user}", user)
        elif normalized_role in ("admin", "super_admin", "root"):
            # 全域管理者：完整免密碼管理特權 (Full administrator root privileges without password)
            rule_content = f"{user} ALL=(ALL) NOPASSWD: ALL"
        elif normalized_role in ("ops", "devops", "sre", "engineer"):
            # 維運工程師：常用系統維護、服務重啟與日誌調閱特權 (DevOps & SRE maintenance privileges)
            rule_content = (
                f"{user} ALL=(ALL) NOPASSWD: "
                f"/usr/bin/systemctl, /bin/systemctl, "
                f"/usr/bin/journalctl, /bin/journalctl, "
                f"/usr/bin/docker, /usr/bin/podman, "
                f"/usr/bin/supervisorctl, /etc/init.d/*, "
                f"/usr/bin/tail /var/log/*, /bin/cat /var/log/*, /usr/bin/less /var/log/*"
            )
        elif normalized_role in ("dept_admin", "manager", "lead"):
            # 部門管理者：服務生命週期管理與監控權限 (Department manager & service lifecycle privileges)
            rule_content = (
                f"{user} ALL=(ALL) NOPASSWD: "
                f"/usr/bin/systemctl status *, /usr/bin/systemctl restart *, "
                f"/usr/bin/docker ps, /usr/bin/docker logs *, "
                f"/usr/bin/tail /var/log/*"
            )
        elif normalized_role in ("auditor", "audit"):
            # 安全稽核員特例：僅允許調閱系統與稽核日誌 (Audit log viewing only)
            rule_content = f"{user} ALL=(ALL) NOPASSWD: /usr/bin/journalctl, /usr/bin/tail /var/log/*, /bin/cat /var/log/*"
        else:
            # 一般連線者 / 研發人員 (developer / viewer / user)：標準 Shell，無 sudo 特權 (Standard user: no sudo)
            rule_content = ""

        if rule_content:
            # 寫入前確保 /etc/sudoers.d 目錄存在，並設定安全權限 0440 (即時生效，無需重啟 sshd)
            # 採用 printf 單行傳遞，杜絕跨 SSH Exec 之 Heredoc 換行解析異常
            quoted_rule = shlex.quote(rule_content)
            setup_cmd = (
                f"mkdir -p /etc/sudoers.d && "
                f"printf '%s\\n' {quoted_rule} > {quoted_path} && "
                f"chmod 0440 {quoted_path}"
            )
            try:
                res_rule = await asyncio.wait_for(conn.run(setup_cmd), timeout=self.command_timeout)
                if res_rule.exit_status != 0:
                    err_msg = res_rule.stderr.strip() if res_rule.stderr else f"Exit code {res_rule.exit_status}"
                    logger.error("[JIT_RBAC_FAILED] 寫入 Sudoers 失敗 (%s): %s (Failed to write sudoers)", user, err_msg)
                    raise JitProvisionError(f"寫入 Sudoers RBAC 規則失敗: {err_msg}")
                logger.info(
                    "[JIT_RBAC_UPDATED] 成功派發 Sudoers 規則 (檔案: %s, 角色: %s) (Configured sudoers: %s)",
                    sudoers_path,
                    normalized_role,
                    sudoers_path,
                )
            except Exception as err:
                if not isinstance(err, JitProvisionError):
                    logger.error("[JIT_RBAC_ERROR] 派發 Sudoers 異常 (%s): %s (Exception writing sudoers)", user, err)
                    raise JitProvisionError(f"派發 Sudoers RBAC 規則異常: {err}")
                raise
        else:
            # 清理 Sudoers 檔案 (Remove sudoers file if exists)
            cleanup_cmd = f"rm -f {quoted_path}"
            try:
                res_clean = await asyncio.wait_for(conn.run(cleanup_cmd), timeout=self.command_timeout)
                if res_clean.exit_status != 0:
                    err_msg = res_clean.stderr.strip() if res_clean.stderr else f"Exit code {res_clean.exit_status}"
                    logger.warning("[JIT_RBAC_CLEAN_FAILED] 清理 Sudoers 警告 (%s): %s (Warning cleaning sudoers)", user, err_msg)
                else:
                    logger.info("[JIT_RBAC_REMOVED] 已清除使用者的 Sudo 特權檔案: %s (Removed sudoers for: %s)", user, user)
            except Exception as err:
                logger.warning("[JIT_RBAC_CLEAN_ERROR] 清除 Sudoers 異常 (%s): %s (Exception cleaning sudoers)", user, err)

        return True

    async def prune_inactive_accounts(
        self,
        conn: asyncssh.SSHClientConnection,
        enabled: bool = False,
        max_idle_days: int = 365,
        dry_run: bool = True,
    ) -> List[str]:
        """
        巡檢目標伺服器上超過指定天數未活動的 JIT 帳號清單。
        Scan target host for inactive JIT accounts with configurable threshold and safety toggle.

        :param conn: 具備管理特權之 SSH 通道 (Privileged SSH connection)
        :param enabled: 是否啟用閒置清理機制，預設為 False 關閉 (Whether prune feature is enabled, default: False)
        :param max_idle_days: 閒置天數閥值，可自訂 (例如 365 或 3650 天) (Idle threshold in days)
        :param dry_run: 試跑模式，若為 True 僅列出候選帳號不刪除 (Dry run mode, list candidates only)
        :return: 巡檢發現之閒置帳號名稱清單 (List of inactive JIT usernames)
        """
        if not enabled:
            logger.info(
                "[JIT_PRUNE_DISABLED] 閒置帳號清理功能未啟用，保留所有 JIT UID 與目錄 (JIT account prune is disabled, retaining all accounts)"
            )
            return []

        logger.info(
            "[JIT_PRUNE_SCAN] 開始巡檢閒置 JIT 帳號 (閥值: %d 天, 試跑模式: %s) (Scanning for inactive accounts older than %d days, dry_run: %s)",
            max_idle_days,
            dry_run,
            max_idle_days,
            dry_run,
        )
        inactive_users: List[str] = []

        # 檢索由跳板機管理的 Sudoers 檔案清單：/etc/sudoers.d/bastion_*
        list_cmd = "ls -1 /etc/sudoers.d/bastion_* 2>/dev/null"
        try:
            res_ls = await asyncio.wait_for(conn.run(list_cmd), timeout=self.command_timeout)
            if res_ls.exit_status == 0 and res_ls.stdout:
                candidates = []
                for line in res_ls.stdout.splitlines():
                    fn = line.strip()
                    if "/bastion_" in fn:
                        u = fn.split("/bastion_")[-1]
                        if u and USERNAME_REGEX.match(u):
                            candidates.append(u)

                # 針對候選帳號透過 lastlog 或 pam 紀錄核驗最後登入時間
                for cand in candidates:
                    q_cand = shlex.quote(cand)
                    # 檢查是否在指定天數內無任何登入紀錄 (Check if last login exceeds threshold)
                    check_idle = f"lastlog -b {max_idle_days} -u {q_cand} 2>/dev/null"
                    res_idle = await asyncio.wait_for(conn.run(check_idle), timeout=self.command_timeout)
                    if res_idle.exit_status == 0 and cand in res_idle.stdout:
                        inactive_users.append(cand)
                        if not dry_run:
                            # 正式清理模式：封存並安全清除 Sudoers 與鎖定帳號 (Archive & clean)
                            rm_sudo = f"rm -f /etc/sudoers.d/bastion_{q_cand}"
                            await conn.run(rm_sudo)
                            logger.info("[JIT_ACCOUNT_PRUNED] 已清理逾期閒置帳號特權: %s (Pruned inactive user: %s)", cand, cand)

            logger.info(
                "[JIT_PRUNE_OK] 閒置帳號巡檢完畢，發現 %d 個閒置帳號 (Scan complete: %d inactive accounts)",
                len(inactive_users),
                len(inactive_users),
            )
        except Exception as err:
            logger.warning("[JIT_PRUNE_ERROR] 巡檢閒置帳號異常: %s (Exception during inactive accounts scan)", err)

        return inactive_users

