"""
OpenBastion 主程式啟動入口 (Application Entrypoint)
=================================================
啟動 OpenBastion 核心跳板機通訊服務、SQLite WAL 儲存驅動與 CLI 管理工具。
Main entrypoint to boot up OpenBastion gateway & storage services, with CLI management tools.
"""

import argparse
import asyncio
import getpass
import logging
import os
import secrets
import sys
import time
from typing import Optional

from core.gateway import GatewayListener
from core.i18n import t
from core.storage import StorageProvider

# 依據 SPEC.md §4.3 強制終端輸出為 UTF-8 編碼
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("openbastion.main")


def check_os_admin_privilege() -> bool:
    """
    檢查當前行程是否具備作業系統最高管理員權限。
    Check if the current process has operating system administrator or root privileges.
    """
    try:
        if os.name == "nt":
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def handle_reset_admin(storage: StorageProvider) -> int:
    """
    執行命令列管理員密碼安全重設 (方案 B + 現場雙人覆核 Co-Signing)。
    Execute CLI admin password reset with TTY dynamic challenge and two-person co-signing.
    """
    print("=" * 68)
    print("【OpenBastion 核心安全門禁】管理員密碼緊急重設 (Admin Password Reset)")
    print("=" * 68)

    # 1. 作業系統權限安全檢驗
    is_os_admin = check_os_admin_privilege()
    if is_os_admin:
        print("[OS_PRIV] 作業系統特權檢驗通過 (Administrator / root)。")
    else:
        print("[OS_PRIV] 警告: 未以系統管理員身分執行，啟動強化動態人機挑戰與雙人共管防線。")

    # 2. 檢驗真實終端 (TTY Check - 防背景惡意腳本偷跑)
    if not sys.stdin.isatty():
        print("[SECURITY_DENIED] 錯誤: 必須在真實互動式終端 (TTY) 下執行重設，拒絕背景執行！")
        return 1

    # 3. 人機動態挑戰碼 (Dynamic Challenge-Response)
    challenge_code = secrets.token_hex(3).upper()  # 6 位動態碼
    print(f"\n[CHALLENGE] 請輸入動態驗證碼 [{challenge_code}] 以核驗人機身分：")
    try:
        user_input = input("> ").strip().upper()
    except (EOFError, KeyboardInterrupt):
        print("\n[ABORTED] 操作已取消。")
        return 1

    if user_input != challenge_code:
        print("[SECURITY_DENIED] 動態挑戰碼核驗失敗，密碼重設終止！")
        return 1
    print("[CHALLENGE_OK] 動態人機挑戰核驗通過！")

    # 4. 現場雙人覆核判定 (Co-Signing Gate)
    active_supervisors = storage.list_active_managers_and_admins(exclude_username="admin")
    if not active_supervisors:
        print("\n[SINGLE_OPERATOR] 檢測到系統處於初生維運階段 (除 admin 外無其他主管)。")
        try:
            confirm = input("確定要重設系統管理員 (admin) 密碼嗎？[Y/n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n[ABORTED] 操作已取消。")
            return 1
        if confirm not in ("", "y", "yes"):
            print("[ABORTED] 操作已由使用者取消。")
            return 1
    else:
        print("\n[FOUR_EYES] 檢測到系統已配置分權主管，依法啟動「雙人共管原則 (Four-Eyes Principle)」！")
        print("具備授權背書資格之主管名冊:")
        for sup in active_supervisors:
            print(f"  * 帳號: {sup['username']} | 身分: {sup['role']} | 部門: {sup['department']}")

        print("\n請由現場任一主管出面輸入帳號密碼完成共同簽署授權:")
        try:
            co_signer = input("授權主管帳號: ").strip()
            co_password = getpass.getpass(t("cli.reset_admin_cosign_prompt", default="授權主管密碼: "))
        except (EOFError, KeyboardInterrupt):
            print("\n[ABORTED] 操作已取消。")
            return 1

        ok, sup_user = storage.authenticate(co_signer, co_password)
        if not ok or not sup_user or sup_user.get("role") not in ("admin", "manager"):
            print("[SECURITY_DENIED] 雙人背書核驗失敗: 帳號密碼錯誤或非授權主管，重設終止！")
            return 1

        print(f"[AUTH_OK] 主管 '{co_signer}' 現場雙人背書簽署成功！")

    # 5. 生成高強度隨機新密碼並存入資料庫
    new_password = secrets.token_urlsafe(12)
    success = storage.reset_admin_password(new_password)
    if success:
        print("\n" + "=" * 68)
        print("[SUCCESS] 系統管理員密碼重設成功！")
        print(f"  管理員帳號 (Username): admin")
        print(f"  全新密碼   (Password): {new_password}")
        print("-" * 68)
        print("注意: 此密碼僅於本機終端顯示一次，請立即登入並妥善保存！")
        print("=" * 68 + "\n")
        return 0
    else:
        print("[ERROR] 資料庫寫入失敗，密碼重設未完成！")
        return 1


def handle_add_host(storage: StorageProvider, args: argparse.Namespace) -> int:
    """
    命令列真實目標主機登錄精靈 (Interactive Real Host Enrollment Wizard)。
    引導架構者快速登記真實主機資產與加密連線憑證。
    """
    from core.vault import CredentialVault

    vault = CredentialVault()

    print("=" * 68)
    print("【OpenBastion 核心資產登錄】目標主機註冊精靈 (Add Target Host)")
    print("=" * 68)

    # 門禁 1: 管理者身分強鑑權 (Fail-Closed)
    admin_user = getattr(args, "admin_user", None) or "admin"
    admin_pwd = getattr(args, "admin_password", None)
    if not admin_pwd:
        admin_pwd = getpass.getpass(t("cli.admin_pwd_prompt", default=f"請輸入管理者 [{admin_user}] 密碼以驗證權限: ", user=admin_user)).strip()

    ok, user_rec = storage.authenticate(admin_user, admin_pwd)
    if not ok or not user_rec or user_rec.get("role") != "admin":
        print("[SECURITY_ALERT] 管理者鑑權失敗或權限不足！操作遭到拒絕 (Authentication failed, access denied)")
        return 1

    name = getattr(args, "name", None) or input("1. 請輸入主機識別名稱 (例如 Web-Node-01): ").strip()
    if not name:
        print("[ERROR] 主機名稱不可為空！")
        return 1

    raw_host = getattr(args, "target_host", None) or input("2. 請輸入目標主機 IP 或網域名稱 (例如 192.168.1.50): ").strip()
    host = raw_host.strip("<> \t\r\n") if raw_host else ""
    if not host:
        print("[ERROR] 主機 IP 不可為空！")
        return 1

    port_str = getattr(args, "target_port", None) or input("3. 請輸入 SSH 連線埠號 [預設 22]: ").strip()
    port = int(port_str) if port_str else 22

    # 門禁 2: 端點防重複檢驗 (Duplicate Endpoint Check)
    existing_host = storage.get_host_by_endpoint(host, port)
    if existing_host:
        print(f"[ERROR] 該連線端點 ({host}:{port}) 已由主機 [{existing_host['name']}] (ID: {existing_host['host_id']}) 註冊！禁止重複登錄。")
        return 1

    target_user = getattr(args, "user", None) or input("4. 請輸入登入目標主機之帳號 [預設 root]: ").strip() or "root"

    provision_mode = getattr(args, "provision_mode", None)
    if not provision_mode:
        mode_choice = input("5. 治理模式: [1] Level 1: 協定代理 (Direct 密碼/私鑰代管)  [2] Level 2: 憑證免密 (CA 短期憑證 300s)  [3] Level 3: JIT 帳號動態治理 (JIT 獨立 UID + Sudoers) [預設 3]: ").strip()
        if mode_choice == "1":
            provision_mode = "direct"
        elif mode_choice == "2":
            provision_mode = "ca"
        else:
            provision_mode = "jit"

    encrypted_cred = ""
    if provision_mode == "jit":
        auth_type = "cert"
        # JIT 模式預設採用連線者動態帳號
        if target_user == "root":
            target_user = "{username}"
        print("   [模式說明] 已選擇 Level 3 JIT 帳號動態治理模式 (JIT Dynamic Provisioning & RBAC)。")
        print("              受控端零 Agent，連線時動態維護獨立 POSIX 帳號、鎖定密碼並即時配置 Sudoers。")
    elif provision_mode == "ca":
        auth_type = "cert"
        print("   [模式說明] 已選擇 Level 2 憑證免密模式 (CA-Based Agentless)。")
        print("              受控端免存任何固定密碼或私鑰，連線時由 CA 自動簽發 300 秒極短期憑證。")
    else:
        auth_type = getattr(args, "auth", None) or ""
        if auth_type not in ("password", "key"):
            choice = input("   認證類型: [1] 密碼 (Password)  [2] 私鑰 (SSH Key) [預設 1]: ").strip()
            auth_type = "key" if choice == "2" else "password"

        secret_raw = getattr(args, "secret", None)
        if not secret_raw:
            if auth_type == "password":
                secret_raw = getpass.getpass(t("cli.add_host_password", default="6. 請輸入遠端登入密碼 (Password, 輸入不顯示): ")).strip()
            else:
                key_input = input("   請輸入私鑰路徑 (例如 id_rsa) 或直接貼上私鑰內容: ").strip()
                if os.path.isfile(key_input):
                    with open(key_input, "r", encoding="utf-8") as f:
                        secret_raw = f.read().strip()
                else:
                    secret_raw = key_input

        if not secret_raw:
            print("[ERROR] 認證憑證不可為空！")
            return 1

        # 使用硬體綁定金鑰加密連線憑證
        encrypted_cred = vault.encrypt(secret_raw)

    step_os = "6" if provision_mode in ("ca", "jit") else "8"
    step_dept = "7" if provision_mode in ("ca", "jit") else "9"
    system_desc = (getattr(args, "target_os", None) or input(f"{step_os}. 請輸入作業系統類型 (例如 Ubuntu 22.04 / CentOS 7) [預設留空]: ").strip()) if getattr(args, "target_os", None) is None else getattr(args, "target_os", "")
    dept = (getattr(args, "dept", None) or input(f"{step_dept}. 請輸入所屬維運組/部門 [預設留空]: ").strip()) if getattr(args, "dept", None) is None else getattr(args, "dept", "")

    host_info = storage.add_host(
        name=name,
        host=host,
        port=port,
        system=system_desc or "",
        alias="",
        dept=dept or "",
        status="offline",
        provision_mode=provision_mode,
        default_user=target_user,
        auth_type=auth_type,
        credential_encrypted=encrypted_cred,
        created_by=admin_user,
    )

    print("\n" + "-" * 68)
    if provision_mode == "jit":
        print("✅ 目標主機註冊成功！(Level 3 JIT 帳號動態治理模式)")
        print(f"   * 主機代碼: {host_info['host_id']}")
        print(f"   * 連線端點: {host}:{port} (帳號: {target_user}, 模式: JIT 獨立動態帳號 + CA 短期憑證)")
        print("   * 安全機制: 零 Agent、密碼強制鎖定 (Fail-Closed)、/etc/sudoers.d/ 動態派發")
        print("   * 部署提醒: 請確保目標主機已將 OpenBastion CA 公鑰加入 /etc/ssh/trusted_user_ca_keys")
        print("              (可執行 `python main.py --export-ca` 檢視完整部署指令)")
    elif provision_mode == "ca":
        print("✅ 目標主機註冊成功！(Level 2 憑證免密模式)")
        print(f"   * 主機代碼: {host_info['host_id']}")
        print(f"   * 連線端點: {host}:{port} (帳號: {target_user}, 模式: OpenSSH CA 短期憑證)")
        print("   * 憑證安全: 受控端免存任何固定密碼或私鑰 (Zero Stored Credentials)")
        print("   * 部署提醒: 請確保目標主機已將 OpenBastion CA 公鑰加入 /etc/ssh/trusted_user_ca_keys")
        print("              (可執行 `python main.py --export-ca` 檢視完整部署指令)")
    else:
        print("✅ 目標主機註冊成功！(Level 1 協定代理模式)")
        print(f"   * 主機代碼: {host_info['host_id']}")
        print(f"   * 連線端點: {host}:{port} (帳號: {target_user}, 認證: {auth_type})")
        print("   * 憑證保管: 已由 CredentialVault 加密保存 (AES-256-GCM，本機指紋衍生金鑰)")
    print("-" * 68)
    print("現在您可以直接執行 `python main.py`，連入 OpenBastion 選單測試畫面！\n")
    return 0


def handle_setup_mfa(storage: StorageProvider, args: argparse.Namespace) -> int:
    """
    命令列為指定使用者設定並啟用 MFA 雙因子驗證 (產生 Base32 金鑰、備援碼與 QR 碼)。
    Configure and enable MFA for specified user with Base32 secret, scratch codes, and QR Code.
    強制執行管理者身分強鑑權門禁與操作審計留痕 (Fail-Closed)。
    """
    from core.auth import TotpMfaProvider

    username = args.setup_mfa
    print("=" * 68)
    print(t("cli.mfa_setup_title", default=f"【OpenBastion 身分安全門禁】MFA 雙因子驗證設定 (Setup MFA: {username})", username=username))
    print("=" * 68)

    # 門禁 1: 管理者身分強鑑權 (Fail-Closed)
    admin_user = getattr(args, "admin_user", None) or "admin"
    admin_pwd = getattr(args, "admin_password", None)
    if not admin_pwd:
        try:
            admin_pwd = getpass.getpass(t("cli.admin_pwd_prompt", default=f"請輸入管理者 [{admin_user}] 密碼以驗證權限: ", user=admin_user)).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[ABORTED] 操作已取消。")
            return 1

    ok, admin_rec = storage.authenticate(admin_user, admin_pwd)
    if not ok or not admin_rec or admin_rec.get("role") != "admin":
        print(t("cli.auth_denied", default="[SECURITY_ALERT] 管理者鑑權失敗或權限不足！操作遭到拒絕 (Authentication failed, access denied)"))
        return 1

    user = storage.get_user_by_username(username)
    if not user:
        print(t("cli.mfa_user_not_found", default=f"[ERROR] 查無使用者 '{username}'！請先確認帳號名稱是否正確。", username=username))
        return 1

    # 1. 生成 160-bit 隨機金鑰與 8 組 8 碼一次性備援碼
    secret = TotpMfaProvider.generate_secret()
    codes = TotpMfaProvider.generate_scratch_codes(count=8, code_len=8)
    uri = TotpMfaProvider.generate_provisioning_uri(secret, username, issuer="OpenBastion")

    # 2. 持久化至 SQLite
    ok = storage.enable_user_mfa(user["user_id"], secret, codes)
    if not ok:
        print(t("cli.mfa_db_error", default="[ERROR] 資料庫更新失敗，操作未完成！"))
        return 1

    # 3. 寫入維運審計日誌 (CLI Audit Logging)
    try:
        storage.log_audit_event(
            session_id="cli_local",
            user_id=admin_rec["user_id"],
            username=admin_user,
            host_id="bastion",
            host_ip="127.0.0.1",
            host_name="OpenBastion-Gateway",
            event_type="CLI_MFA_ENABLED",
            command_raw=f"main.py --setup-mfa {username}",
            command_clean=f"Admin '{admin_user}' enabled MFA for target user '{username}' (ID: {user['user_id']})",
            action_taken="LOG",
        )
    except Exception as audit_err:
        logger.warning("[AUDIT_WARN] 寫入 MFA 啟用審計失敗: %s", audit_err)

    print(t("cli.mfa_setup_success", default=f"✅ 使用者 '{username}' (ID: {user['user_id']}) 已成功啟用 MFA 雙因子驗證！\n", username=username, user_id=user["user_id"]))

    # 4. 嘗試以純終端字元渲染 QR Code
    qr_rendered = False
    try:
        import io
        import qrcode

        qr = qrcode.QRCode(border=1)
        qr.add_data(uri)
        qr.make(fit=True)
        print(t("cli.mfa_scan_qr", default="📱 請使用 Google Authenticator / 1Password 掃描下方 QR Code 綁定：\n"))
        f = io.StringIO()
        qr.print_ascii(out=f, invert=True)
        print(f.getvalue())
        qr_rendered = True
    except Exception:
        qr_rendered = False

    if not qr_rendered:
        print(t("cli.mfa_guide_header", default="📱 手機 Authenticator 綁定指引 (Authenticator Binding Guide):"))
        print(t("cli.mfa_guide_secret", default=f"   * 手動輸入金鑰 (Base32 Secret): \033[1;36m{secret}\033[0m", secret=secret))
        print(t("cli.mfa_guide_uri", default=f"   * 標準 URI (可直接貼入或自行轉碼): \033[33m{uri}\033[0m", uri=uri))
        print(t("cli.mfa_guide_qr_hint", default="   * 終端圖形提醒: 執行 `pip install qrcode` 後可直接於終端機顯示 ASCII QR Code。\n"))

    # 5. 顯示 8 組備援碼 (排成 2 欄 4 列垂直齊頭對齊)
    print("-" * 68)
    print(t("cli.mfa_recovery_title", default="🚨 一次性備援碼 (Recovery Codes):"))
    print(t("cli.mfa_recovery_desc1", default="   說明: 手機遺失、沒電或無法讀取動態碼時，可輸入以下備援碼登入。"))
    print(t("cli.mfa_recovery_desc2", default="         每組備援碼僅限使用一次，使用後即刻失效。\n"))
    for i in range(0, len(codes), 2):
        c1 = codes[i]
        c2 = codes[i + 1] if i + 1 < len(codes) else ""
        print(f"     [{i + 1}] {c1:<16}  [{i + 2}] {c2:<16}")
    print("-" * 68)
    print(t("cli.mfa_save_hint", default="請妥善保存上述密鑰與備援碼。\n"))
    return 0


def handle_disable_mfa(storage: StorageProvider, args: argparse.Namespace) -> int:
    """
    命令列停用指定使用者之 MFA 雙因子驗證。
    Disable MFA for specified user and revert to single-factor password authentication.
    強制執行管理者身分強鑑權門禁與操作審計留痕 (Fail-Closed)。
    """
    username = args.disable_mfa
    print("=" * 68)
    print(t("cli.mfa_disable_title", default=f"【OpenBastion 身分安全門禁】MFA 雙因子驗證停用 (Disable MFA: {username})", username=username))
    print("=" * 68)

    # 門禁 1: 管理者身分強鑑權 (Fail-Closed)
    admin_user = getattr(args, "admin_user", None) or "admin"
    admin_pwd = getattr(args, "admin_password", None)
    if not admin_pwd:
        try:
            admin_pwd = getpass.getpass(t("cli.admin_pwd_prompt", default=f"請輸入管理者 [{admin_user}] 密碼以驗證權限: ", user=admin_user)).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[ABORTED] 操作已取消。")
            return 1

    ok, admin_rec = storage.authenticate(admin_user, admin_pwd)
    if not ok or not admin_rec or admin_rec.get("role") != "admin":
        print(t("cli.auth_denied", default="[SECURITY_ALERT] 管理者鑑權失敗或權限不足！操作遭到拒絕 (Authentication failed, access denied)"))
        return 1

    user = storage.get_user_by_username(username)
    if not user:
        print(t("cli.mfa_user_not_found", default=f"[ERROR] 查無使用者 '{username}'！請確認帳號名稱是否正確。", username=username))
        return 1

    if not user.get("mfa_enabled"):
        print(t("cli.mfa_already_disabled", default=f"[NOTICE] 使用者 '{username}' 本就未啟用 MFA 雙因子驗證。", username=username))
        return 0

    ok = storage.disable_user_mfa(user["user_id"])
    if ok:
        # 寫入維運審計日誌 (CLI Audit Logging)
        try:
            storage.log_audit_event(
                session_id="cli_local",
                user_id=admin_rec["user_id"],
                username=admin_user,
                host_id="bastion",
                host_ip="127.0.0.1",
                host_name="OpenBastion-Gateway",
                event_type="CLI_MFA_DISABLED",
                command_raw=f"main.py --disable-mfa {username}",
                command_clean=f"Admin '{admin_user}' disabled MFA for target user '{username}' (ID: {user['user_id']})",
                action_taken="LOG",
            )
        except Exception as audit_err:
            logger.warning("[AUDIT_WARN] 寫入 MFA 停用審計失敗: %s", audit_err)

        print(t("cli.mfa_disable_success", default=f"✅ 使用者 '{username}' (ID: {user['user_id']}) 已成功停用 MFA，恢復為純密碼登入模式。\n", username=username, user_id=user["user_id"]))
        return 0
    else:
        print(t("cli.mfa_db_error", default="[ERROR] 資料庫更新失敗，操作未完成！"))
        return 1


async def main() -> None:
    """
    主非同步通訊回環。
    Main asynchronous application loop running gateway and storage listeners.
    """
    # 0. 剖析命令列參數
    parser = argparse.ArgumentParser(
        description="OpenBastion SSH-2.0 跳板機核心通訊與管理服務 (OpenBastion SSH-2.0 Gateway Core Service)"
    )
    parser.add_argument(
        "--reset-admin",
        action="store_true",
        help="啟動管理員密碼緊急安全重設流程 (方案 B + 現場雙人覆核) / Emergency admin password reset with co-signing",
    )
    parser.add_argument(
        "--add-host",
        action="store_true",
        help="啟動真實目標主機互動式註冊精靈 / Interactive target host enrollment wizard",
    )
    parser.add_argument(
        "--setup-mfa",
        type=str,
        metavar="USERNAME",
        help="為指定使用者配置並啟用 MFA 雙因子驗證 / Configure and enable MFA for user (secret, codes, QR)",
    )
    parser.add_argument(
        "--disable-mfa",
        type=str,
        metavar="USERNAME",
        help="停用指定使用者之 MFA 雙因子驗證 / Disable MFA for user and revert to password only",
    )
    parser.add_argument(
        "--name",
        type=str,
        help="主機識別名稱 (例如 Web-01) / Host identification name (e.g. Web-01)",
    )
    parser.add_argument(
        "--target-host",
        type=str,
        help="目標主機 IP 或域名 / Target host IP address or domain name",
    )
    parser.add_argument(
        "--target-port",
        type=str,
        help="目標 SSH 埠號 (預設 22) / Target SSH port (default: 22)",
    )
    parser.add_argument(
        "--user",
        type=str,
        help="目標登入帳號 (預設 root) / Target login username (default: root)",
    )
    parser.add_argument(
        "--provision-mode",
        type=str,
        choices=["direct", "ca", "jit"],
        help="治理模式 (direct: 代理, ca: 憑證免密, jit: JIT 動態帳號) / Provisioning mode",
    )
    parser.add_argument(
        "--admin-user",
        type=str,
        default="admin",
        help="登錄主機之管理者帳號 (預設 admin) / Administrator account for enrollment (default: admin)",
    )
    parser.add_argument(
        "--admin-password",
        type=str,
        help="管理者登入密碼 / Administrator password",
    )
    parser.add_argument(
        "--auth",
        type=str,
        choices=["password", "key"],
        help="目標主機認證方式 / Target authentication method (password or key)",
    )
    parser.add_argument(
        "--secret",
        type=str,
        help="目標主機認證密碼或私鑰內容 / Target password or private key content",
    )
    parser.add_argument(
        "--target-os",
        type=str,
        help="目標主機作業系統類型 / Target operating system type",
    )
    parser.add_argument(
        "--dept",
        type=str,
        help="所屬維運組或部門 / Department or maintenance group",
    )
    parser.add_argument(
        "--export-ca",
        action="store_true",
        help="匯出 OpenSSH CA 根公鑰與目標主機配置指引 / Export OpenSSH CA public keys and setup guide",
    )
    args = parser.parse_args()

    # 1. 初始化 SQLite WAL 儲存驅動
    storage = StorageProvider()

    # 若帶有 --export-ca 參數，輸出 CA 根公鑰與部署指引後退出
    if args.export_ca:
        from core.ca import CertificateAuthorityManager
        from core.vault import CredentialVault

        vault = CredentialVault()
        ca_mgr = CertificateAuthorityManager(storage=storage, vault=vault)
        ca_keys = ca_mgr.get_ca_public_keys()
        enroll_cmd = ca_mgr.get_enroll_command()

        print("=" * 72)
        print(t("cli.export_ca_header", default="【OpenBastion】雙軌 OpenSSH CA 根公鑰與自適應部署指引 (Dual-CA Setup)"))
        print("=" * 72)
        print("\n" + t("cli.export_ca_pub_keys", default="1. 雙軌 OpenSSH CA 根公鑰 (Dual CA Public Keys):"))
        print(t("cli.export_ca_track1", default="   [軌道 1: 現代主機 (Ed25519 - 128-bit 強度)]:"))
        print(f"   {ca_keys['ed25519']}")
        print("\n" + t("cli.export_ca_track2", default="   [軌道 2: 遺留相容 (RSA-4096 高強度金鑰)]:"))
        print(f"   {ca_keys['rsa']}")
        print("\n" + t("cli.export_ca_cmd_title", default="2. 目標主機一鍵自適應部署指令 (All-in-One Adaptive Shell Command):"))
        print(t("cli.export_ca_cmd_desc", default="   * 說明：在受控端目標主機（相容 CentOS 6 至現代 Linux）貼上下方單行指令，\n          腳本將透過 `ssh -V` 自動識別版本，並完成公鑰寫入、sshd_config 配置與平滑重載：\n"))
        print(f"   {enroll_cmd}\n")
        print("=" * 72)
        print(t("cli.export_ca_complete", default="完成後，受控端主機即可接受 OpenBastion 簽發之短期憑證連線。\n"))
        sys.exit(0)

    # 若帶有 --setup-mfa 參數，執行 MFA 設定後退出
    if args.setup_mfa:
        exit_code = handle_setup_mfa(storage, args)
        sys.exit(exit_code)

    # 若帶有 --disable-mfa 參數，執行 MFA 停用後退出
    if args.disable_mfa:
        exit_code = handle_disable_mfa(storage, args)
        sys.exit(exit_code)

    # 若帶有 --reset-admin 參數，執行重設流程後退出
    if args.reset_admin:
        exit_code = handle_reset_admin(storage)
        sys.exit(exit_code)

    # 若帶有 --add-host 參數，啟動註冊精靈後退出
    if args.add_host:
        exit_code = handle_add_host(storage, args)
        sys.exit(exit_code)

    logger.info("[BOOT_OK] SQLite WAL 儲存驅動已就緒: %s (SQLite WAL storage driver initialized)", storage.db_path)

    # 2. 開機孤兒會話對帳修復 (Boot Reconciliation)
    reconciled_count = storage.reconcile_orphan_sessions()
    if reconciled_count > 0:
        logger.info("[RECONCILE_DONE] 開機對帳修復完成，已將 %d 筆異常中斷連線標記為 ABRUPT (Boot reconciliation completed)", reconciled_count)

    # 3. 首次開機安全引導 (Bootstrap Admin - 隨機密碼防預設寫死)
    bootstrap_info = storage.bootstrap_admin_if_empty()
    if bootstrap_info:
        logger.warning(
            "[BOOTSTRAP_ADMIN] 系統初次啟動，已生成初始管理員: 帳號=%s 密碼=%s (Initial admin created, please save securely!)",
            bootstrap_info["username"],
            bootstrap_info["password"],
        )

    # 4. 啟動 SSH-2.0 閘道監聽器 (無實體磁碟金鑰，記憶體直載)
    gateway = GatewayListener(host="0.0.0.0", port=2222, storage=storage)
    await gateway.start()

    logger.info("[CHANNEL_READY] OpenBastion 核心通訊通道已就緒 (Port %s) (Core communication channel ready)", 2222)
    logger.info("[CLIENT_HINT] 可於本機執行連線: ssh -p %s <帳號>@127.0.0.1 (Connect for verification)", 2222)
    logger.info("[SYSTEM_HINT] 按下 Ctrl+C 可停止服務 (Press Ctrl+C to stop services)")

    try:
        # 維持服務常駐運作
        while True:
            await asyncio.sleep(3600)
    except (asyncio.CancelledError, KeyboardInterrupt):
        logger.info("[SHUTDOWN_SIGNAL] 接收到終止訊號，正在關閉服務（等待 30 秒倒數，再次按下 Ctrl + C 可立即強制結束）(Termination signal received, shutting down...)")
        try:
            await gateway.stop(timeout=30.0, force=False)
        except (KeyboardInterrupt, asyncio.CancelledError):
            logger.warning("[FORCE_SHUTDOWN] 再次接收到 Ctrl + C，立即強制結束服務 (Second Ctrl + C received, forcing immediate exit)")
            await gateway.stop(timeout=0.0, force=True)
    except Exception as exc:
        logger.error("[UNEXPECTED_ERROR] 服務異常中斷: %s (Service interrupted unexpectedly: %s)", exc, exc)
        await gateway.stop(timeout=0.0, force=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
