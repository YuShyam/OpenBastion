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
    執行命令列管理員密碼安全重設 (方案 B + 智慧現場雙人背書 Smart Co-Signing)。
    Execute CLI admin password reset with TTY dynamic challenge and Smart Co-Signing.
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

    # 4. 智慧動態雙人背書判定 (Smart Co-Signing Gate)
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
            co_password = getpass.getpass("授權主管密碼: ")
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


async def main() -> None:
    """
    主非同步通訊回環。
    Main asynchronous application loop running gateway and storage listeners.
    """
    # 0. 剖析命令列參數
    parser = argparse.ArgumentParser(description="OpenBastion SSH-2.0 Gateway Core Service")
    parser.add_argument(
        "--reset-admin",
        action="store_true",
        help="啟動管理員密碼緊急安全重設流程 (方案 B + 智慧雙人背書)",
    )
    args = parser.parse_args()

    # 1. 初始化 SQLite WAL 儲存驅動
    storage = StorageProvider()

    # 若帶有 --reset-admin 參數，執行重設流程後退出
    if args.reset_admin:
        exit_code = handle_reset_admin(storage)
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
        logger.info("[SHUTDOWN_SIGNAL] 接收到終止信號，正在安全關閉服務... (Termination signal received, shutting down...)")
    finally:
        await gateway.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
