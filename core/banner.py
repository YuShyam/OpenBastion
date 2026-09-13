"""
OpenBastion 核心 - 動態連線 HUD Banner 插件引擎 (Dynamic Connection Banner Engine)
==========================================================================
依據 docs/SPEC.md §2.3 與 ADR-001 架構規範原生實作。
提供連線前夕 78 欄位動態審計卡片輸出、定寬標題槽垂直齊頭對齊、全量 HUD 欄位還原、
i18n 多語系替換、ANSI 逃逸消毒與 200ms 非同步熔斷保護。

核心設計：
  1. 插件化介面 (IBannerProvider)：允許抽換自訂實作，預設提供標準動態範本。
  2. 78 欄位安全線保證：以 East Asian Width 計算中英字元寬度，超長安全截斷，不破版折行。
  3. 定寬標題槽 (Fixed-Width Slot)：消除複合 Emoji (如 🖥️、🛡️) 造成的寬度差，冒號嚴格垂直對齊。
  4. 終端輸入安全消毒：所有注入文字強制通過 AnsiSanitizer 過濾，防範終端逃逸注入攻擊。
  5. 200ms 硬性超時熔斷：外部資料採集逾時自動降級顯示基礎靜態連線資訊，避免連線受到阻塞。
  6. 嚴格 CRLF 相容性：所有行尾輸出保證 \\r\\n，杜絕 PuTTY 等終端之階梯狀排版錯位。
"""

import asyncio
import logging
import re
import unicodedata
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.i18n import t
from core.menu import AnsiSanitizer

logger = logging.getLogger("openbastion.banner")

BANNER_MAX_WIDTH = 78
BANNER_PREFIX = "│  "
BANNER_PREFIX_WIDTH = 3  # "│" (1) + "  " (2) = 3


def get_terminal_char_width(ch: str) -> int:
    """
    計算單一字元在終端環境之視覺欄位寬度。
    Calculate visual column width of a single character in terminal environments.
    """
    code = ord(ch)
    # 變體選擇器與零寬字元寬度計為 0
    if 0xFE00 <= code <= 0xFE0F or code == 0x200D:
        return 0
    # 常見終端顯示為 2 欄位寬度之 Emoji
    if code in (
        0x1F5A5,  # 🖥
        0x1F6E1,  # 🛡
        0x23F3,   # ⏳
        0x1F4BB,  # 💻
        0x1F510,  # 🔐
        0x1F552,  # 🕒
        0x1F464,  # 👤
        0x1F4CA,  # 📊
        0x1F3AB,  # 🎫
        0x1F310,  # 🌐
        0x1F4A1,  # 💡
        0x1F534,  # 🔴
    ):
        return 2
    ea = unicodedata.east_asian_width(ch)
    return 2 if ea in ("F", "W") else 1


def get_terminal_display_width(text: str) -> int:
    """
    精準計算終端字串（包含過濾 ANSI 轉義碼）之視覺顯示寬度。
    Accurately calculate terminal display column width filtering out ANSI escape codes.
    """
    clean = re.sub(r"\x1b\[[0-9;]*m", "", text)
    return sum(get_terminal_char_width(c) for c in clean)


@dataclass
class BannerContext:
    """
    動態連線 Banner 渲染上下文資料載體。
    Context data object containing target host metadata, user privileges, metrics, and ticket info.
    """

    hostname: str
    ip: str
    port: int = 22
    system: str = ""
    dept: str = ""
    service_desc: Optional[str] = None
    status: str = "online"
    cpu_load: Optional[str] = None
    mem_usage: Optional[str] = None
    disk_usage: Optional[str] = None
    uptime: Optional[str] = None
    uptime_seconds: Optional[int] = None
    listen_ports: Optional[str] = None
    operator_username: str = ""
    operator_name: Optional[str] = None
    operator_dept: Optional[str] = None
    target_user: str = ""
    account_expires_at: Optional[str] = None
    account_remaining_days: Optional[int] = None
    account_remaining_hours: Optional[int] = None
    provision_mode: str = "direct"
    sudo_perms: Optional[str] = None
    ticket_no: Optional[str] = None
    ticket_remaining_min: Optional[int] = None
    ticket_reason: Optional[str] = None
    recent_login: Optional[str] = None
    recent_logins: Optional[List[str]] = None
    session_id: str = ""
    locale: str = "zh_TW"
    username: Optional[str] = None
    audit_anomaly: bool = False
    custom_fields: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.username:
            if not self.operator_username:
                self.operator_username = self.username
            if not self.target_user:
                self.target_user = self.username


class IBannerProvider(ABC):
    """
    動態 Banner 插件抽象介面。
    Abstract base interface for customizable connection banner providers.
    """

    @abstractmethod
    async def build_banner(self, context: BannerContext) -> str:
        """
        組裝並回傳格式化後的終端 Banner 字串。
        Build and return formatted terminal banner string.
        """
        pass


class DefaultTemplateBannerProvider(IBannerProvider):
    """
    OpenBastion 原生預設範本 Banner 實作。
    Adheres to 78-column safety line, fixed-width title slots, and i18n localization.
    """

    async def build_banner(self, context: BannerContext) -> str:
        """
        非同步渲染動態 Banner，各項動態資料安全消毒並格式化為 78 欄位卡片。
        Asynchronously render dynamic banner formatted as a 78-column HUD card.
        """
        loc = context.locale
        lines: List[str] = []

        # 頂部邊框
        top_border = "╭" + "─" * (BANNER_MAX_WIDTH - 2)
        lines.append(f"\033[1;34m{top_border}\033[0m")

        # 1. 目標主機列
        clean_name = AnsiSanitizer.sanitize(context.hostname)
        clean_ip = AnsiSanitizer.sanitize(context.ip)
        clean_dept = AnsiSanitizer.sanitize(context.dept)
        target_info = clean_name
        if context.service_desc and context.service_desc != context.hostname:
            clean_svc = AnsiSanitizer.sanitize(context.service_desc)
            target_info += f" [{clean_svc}]"
        target_info += f" ({clean_ip}:{context.port} | {clean_dept})"
        lines.append(self._render_hud_item("💻", t("banner.target_host", locale=loc), f"\033[1;33m{target_info}\033[0m", loc))

        # 2. 系統環境列 (支援秒數計算與中英雙軌時長防穿幫)
        clean_sys = AnsiSanitizer.sanitize(context.system)
        sys_details = [clean_sys]
        up_display: Optional[str] = None
        if context.uptime_seconds is not None and context.uptime_seconds > 0:
            up_sec = context.uptime_seconds
            days = up_sec // 86400
            hours = (up_sec % 86400) // 3600
            mins = (up_sec % 3600) // 60
            if "zh" in loc.lower():
                if days > 0:
                    up_display = f"{days} 天 {hours} 小時 {mins} 分"
                elif hours > 0:
                    up_display = f"{hours} 小時 {mins} 分"
                else:
                    up_display = f"{mins} 分"
            else:
                if days > 0:
                    up_display = f"{days}d {hours}h {mins}m"
                elif hours > 0:
                    up_display = f"{hours}h {mins}m"
                else:
                    up_display = f"{mins}m"
        elif context.uptime:
            raw_up = AnsiSanitizer.sanitize(context.uptime)
            if "zh" not in loc.lower():
                up_conv = raw_up
                up_conv = re.sub(r"(\d+)\s*天\s*", r"\1d ", up_conv)
                up_conv = re.sub(r"(\d+)\s*小時\s*", r"\1h ", up_conv)
                up_conv = re.sub(r"(\d+)\s*(?:分鐘|分)\s*", r"\1m", up_conv)
                up_display = re.sub(r"\s+", " ", up_conv).strip()
            else:
                up_display = raw_up

        if up_display:
            sys_details.append(t("banner.uptime", locale=loc, uptime=up_display))
        lines.append(self._render_hud_item("🖥️", t("banner.system_env", locale=loc), " | ".join(sys_details), loc))

        # 3. 主機狀態列 (含監控採集指標，無採集指標時整行隱藏，絕不輸出「在線」贅字)
        status_items = []
        if context.cpu_load:
            status_items.append(t("banner.cpu_load", locale=loc, load=AnsiSanitizer.sanitize(context.cpu_load)))
        if context.mem_usage:
            status_items.append(t("banner.mem_usage", locale=loc, mem=AnsiSanitizer.sanitize(context.mem_usage)))
        if context.disk_usage:
            status_items.append(t("banner.disk_usage", locale=loc, disk=AnsiSanitizer.sanitize(context.disk_usage)))
        if status_items:
            lines.append(self._render_hud_item("📊", t("banner.host_status", locale=loc), " | ".join(status_items), loc))

        # 4. 系統監聽列 (若有)
        if context.listen_ports:
            clean_ports = AnsiSanitizer.sanitize(context.listen_ports)
            lines.append(self._render_hud_item("🌐", t("banner.system_listen", locale=loc), t("banner.listen_ports", locale=loc, ports=clean_ports), loc))

        # 5. 登入身分列 (雙向身分映射：當 target_user != operator 時展開顯示真實帳號與操作人員)
        op_user = AnsiSanitizer.sanitize(context.operator_username or context.target_user)
        user_display = op_user
        if context.operator_name:
            clean_op_name = AnsiSanitizer.sanitize(context.operator_name)
            if clean_op_name in ("系統初始管理員", "系統管理員", "Initial Administrator", "Administrator", "Admin"):
                clean_op_name = t("banner.admin_display", locale=loc, default="Admin")
            if "en" in loc.lower() and op_user.lower() == "admin" and clean_op_name.lower() in ("admin", "administrator"):
                user_display = op_user
            else:
                user_display = f"{op_user} ({clean_op_name})"

        user_dept_str = AnsiSanitizer.sanitize(context.operator_dept or context.dept or "-")
        dept_lbl = t("banner.dept_label_short", locale=loc, default="部門")
        dept_colon = "：" if "zh" in loc.lower() else ": "
        dept_part = f"{dept_lbl}{dept_colon}{user_dept_str}"

        clean_target = AnsiSanitizer.sanitize(context.target_user) if context.target_user else op_user
        # 標註治理身分小徽章 (僅 JIT 模式標註 [JIT 臨時帳號]，CA 與 Direct 模式保持純淨無干擾)
        mode_badge = ""
        if context.provision_mode == "jit":
            b_txt = t("banner.badge_jit", locale=loc, default="JIT 臨時帳號")
            mode_badge = f" \033[1;36m[{b_txt}]\033[0m"

        if clean_target == op_user:
            user_val = f"\033[1;36m{user_display}\033[0m{mode_badge} | \033[35m{dept_part}\033[0m"
            lines.append(self._render_hud_item("👤", t("banner.login_identity", locale=loc), user_val, loc))
        else:
            lbl_op = t("banner.operator_label", locale=loc, default="操作人員")
            op_colon = "：" if "zh" in loc.lower() else ": "
            user_val = f"\033[1;32m{clean_target}\033[0m{mode_badge} | \033[36m{lbl_op}{op_colon}{user_display}\033[0m | \033[35m{dept_part}\033[0m"
            lines.append(self._render_hud_item("👤", t("banner.target_account", locale=loc, default="登入帳號"), user_val, loc))

        # 6. 帳號期限列
        if not context.account_expires_at or context.account_expires_at.lower() in ("forever", "permanent", "none"):
            exp_str = f"\033[32m{t('banner.perm_forever', locale=loc)}\033[0m"
        elif context.account_remaining_days is not None and context.account_remaining_days < 0:
            exp_str = f"\033[1;31m{t('banner.perm_expired', locale=loc, expires_at=context.account_expires_at)}\033[0m"
        elif context.account_remaining_days is not None and context.account_remaining_days > 0:
            exp_str = t(
                "banner.perm_days_hours",
                locale=loc,
                expires_at=context.account_expires_at,
                days=context.account_remaining_days,
                hours=context.account_remaining_hours or 0,
            )
        else:
            exp_str = AnsiSanitizer.sanitize(context.account_expires_at)
        lines.append(self._render_hud_item("⏳", t("banner.account_expiry", locale=loc), exp_str, loc))

        # 7. 存取模式列 (方案 C：僅 JIT 動態臨時帳號時才顯示警示提示)
        if context.provision_mode == "jit":
            mode_desc = t("banner.mode_jit", locale=loc)
            mode_color = "\033[1;36m"
            lines.append(self._render_hud_item("🔐", t("banner.access_mode", locale=loc), f"{mode_color}{mode_desc}\033[0m", loc))

        # 8. 特權授權列 (Sudo 權限)
        if context.sudo_perms:
            priv_key = f"banner.sudo_{context.sudo_perms.lower()}"
            priv_desc = t(priv_key, locale=loc, default=context.sudo_perms)
            priv_color = "\033[1;31m" if "all" in context.sudo_perms.lower() else "\033[1;33m"
        else:
            priv_desc = t("banner.priv_inherit", locale=loc, target_user=context.target_user or "root")
            priv_color = "\033[37m"
        lines.append(self._render_hud_item("🛡️", t("banner.privilege", locale=loc), f"{priv_color}{priv_desc}\033[0m", loc))

        # 9. 工單授權列 (若有)
        if context.ticket_no:
            clean_tno = AnsiSanitizer.sanitize(context.ticket_no)
            clean_reason = AnsiSanitizer.sanitize(context.ticket_reason or "-")
            rem_m = context.ticket_remaining_min if context.ticket_remaining_min is not None else 0
            ticket_detail = t(
                "banner.ticket_detail",
                locale=loc,
                ticket_no=clean_tno,
                remaining_min=rem_m,
                reason=clean_reason,
            )
            lines.append(self._render_hud_item("🎫", t("banner.ticket_auth", locale=loc), f"\033[1;33m{ticket_detail}\033[0m", loc))

        # 10. 最近登入列（紀錄相符時顯示 1 筆，異常時展開歷史紀錄）
        logins = context.recent_logins or ([context.recent_login] if context.recent_login else [])
        if logins:
            if context.audit_anomaly:
                alert_text = f"\033[1;31m{t('banner.audit_alert', locale=loc)}\033[0m"
                lines.append(self._render_hud_item("🕒", t("banner.recent_login", locale=loc), alert_text, loc))
                target_w = 11 if "zh" in loc.lower() else 17
                colon_w = 2
                indent_spaces = " " * (target_w + colon_w)
                for idx, item in enumerate(logins, start=1):
                    clean_item = AnsiSanitizer.sanitize(item)
                    if "[未經審計]" in clean_item or "[Unaudited]" in clean_item:
                        colored_item = f"\033[1;31m{idx}. {clean_item}\033[0m"
                    else:
                        colored_item = f"\033[36m{idx}. {clean_item}\033[0m"
                    lines.append(self._format_line(f"{indent_spaces}{colored_item}"))
            elif len(logins) == 1:
                clean_login = AnsiSanitizer.sanitize(logins[0])
                lines.append(self._render_hud_item("🕒", t("banner.recent_login", locale=loc), f"\033[36m{clean_login}\033[0m", loc))
            else:
                target_w = 11 if "zh" in loc.lower() else 17
                colon_w = 2
                indent_spaces = " " * (target_w + colon_w)
                for idx, item in enumerate(logins, start=1):
                    clean_item = AnsiSanitizer.sanitize(item)
                    colored_item = f"\033[36m{idx}. {clean_item}\033[0m"
                    if idx == 1:
                        lines.append(self._render_hud_item("🕒", t("banner.recent_login", locale=loc), colored_item, loc))
                    else:
                        lines.append(self._format_line(f"{indent_spaces}{colored_item}"))
        else:
            login_val = f"\033[32m{t('banner.first_login', locale=loc)}\033[0m"
            lines.append(self._render_hud_item("🕒", t("banner.recent_login", locale=loc), login_val, loc))

        # 11. 安全審計告示列
        clean_sid = AnsiSanitizer.sanitize(context.session_id)
        lbl_audit = t("banner.audit_notice", locale=loc)
        audit_line = f"🔴 \033[1;31m{lbl_audit}\033[0m \033[90m({clean_sid})\033[0m"
        lines.append(self._format_line(audit_line))

        # 12. 快捷鍵提示列
        lbl_hint = t("banner.return_hint", locale=loc)
        lines.append(self._format_line(f"💡 \033[33m{lbl_hint}\033[0m"))

        # 底部邊框
        bottom_border = "╰" + "─" * (BANNER_MAX_WIDTH - 2)
        lines.append(f"\033[1;34m{bottom_border}\033[0m")

        # 嚴格 CRLF 換行，首尾各空一行增強終端呼吸感
        return "\r\n" + "\r\n".join(lines) + "\r\n\r\n"

    def _render_hud_item(self, icon: str, label: str, value_colored: str, locale: str = "zh_TW") -> str:
        """
        以定寬標題槽精準格式化 HUD 單項，保證冒號嚴格垂直對齊。
        Format single HUD item with fixed-width label slots for strict vertical colon alignment.
        """
        # 繁體中文環境標題槽為 11 視覺寬度，英文環境為 17 視覺寬度
        target_w = 11 if "zh" in locale.lower() else 17
        colon = "：" if "zh" in locale.lower() else ": "
        title_raw = f"{icon} {label}"
        w = get_terminal_display_width(title_raw)
        padding = " " * max(0, target_w - w)
        header_part = f"{icon} \033[1;37m{label}\033[0m{padding}\033[1;37m{colon}\033[0m"
        return self._format_line(f"{header_part}{value_colored}")

    def _format_line(self, colored_text: str) -> str:
        """
        將內容文字精準格式化為安全寬度內的單行，超長自動截斷以維持邊框美觀。
        Format content text into a safe-width single line with truncation on overflow.
        """
        max_content_width = BANNER_MAX_WIDTH - BANNER_PREFIX_WIDTH - 1
        clean_text = AnsiSanitizer.sanitize(colored_text)
        current_width = get_terminal_display_width(clean_text)

        if current_width > max_content_width:
            truncated_clean = AnsiSanitizer.fit_width(clean_text, max_content_width, truncate_indicator="..")
            content_part = truncated_clean
        else:
            content_part = colored_text

        return f"\033[1;34m{BANNER_PREFIX}\033[0m{content_part}"


def build_fallback_banner(context: BannerContext) -> str:
    """
    熔斷降級用極簡 Banner，保證在插件逾時或崩潰時仍能提供安全連線指示。
    Minimal fallback banner rendered when dynamic provider times out or errors.
    """
    loc = context.locale
    lbl_host = t("banner.target_host", locale=loc)
    lbl_audit = t("banner.audit_notice", locale=loc)
    lbl_hint = t("banner.return_hint", locale=loc)

    clean_name = AnsiSanitizer.sanitize(context.hostname)
    clean_ip = AnsiSanitizer.sanitize(context.ip)
    clean_sid = AnsiSanitizer.sanitize(context.session_id)

    lines = [
        f"\033[1;34m╭────────────────────────────────────────────────────────────────────────────\033[0m",
        f"\033[1;34m│\033[0m  💻 {lbl_host}：{clean_name} ({clean_ip}:{context.port})",
        f"\033[1;34m│\033[0m  🔴 {lbl_audit} ({clean_sid})",
        f"\033[1;34m│\033[0m  💡 {lbl_hint}",
        f"\033[1;34m╰────────────────────────────────────────────────────────────────────────────\033[0m",
    ]
    return "\r\n" + "\r\n".join(lines) + "\r\n\r\n"


async def render_banner_safe(
    provider: Optional[IBannerProvider],
    context: BannerContext,
    timeout_sec: float = 0.2,
) -> str:
    """
    具備 200ms 超時熔斷與異常攔截之動態 Banner 安全調用入口。
    Safely render banner with 200ms circuit breaker timeout and fallback degradation.
    """
    active_provider = provider or DefaultTemplateBannerProvider()
    try:
        banner_text = await asyncio.wait_for(
            active_provider.build_banner(context),
            timeout=timeout_sec,
        )
        return banner_text
    except asyncio.TimeoutError:
        logger.warning(
            "[BANNER_TIMEOUT] Banner 插件組裝逾時 (超過 %.1fs)，自動降級輸出基礎資訊 (Banner build timed out, falling back to minimal banner)",
            timeout_sec,
        )
        return build_fallback_banner(context)
    except Exception as err:
        logger.error(
            "[BANNER_ERROR] Banner 插件執行拋出未捕捉異常，自動降級輸出: %s (Unhandled exception during banner build, falling back: %s)",
            err,
            err,
        )
        return build_fallback_banner(context)
