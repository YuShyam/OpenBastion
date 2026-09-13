"""
OpenBastion Core - Internationalization Engine (輕量多語系引擎)
==============================================================
依據 docs/SPEC.md §4.2 規範，提供零外部相依之輕量多語系支援。
Lightweight internationalization engine with zero external dependencies.

核心職責 / Responsibilities:
  1. 內建 zh_TW（繁體中文）與 en_US（英文）雙語字典。
  2. 提供 t(key, locale=None, **kwargs) 字典查詢與安全退避 (Safe Fallback)。
  3. 所有文字均經過自然化潤飾，無任何空泛形容詞與機械化套話。
"""

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("openbastion.i18n")

DEFAULT_LOCALE = "zh_TW"
SUPPORTED_LOCALES = ("zh_TW", "en_US")

# 內建多語系字典 (自然平實用語，經去油去味潤飾)
BUILTIN_TRANSLATIONS: Dict[str, Dict[str, str]] = {
    # 共通狀態詞
    "common.online": {"zh_TW": "在線", "en_US": "Online"},
    "common.offline": {"zh_TW": "離線", "en_US": "Offline"},
    "common.unknown": {"zh_TW": "未知", "en_US": "Unknown"},
    "common.exit": {"zh_TW": "退出", "en_US": "Exit"},

    # 終端選單 (Terminal Menu)
    "menu.title": {"zh_TW": "OpenBastion 主機選單", "en_US": "OpenBastion Host Menu"},
    "menu.col_index": {"zh_TW": "#", "en_US": "#"},
    "menu.col_name": {"zh_TW": "主機名稱", "en_US": "Hostname"},
    "menu.col_address": {"zh_TW": "IP:埠號", "en_US": "Endpoint"},
    "menu.col_internal_nat": {"zh_TW": "內網NAT", "en_US": "Internal IP"},
    "menu.col_os": {"zh_TW": "作業系統", "en_US": "OS"},
    "menu.col_alias": {"zh_TW": "別名", "en_US": "Alias"},
    "menu.col_status": {"zh_TW": "狀態", "en_US": "Status"},
    "menu.col_rack": {"zh_TW": "機櫃位置", "en_US": "Rack"},
    "menu.view_system": {"zh_TW": "系統模式", "en_US": "System"},
    "menu.view_idc": {"zh_TW": "機房模式", "en_US": "IDC"},
    "menu.nav_bar": {
        "zh_TW": "[1-9]連線 | [v]視圖({view}) | [/]搜尋 | [n/p]翻頁 | [exit]退出",
        "en_US": "[1-9]Connect | [v]View({view}) | [/]Search | [n/p]Page | [exit]Exit",
    },
    "menu.page_info": {
        "zh_TW": "頁次: {page}/{total_pages} (共 {total_count} 台)",
        "en_US": "Page: {page}/{total_pages} ({total_count} hosts)",
    },
    "menu.search_active": {
        "zh_TW": "過濾: '{query}' (匹配 {count} 台)",
        "en_US": "Filter: '{query}' ({count} matches)",
    },
    "menu.search_empty": {
        "zh_TW": "(查無符合條件的主機)",
        "en_US": "(No matching hosts found)",
    },
    "menu.empty_hosts": {
        "zh_TW": "目前無任何主機資產 (尚未建立資料庫連線)",
        "en_US": "No host assets found (Database not yet connected)",
    },

    # 閘道互動訊息 (Gateway Messages)
    "gateway.bye": {
        "zh_TW": "連線已關閉，再見！",
        "en_US": "Connection closed, goodbye!",
    },
    "gateway.invalid_cmd": {
        "zh_TW": "無效指令，請輸入序號、[v]切換視圖、[/]搜尋、[lang en/zh]切換語言或 [exit]退出",
        "en_US": "Invalid command. Enter index, [v]view, [/]search, [lang en/zh]locale, or [exit]exit",
    },
    "gateway.connected_to": {
        "zh_TW": "正在建立安全連線至: {name} ({endpoint}) ...",
        "en_US": "Establishing secure connection to: {name} ({endpoint}) ...",
    },
    "gateway.auto_connected_to": {
        "zh_TW": "搜尋唯一命中，自動直連至: {name} ({endpoint}) ...",
        "en_US": "Single search match found, auto-connecting to: {name} ({endpoint}) ...",
    },
    "gateway.system_type": {
        "zh_TW": "目標系統類型: {system} | 所屬維運組: {dept}",
        "en_US": "Target OS: {system} | Department: {dept}",
    },

    "gateway.cmd_too_long": {
        "zh_TW": "指令過長，超出安全長度限制 (最大 256 字元)",
        "en_US": "Command too long, exceeding safety limit (max 256 chars)",
    },

    # 後台系統日誌 (System Logs)
    "log.host_key_loaded": {
        "zh_TW": "已載入主機金鑰: {path}",
        "en_US": "Host key loaded: {path}",
    },
    "log.host_key_generating": {
        "zh_TW": "未偵測到主機金鑰，正在生成專屬 ED25519 金鑰...",
        "en_US": "No host key detected, generating dedicated ED25519 key...",
    },
    "log.host_key_persisted": {
        "zh_TW": "主機金鑰已成功持久化至: {path}",
        "en_US": "Host key successfully persisted to: {path}",
    },
    "log.host_key_load_failed": {
        "zh_TW": "讀取現有主機金鑰失敗，重新生成: {error}",
        "en_US": "Failed to read existing host key, regenerating: {error}",
    },
    "log.gateway_listening": {
        "zh_TW": "OpenBastion SSH-2.0 閘道已啟動，監聽於 {host}:{port}",
        "en_US": "OpenBastion SSH-2.0 gateway started, listening on {host}:{port}",
    },
    "log.channel_ready": {
        "zh_TW": "OpenBastion 核心通訊通道已就緒 (Port {port})",
        "en_US": "OpenBastion core communication channel is ready (Port {port})",
    },
    "log.channel_waiting_db": {
        "zh_TW": "通訊通道已就緒 (Port {port}) [尚未建立使用者資料庫，安全處於 Fail-Closed 預設拒絕狀態]",
        "en_US": "Channel ready (Port {port}) [Database not yet initialized, running in secure Fail-Closed state]",
    },
    "log.connect_hint": {
        "zh_TW": "外部 SSH 連線將依 Fail-Closed 原則安全拒絕，待 Phase 3 建立資料庫後方可登入",
        "en_US": "Incoming SSH connections are safely denied under Fail-Closed until Phase 3 database is provisioned",
    },
    "log.shutdown_hint": {
        "zh_TW": "按下 Ctrl+C 可停止服務",
        "en_US": "Press Ctrl+C to stop service",
    },
    "log.shutting_down": {
        "zh_TW": "接收到終止信號，正在關閉服務...",
        "en_US": "Termination signal received, shutting down services...",
    },
    "log.server_stopping": {
        "zh_TW": "正在停止 SSH-2.0 閘道伺服器...",
        "en_US": "Stopping SSH-2.0 gateway server...",
    },
    "log.server_stopped": {
        "zh_TW": "SSH-2.0 閘道伺服器已安全停止",
        "en_US": "SSH-2.0 gateway server safely stopped",
    },
    "log.session_end": {
        "zh_TW": "使用者 '{username}' 會話已正常關閉",
        "en_US": "Session for user '{username}' closed normally",
    },
    "log.auth_denied_no_db": {
        "zh_TW": "[AUTH_DENIED] 尚未建立使用者資料庫，依據 Fail-Closed 原則拒絕連線: '{username}'",
        "en_US": "[AUTH_DENIED] Database not yet initialized, access denied under Fail-Closed policy: '{username}'",
    },
}

_current_locale = DEFAULT_LOCALE


def set_locale(locale: str) -> None:
    """設定當前語系 (Set current active locale)"""
    global _current_locale
    if locale in SUPPORTED_LOCALES:
        _current_locale = locale


def get_locale() -> str:
    """取得當前語系代碼 (Get current locale code)"""
    return _current_locale


def t(key: str, locale: Optional[str] = None, **kwargs: Any) -> str:
    """
    依據語系字典轉換文字，支援安全退避與格式化參數。
    Translate text by key with safe fallback and kwargs formatting.
    """
    loc = locale or _current_locale
    if loc not in SUPPORTED_LOCALES:
        loc = DEFAULT_LOCALE

    entry = BUILTIN_TRANSLATIONS.get(key)
    if not entry:
        return key

    text = entry.get(loc) or entry.get(DEFAULT_LOCALE, key)
    if kwargs:
        try:
            return text.format(**kwargs)
        except Exception:
            return text
    return text
