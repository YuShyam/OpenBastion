"""
OpenBastion Core - Internationalization Engine (輕量多語系引擎)
==============================================================
依據 docs/SPEC.md §4.2 規範，提供零外部相依之輕量多語系支援。
Lightweight internationalization engine with zero external dependencies and dynamic JSON discovery.

核心職責 / Responsibilities:
  1. 外部語系完全解耦：100% 自 locales/*.json 動態載入，單一真理來源 (SSOT)。
  2. 零修改熱插拔：新增語系只需丟入 locales/<code>.json，開機自動發現 (Auto-Discovery)。
  3. 安全退避機制 (Fail-Safe)：查無字典或查無 key 時直接回傳 key 本身，永不拋例外中斷連線。
  4. 支援別名動態模糊匹配 (match_locale) 與語系自省導引 (get_supported_locales_info)。
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("openbastion.i18n")

DEFAULT_LOCALE = "zh_TW"
LOCALES_DIR = Path(__file__).resolve().parent.parent / "locales"

# 支援語系元資料登錄表 (開機時自 locales/*.json 動態發現並自動註冊)
SUPPORTED_LOCALES: Dict[str, Dict[str, Any]] = {}

# 全域多語系字典 (單一真理來源：由 locales/*.json 載入，零重複代碼)
_translations: Dict[str, Dict[str, str]] = {}

_current_locale = DEFAULT_LOCALE


def load_locales_from_disk() -> None:
    """
    自 locales/ 目錄動態掃描並載入所有 JSON 語系字典 (Auto-Discovery)。
    Scan and dynamically load all JSON translation files from locales directory.
    """
    global SUPPORTED_LOCALES, _translations

    if not LOCALES_DIR.exists() or not LOCALES_DIR.is_dir():
        logger.warning("[I18N_WARN] 語系目錄不存在: %s (Locales directory not found)", LOCALES_DIR)
        return

    for json_file in sorted(LOCALES_DIR.glob("*.json")):
        locale_code = json_file.stem
        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # 擷取 _metadata 宣告
            metadata = data.pop("_metadata", None) or {}
            # 忽視非字串的輔助欄位 (如 _budget_hints)
            data.pop("_budget_hints", None)

            name = metadata.get("name", locale_code)
            aliases = tuple(metadata.get("aliases", [locale_code.lower()]))

            SUPPORTED_LOCALES[locale_code] = {
                "name": name,
                "aliases": aliases,
            }

            # 載入所有鍵值至全域字典 (SSOT)
            for key, val in data.items():
                if not isinstance(val, str):
                    continue
                if key not in _translations:
                    _translations[key] = {}
                _translations[key][locale_code] = val
        except Exception as e:
            logger.warning("[I18N_FAIL] 載入外部語系檔案 %s 失敗: %s (Failed to load locale file)", json_file.name, e)


# 模組載入時自動執行外部語系發現
load_locales_from_disk()


def match_locale(query: str) -> Optional[str]:
    """
    依輸入之別名或語系代碼動態模糊匹配支援的語系。
    Match a query alias or code against registered supported locales.
    """
    clean = query.strip().lower()
    for loc, meta in SUPPORTED_LOCALES.items():
        if clean == loc.lower() or clean in meta.get("aliases", ()):
            return loc
    return None


def get_supported_locales_info() -> List[Dict[str, str]]:
    """
    取得目前支援的所有語系資訊清單 (代碼、名稱、推薦指令)。
    Get a list of all supported locales with display names and command hints.
    """
    return [
        {
            "code": loc,
            "name": str(meta["name"]),
            "hint": f"lang {meta['aliases'][0]}" if meta.get("aliases") else f"lang {loc}",
        }
        for loc, meta in sorted(SUPPORTED_LOCALES.items())
    ]


def set_locale(locale: str) -> None:
    """
    設定當前語系代碼。
    Set the current active locale code globally.
    """
    global _current_locale
    if locale in SUPPORTED_LOCALES:
        _current_locale = locale


def get_locale() -> str:
    """
    取得當前全域語系代碼。
    Get the currently configured active locale code.
    """
    return _current_locale


def t(key: str, locale: Optional[str] = None, **kwargs: Any) -> str:
    """
    依據語系字典轉換文字，支援安全退避與格式化參數。
    Translate text by key with safe fallback and kwargs formatting.
    查無字典或查無 key 時，安全退避直接回傳 key 本身，確保系統永不崩潰。
    """
    loc = locale or _current_locale
    if loc not in SUPPORTED_LOCALES:
        loc = DEFAULT_LOCALE

    entry = _translations.get(key)
    if not entry:
        return key

    text = entry.get(loc) or entry.get(DEFAULT_LOCALE, key)
    if kwargs:
        try:
            return text.format(**kwargs)
        except Exception:
            return text
    return text
