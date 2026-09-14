# OpenBastion

一套專為 Linux 與 Windows 伺服器設計的輕量級跳板機（Bastion Host）。受控端完全不需要安裝任何 Agent，透過系統原生 OpenSSH 與 ConPTY 終端協定進行連線控管，並以標準 asciinema v2 格式完整記錄操作過程。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-brightgreen.svg)](https://www.python.org/)
[![Audit: asciinema v2](https://img.shields.io/badge/Audit-asciinema%20v2-red.svg)](recordings/)
[![Security: AES-256-GCM](https://img.shields.io/badge/Vault-AES--256--GCM-orange.svg)](core/vault.py)

---

## 為什麼做這個專案？

一般中小型團隊在管理伺服器連線時，常見的幾種做法往往各自存在缺點：

* **直接發放 SSH 私鑰**：人員流動或金鑰複製難以追蹤，缺少集中收攏與即時吊銷的機制。
* **商用跳板機過於沉重**：動輒需要多台虛擬機與數十 GB 記憶體，維護負擔與授權成本高。
* **Windows 主機審計不易**：常見工具容易被防毒軟體或 EDR 阻擋，而 RDP 圖像連線又難以進行純文字檢索。
* **終端中英排版錯位**：傳統跳板機若遇到中英文混排，選單表格往往斷線破版。

OpenBastion 嘗試在「極簡部署」與「合規審計」之間取得平衡：

| 維度 | 自製腳本 / 直連 | 商用跳板機系統 | OpenBastion |
| :--- | :--- | :--- | :--- |
| **受控端部署** | 需手動分發公鑰 | 需安裝專有 Agent | **原生 OpenSSH，零代理 (Agentless)** |
| **Windows 支援** | 易遭安全軟體攔截 | 多數僅支援圖像 RDP | **原生 ConPTY 支援，純文字即時審計** |
| **金鑰存放安全** | 明文存於檔案系統 | 需配置硬體 KMS 模組 | **AES-256-GCM 結合本機硬體指紋綁定加密** |
| **操作錄影格式** | 依賴 history，易遭竄改 | 廠商專有二進制格式 | **標準 asciinema v2 格式，可用開源工具回放** |
| **終端排版相容** | 中文全形字元容易破版 | 多數未針對雙位元優化 | **嚴格 78 欄位限制，依 East Asian Width 等寬對齊** |

---

## 終端操作畫面

### 1. 主機導航選單 (TUI Navigation)
登入跳板機後，系統會呈現嚴格遵循 78 欄位安全線的互動選單：

```text
+----------------------------------------------------------------------------+
|                            OpenBastion 主機選單                            |
+----------------------------------------------------------------------------+
|      # 主機名稱         IP:埠號                作業系統       部門         |
| ------ ---------------- ---------------------- -------------- ------------ |
|  ● [1] Web-Prod-01      192.168.1.50:22        Ubuntu 22.04   電商核心組   |
|  ● [2] DB-Master        192.168.1.60:22        CentOS 7.9     資料庫維運組 |
|  ● [3] Win-AD-01        192.168.1.10:22        Windows 2022   網管基礎組   |
|----------------------------------------------------------------------------|
|  [1-9]連線 | [v]介面 | [n/p]翻頁 | [q]退出             第 1/1 頁 (共 3 台) |
+----------------------------------------------------------------------------+
```

**快速操作指令：**
* **直接連線**：輸入序號（如 `1`）或全域序號（如 `#12`）連線。
* **穿透直連 (Direct Connect)**：支援終端直連語法 `ssh user#target@bastion -p 2222`（如 `ssh admin#192.168.1.50@127.0.0.1 -p 2222` 或 `ssh admin#1@127.0.0.1 -p 2222`），跳過選單直達目標主機。
* **智慧過濾**：直接輸入關鍵字過濾（支援空格多條件與 `-` 排除，例如 `web -test`）。
* **介面切換**：輸入 `v` 可在「系統模式」與「機房模式（顯示內網 NAT 與機櫃位置）」間切換。
* **會話暫掛與接回**：連線中可隨時按下 `Ctrl + ]` 抽離連線，並透過 `r` 或 `r1`～`r3` 接回既有連線。
* **語系切換**：輸入 `lang zh` 或 `lang en` 即時切換介面語言。

---

### 2. 連線前置 HUD 狀態卡 (Connection Banner)
建立目標連線時，系統會在進入 Shell 前動態印出當前會話與主機概況，並自動垂直對齊冒號：

```text
==============================================================================
  🚀 OpenBastion - 安全連線資訊
==============================================================================
│  💻 目標主機   : #1 | Web-Prod-01 (192.168.1.50:22 | 電商核心組)
│  🖥️ 系統環境   : Linux Ubuntu 22.04 LTS | 正常運作: 45 天 12 小時
│  📊 主機狀態   : 負載: 0.15, 0.22, 0.18 | 記憶體: 42% | 磁碟: 58%
│  👤 登入身分   : admin | 部門：技術維運組
│  ⏳ 帳號期限   : 永久有效
│  🛡️ 特權授權   : 繼承目標帳號權限
│  🎫 工單授權   : 工單號: TICKET-2026-001 (剩餘 58 分鐘) | 原因: 例行維護
│  🔴 安全審計   : 全程雙向字元錄影中 (會話編號: sess_20260914_9a8b7c)
==============================================================================
```

---

## 快速開始 (Quickstart)

本機需備妥 Python 3.9 以上環境。

### 1. 安裝與設定
```bash
git clone https://github.com/YuShyam/OpenBastion.git
cd OpenBastion
pip install -r requirements.txt
```

### 2. 啟動跳板機服務
```bash
python main.py
```
*(預設於本機 Port `2222` 啟動非同步 SSH 監聽閘道)*

### 3. 連入跳板機
使用常用終端連入本機跳板機：
```bash
ssh -p 2222 admin@127.0.0.1
```
*(初次安裝或忘記密碼時，可執行 `python main.py --reset-admin` 透過本機安全精靈重設)*

### 4. 啟用 MFA 雙因子驗證 (可選)
為指定帳號啟用 RFC 6238 原生 TOTP 動態驗證碼（需驗證管理者密碼）：
```bash
python main.py --setup-mfa admin
```
*(終端將顯示 Base32 密鑰、8 組一次性備援碼與 ASCII QR Code 供手機 Authenticator 綁定)*

---

## 外掛擴充：自訂連線 Banner (IBannerProvider)

所有連線前印出的資訊卡皆為插件化設計。若需要加入自訂的機房守則、法務警語或外部監控資訊，只需實作 `IBannerProvider` 介面：

```python
from core.banner import IBannerProvider, BannerContext

class CustomPolicyBannerProvider(IBannerProvider):
    """自訂資安法務聲明 Banner 範例"""

    async def build_banner(self, context: BannerContext) -> str:
        # context 提供目標主機、登入者、工單號、系統負載等完整上下文
        lines = [
            "=" * 78,
            "  ⚠️  【生產環境維運安全警語】",
            "=" * 78,
            f"│  👤 操作人員: {context.operator_username}",
            f"│  🎫 關聯工單: {context.ticket_no or '未綁定工單'}",
            f"│  💻 目標主機: {context.hostname} ({context.ip}:{context.port})",
            "│  🛡️  提醒事項: 所有指令與終端輸出均完整存檔，請審慎執行變更。",
            "=" * 78,
        ]
        return "\r\n".join(lines) + "\r\n"
```

---

## 研發里程碑 (Roadmap)

各階段交付進度與規劃請參閱 [docs/ROADMAP.md](docs/ROADMAP.md)：

- [x] **Phase 1: RFC 4253 SSH-2.0 核心通訊通道與主機金鑰管理**
- [x] **Phase 2: 終端 TUI 78 欄位防破版選單與 PTY 刷新保證**
- [x] **Phase 3: SQLite WAL 儲存驅動與會話生命週期管理器**
- [x] **Phase 4: 字元水管、會話錄影、指令審計與雙軌 CA 短期憑證**
- [x] **Phase 4.5: Level 3 JIT 動態治理、雙軸指令審計體系與穿透直連語法**
- [x] **Phase 4.8: RFC 4256 鍵盤互動協定、可抽換 MFA SPI (純 Python TOTP) 與 CLI 安全門禁**
- [ ] **Phase 5: Web 監控 API 與管理介面**
- [ ] **Phase 6: 真實 OpenSSH 端到端黑箱驗收與正式發布**

---

## 相關文件

* 規格設計說明書：[docs/SPEC.md](docs/SPEC.md)（模組架構契約與防衛機制）
* 架構決策紀錄：[docs/adr/ADR_001_ZERO_TOUCH_AND_JIT.md](docs/adr/ADR_001_ZERO_TOUCH_AND_JIT.md)

---

## 授權條款

本專案採用 [MIT License](LICENSE) 授權釋出。
