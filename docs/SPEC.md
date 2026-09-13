# OpenBastion 系統架構與功能規格書 (Functional Specification)

> **版本**: 1.0.0-draft  
> **定位**: 輕量開源 SSH-2.0 終端跳板機與操作審計系統。  
> **核心原則**: 標準 RFC 4253 協議、零假資料、終端防破版、不可變審計。

---

## 1. 系統概述 (System Overview)

OpenBastion 是一套針對 Linux 與 Windows 伺服器終端管理設計的開源跳板機。提供帳號身分驗證、主機導航選單、即時會話管理、指令審計與操作錄影，受控主機無需安裝任何代理程式。

架構分為三層：**核心服務 (Core Engine)**、**儲存驅動 (Storage Driver)**、**擴展模組 (Extensions)**，各層職責明確，通訊協定標準化、資料持久化可靠。

---

## 2. 核心元件架構 (Core Components)

跳板機核心由六個功能明確的元件組成：

```
+-------------------------------------------------------------------+
|                   OpenBastion 核心架構視圖                        |
+-------------------------------------------------------------------+
| 1. 標準 SSH-2.0 通道監聽器 (RFC 4253 Gateway Listener)           |
|    - 基於 asyncssh 實作，監聽預設 TCP Port 2222                  |
|    - 支援 ED25519 / RSA 主機金鑰持久化 (data/ssh_host_key)        |
|    - 原生相容 OpenSSH、PuTTY、Xshell 等標準客戶端                 |
+-------------------------------------------------------------------+
| 2. 會話生命週期管理器 (Session Registry & Lifecycle)              |
|    - 連線核發唯一 UUID 會話識別碼、記錄來源 IP 與連線時間         |
|    - 字元吞吐流量傳感器 (Rx / Tx Bytes 統計)                     |
|    - 管理員緊急連線中斷能力 (Admin Kill Switch)                   |
+-------------------------------------------------------------------+
| 3. 雙向字元水管與旁路採樣 (Bidirectional Stream Pipe with Tap)    |
|    - 高效無阻塞非同步字元轉發                                     |
|    - 旁路採樣分流孔 (Tee / Tap)：供 asciinema 錄影與指令審計讀取  |
|    - 終端帶內通知插播機制 (In-Band Message Injection)            |
+-------------------------------------------------------------------+
| 4. 存取授權與時效門禁閘門 (Access Pass Gatekeeper)                |
|    - 檢查使用者對目標主機之存取權限與有效期限                     |
|    - 支援逾期強制熔斷中斷機制 (Auto-Disconnect on Expiry)         |
+-------------------------------------------------------------------+
| 5. 開機資料核對引擎 (Boot Reconciliation Engine)                  |
|    - 系統異常重啟或斷電時，強制將未正常關閉的連線標記為 ABRUPT   |
|    - 清理資料庫中殘留的異常狀態                                   |
+-------------------------------------------------------------------+
| 6. 不可變審計紀錄 (Immutable Audit Trail)                         |
|    - 記錄登入、連線建立、指令執行與斷線事件                       |
|    - 支援標準日誌格式輸出 (RFC 5424)                              |
+-------------------------------------------------------------------+
```

---

## 3. 可插拔模組設計 (Modular Architecture)

### 3.1 身分驗證模組 (Authentication Module)
- **基礎驗證**: 本機帳號與 PBKDF2-SHA256 雜湊密碼比對。
- **MFA 挑戰機制**: 支援 TOTP（RFC 6238）二階段驗證。後端主動發起挑戰，終端提示輸入動態驗證碼，登入流程不需改動前端頁面結構。

### 3.2 資料儲存層 (Data Storage Layer)
- **統一介面 (`IStorageProvider`)**: 封裝使用者、伺服器資產與權限規則的 CRUD 操作，核心程式不直接依賴特定資料庫。
- **內建驅動**:
  - `JsonFileStorage`: 讀取 `config/servers.json`，適合個人單機部署，零設定啟動。
  - `SQLiteStorage`: 關聯式儲存，**強制啟用 WAL 模式**，支援多執行緒並行讀寫，不會在高頻審計寫入時鎖死。

### 3.3 目標主機連線轉接器 (Transport Connectors)
- **Linux SSH Adapter**:
  - 對接目標 Linux 伺服器之 OpenSSH 服務（預設 Port 22）。
  - 分配虛擬終端（PTY），轉發終端字元流。
- **Windows SSH Adapter**:
  - 對接 Windows 10 (1809+) / Windows 11 / Server 2019+ 原生內建之 OpenSSH Server 與 ConPTY。
  - 走標準 Port 22 SSH 加密通道，實現 PowerShell 原生命令列審計與操作錄影。

### 3.4 字元串流錄影模組 (Session Recorder)
- **錄影格式**: `asciinema v2` (.cast)，開放標準格式，記錄帶毫秒時間戳記的終端 I/O 事件，可用任意相容播放器回放。
- **歸檔規則**: 依日期與 Session UUID 歸檔於 `recordings/YYYYMMDD_<uuid>.cast`，並記錄檔案 SHA-256 雜湊以供事後完整性驗證。

### 3.5 憑證保管模組 (Credential Vault)
- **儲存規範**: 資料庫與設定檔中嚴禁明文存放目標主機的私鑰與密碼。
- **加密方式**: AES-256-GCM 對稱加密，主金鑰透過環境變數 (`OPENBASTION_MASTER_KEY`) 或金鑰檔案注入，不綁定硬體特徵（確保 VM 遷移後仍可正常解密）。

---

## 4. 介面實作規範 (Interface Standards)

### 4.1 終端 TUI (Terminal User Interface)
1. **78 欄位安全線**:
   - 主機選單總寬度限制在 ≤ 78 字元。各類終端軟體（PuTTY、Windows Terminal、iTerm2）的預設視窗寬度各不相同，78 是最保守的安全值，確保不折行。
   - 欄位預算：縮排(2) + 編號(5) + 主機名稱(16) + IP:Port(21) + 系統類型(16) + 部門/狀態(18) = 78。
2. **東亞字元寬度計算**:
   - 排版時使用 `unicodedata.east_asian_width()` 計算顯示寬度（中文字計 2 格、英數計 1 格），否則中英混排時邊框必然破裂。
3. **ANSI 控制序列消毒**:
   - 輸出字元流過濾 `< 0x20` 與 `0x1B ESC` 等有害控制序列，防止惡意輸入改寫終端畫面。
4. **輸出緩衝區即時刷新**:
   - 選單與提示字元輸出後強制調用 `process.stdout.drain()`，確保即時顯示。沒有這步，某些客戶端會卡在等待緩衝區填滿才顯示。

### 4.2 Web 管理控制台 (Web Management Console)
1. **零假資料原則**:
   - API 回傳的所有數值必須來自真實採集。查無資料時回傳空陣列 `{"total": 0, "events": []}`，未巡檢的指標標記為 `"-"` 或 `"UNKNOWN"`，不捏造假延遲數字。
2. **多語系支援 (i18n)**:
   - 前端靜態頁面不寫死中文字串，一律以 `data-i18n` 屬性對應語系字典檔（`locales/zh_TW.json`）。
3. **樣式規範**:
   - 所有樣式集中於 CSS 樣式表，嚴禁 `style="..."` 內聯。數值欄位靠右對齊並套用 `font-variant-numeric: tabular-nums`，防止數字跳動時版面抖動。

### 4.3 系統日誌規範 (System Logging Specification)
1. **確定性狀態標籤 (Event Status Tag)**:
   - 每條日誌開頭必須包含具備明確狀態語意的英數大寫標籤（如 `[BOOT_OK]`, `[BOOT_FAIL]`, `[AUTH_OK]`, `[AUTH_DENIED]`, `[AUTH_INACTIVE]`, `[SESSION_START]`, `[SESSION_CLOSED]`, `[KILL_SWITCH]`, `[RECONCILE_DONE]`），確保監控系統（ELK / Datadog / Loki）能精準過濾與指標告警。
2. **中英雙軌並列 (Bilingual Message)**:
   - 描述文字採「繁體中文為主 + (英文說明為輔)」，兼顧維運人員直觀閱讀親和力與國際開源檢索相容性。
3. **強制 UTF-8 編碼 (Strict UTF-8 Encoding)**:
   - 控制台與日誌 Handler 強制宣告 `encoding="utf-8"`，確保跨平台（Windows Terminal / Linux / Docker）零亂碼。
4. **敏感資訊脫敏 (Data Sanitization)**:
   - 嚴禁輸出密碼明文、私鑰內容或未加鹽憑證（符合 OWASP Top 10 與 CWE-532 規範）。
5. **架構純淨與無漂移**:
   - 後端 logger 直接以程式碼字串定義，不依賴 `locales/*.json` 選單字典，確保系統日誌格式具備確定性，不因連線者切換語言而漂移。

---

## 5. 實施計畫

各階段任務清單與交付狀態請參閱 [docs/ROADMAP.md](ROADMAP.md)。

---

## 6. 非功能性需求 (Non-Functional Requirements)

1. **依賴精簡**: 核心執行環境僅依賴 Python 3.10+ 與 `asyncssh`、`cryptography` 兩個套件，不引入厚重框架。
2. **資源佔用**: 待機記憶體 < 50MB，字元流轉發延遲 < 5ms。
3. **安全邊界**:
   - 預設禁止 root 直接登入跳板機管理端。
   - 不允許透過 Web 介面動態執行未知程式碼。
   - 審計記錄採追加式寫入（Append-Only），寫入後不可覆蓋。
