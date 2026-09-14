# OpenBastion 研發里程碑 (Product Roadmap)

各階段贏點明確，完成前一階段再進入下一階段，不跨階段假設功能已完成。

---

## Phase 1: SSH-2.0 通道監聽與主機金鑰管理
- [x] 引入 `asyncssh`，實裝標準 RFC 4253 SSH 伺服器
- [x] 自動生成並持久化 ED25519 主機金鑰 (`data/ssh_host_key`)
- [x] 支援本機帳號標準密碼鑑權回呼
- [x] 以原生 OpenSSH 客戶端連線驗證 (`ssh -p 2222 admin@127.0.0.1`)

---

## Phase 2: 終端 78 欄位防破版選單與 PTY 刷新保證
- [x] 實裝 78 欄位主機導航選單
- [x] 使用 `unicodedata.east_asian_width` 算術，中英混排時邊框精準對齊
- [x] 輸出消毒：過濾有害 ANSI 控制序列，防止終端逃逸注入
- [x] `process.stdout.drain()` 非同步刷新保證，避免客戶端卡在緩衝區

---

## Phase 3: SQLite WAL 儲存與會話生命週期管理
- [x] 實裝 SQLite 儲存驅動，強制啟用 WAL 模式
- [x] 會話狀態機與 SessionContext 生命週期登錄
- [x] 系統異常中斷後的開機孤兒對帳修復機制
- [x] 管理員手動緊急中斷連線能力 (Kill Switch)

---

## Phase 4: 字元水管、會話錄影、指令審計與雙軌 CA 短期憑證
- [x] 雙向字元串流轉發水管 (StreamPipe，含 512KB 環形緩衝與 Ctrl + ] 逃逸返回)
- [x] 旁路分流採樣 (Tap)，支援 asciinema v2 (.cast) 本地錄影與 SHA-256 完整性校驗
- [x] 帶內指令審計防禦引擎 (AuditEngine)，支援命令還原、機敏脫敏與三級防護 (LOG/ALERT/BLOCK)
- [x] 動態連線 HUD Banner 卡片 (定寬標題槽垂直齊頭對齊、200ms 熔斷保護、全域 i18n)
- [x] OpenSSH 雙軌 CA 短期憑證引擎 (Level 2 零侵入架構，Ed25519 + RSA-4096 雙軌簽發，相容早期 OpenSSH)

---

## Phase 4.5: Level 3 JIT 帳號動態治理與全面雙軸審計體系
- [x] 受控端零 Agent 動態調度器 (JitProvisioner，獨立 POSIX UID、密碼鎖定 Fail-Closed、/etc/sudoers.d/ 即時收放)
- [x] 動靜分離與西元 4 碼 K-Sortable 識別碼 (host_{12hex}, user_{12hex}, sess_YYYYMMDD_{12hex}, cmd_YYYYMMDD_{12hex})
- [x] 全面雙軸指令審計體系 (audit_logs 擴充 audit_id, host_ip, host_name 與 Enter 鍵敲擊正則脫敏落盤)
- [x] 連線 HUD Banner 極簡化 (目標主機格式 #序號 | 名稱 (IP:Port | 部門)，徹底移除第 7 列存取模式)
- [x] 穿透直連語法支援 (Direct Connect: ssh admin#target@bastion -p 2222，支援以 #序號、IP、名稱直達遠端)
- [x] 資產生命週期門禁 (--add-host 預設 Level 3 JIT，管理者強鑑權門禁，端點防重複檢驗與 created_by 追蹤)

---

## Phase 4.8: RFC 4256 鍵盤互動 MFA 與可抽換 SPI 插件架構
- [x] 認證解耦 SPI 介面 (IAuthProvider / IMfaProvider)，支援純標準函式庫可擴充外掛
- [x] 純 Python 原生 RFC 6238 TOTP 計算與驗證引擎 (90 秒容錯窗口與單次消費防重放)
- [x] 一次性緊急備援碼 (Recovery Codes) 加鹽雜湊持久化與即時核銷
- [x] RFC 4256 鍵盤互動二階瀑布流狀態機 (先驗密碼，未開 MFA 者自動平滑放行)
- [x] RFC 4252 標準認證橫幅通道 (send_auth_banner 靠左對齊，杜絕 Windows OpenSSH 轉義亂碼)
- [x] CLI 參數全面中英雙語化與 MFA 本機安全門禁 (強制管理者鑑權與操作審計留痕)

---

## Phase 5: Web 監控 API 與管理介面
- [ ] 輕量 REST API，所有數字必須來自真實採集 (Zero Mock Data)
- [ ] 極簡灰階 Web 控制台（Shadcn UI 設計代幣體系）
- [ ] 全站 i18n 語系抽離，語系字典動態載入
- [ ] 即時連線數、審計日誌與主機資產管理視圖

---

## Phase 6: 黑箱驗收與正式發布
- [ ] 原生 OpenSSH 客戶端端到端黑箱自動化驗收
- [ ] 多平台相容性驗證（Windows Terminal / PuTTY / Linux Bash）
- [ ] 正式發布文件與快速入門指南
