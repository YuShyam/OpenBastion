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
- [ ] 實裝 78 欄位主機導航選單
- [ ] 使用 `unicodedata.east_asian_width` 算術，中英混排時邊框精準對齊
- [ ] 輸出消毒：過濾有害 ANSI 控制序列，防止終端逃逸注入
- [ ] `process.stdout.drain()` 非同步刷新保證，避免客戶端卡在緩衝區

---

## Phase 3: SQLite WAL 儲存與會話生命週期管理
- [ ] 實裝 SQLite 儲存驅動，強制啟用 WAL 模式
- [ ] 會話狀態機與 SessionContext 生命週期登錄
- [ ] 系統異常中斷後的開機孤児對帳修復機制
- [ ] 管理員手動緊急中斷連線能力 (Kill Switch)

---

## Phase 4: 字元水管旁路採樣、asciinema 錄影與審計落盤
- [ ] 雙向字元串流轉發水管 (StreamPipe)
- [ ] 旁路分流採樣 (Tap)，支援 asciinema v2 (.cast) 本地錄影
- [ ] 登入、指令、斷線事件落盤審計日誌（Append-Only，不可覆蓋）
- [ ] 終端帶內通知插播機制

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
