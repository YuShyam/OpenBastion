# OpenBastion

> 現代化輕量開源 SSH-2.0 終端跳板機與操作審計系統 (Lightweight SSH-2.0 Bastion JumpServer & Audit System)

---

## 專案概述 (Overview)

OpenBastion 是一套專為 Linux 與 Windows 伺服器終端管理設計的開源跳板機系統。受控主機維持原生環境，無需安裝第三方代理程式 (Agentless)。

系統基於標準 RFC 4253 SSH-2.0 協定實作，提供集中身分認證、78 欄位終端防破版導航選單、操作會話生命週期管理、asciinema v2 終端錄影與不可變審計日誌。

---

## 核心設計原則 (Core Principles)

* **標準 SSH-2.0 協定**: 基於 RFC 4253 規範，支援 ED25519 主機金鑰，原生相容 OpenSSH、PuTTY、Xshell 等標準終端客戶端。
* **終端排版防破版**: 選單寬度鎖定在 78 欄位安全線，全面使用 Unicode East Asian Width 算術，中英混排時邊框對齊不折行。
* **零假資料**: 無審計事件誠實顯示空清單，未巡檢主機明確標記未知，不捏造數字。
* **操作錄影與審計**: 透過雙向字元水管旁路採樣，即時將操作記錄為標準 asciinema v2 (.cast) 檔案，並落盤至資料庫。

---

## 規格與架構 (Specification)

本專案採規格導向開發 (Specification-Driven Development)。詳細架構分層、通訊協定規範與實施階段請參閱：

👉 [OpenBastion 系統架構與功能規格書 (docs/SPEC.md)](docs/SPEC.md)

---

## 研發里程碑 (Roadmap)

各階段交付計畫請參閱 [docs/ROADMAP.md](docs/ROADMAP.md)：

- [ ] **Phase 1: RFC 4253 SSH-2.0 核心通訊通道與主機金鑰管理**
- [ ] **Phase 2: 終端 TUI 78 欄位防破版選單與 PTY 刷新保證**
- [ ] **Phase 3: SQLite WAL 儲存驅動與會話生命週期管理器**
- [ ] **Phase 4: 字元水管旁路採樣、asciinema 錄影與不可變審計**
- [ ] **Phase 5: 純淨數據 Web 監控 API 與微前端管理介面**
- [ ] **Phase 6: 真實 OpenSSH 端到端黑箱驗收與正式發布**

---

## 授權條款 (License)

本專案採用 [MIT License](LICENSE) 開源發布。
