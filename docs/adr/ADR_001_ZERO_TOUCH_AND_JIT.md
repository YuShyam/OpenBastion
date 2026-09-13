# ADR-001: 零侵入架構分級與 JIT 帳號治理標準
# Architectural Decision Record: Zero-Touch Tiers & JIT Account Governance

> **狀態 (Status)**: 已核准 (Approved)  
> **日期 (Date)**: 2026-09-13  
> **參與人員 (Participants)**: 架構者、Tech Lead、資安審查專員、SRE 維運人員、Linux 協定工程師  
> **適用範圍 (Scope)**: OpenBastion 連線轉發與目標主機帳號管理架構  

---

## 摘要 (Summary)

這份文件記錄 OpenBastion 對於「零侵入 (Agentless / Zero-Touch)」與「動態開通 (JIT, Just-In-Time)」的技術定義與實作標準。

過去討論跳板機時，常把「受控主機免裝 Agent」字面理解為「受控主機不能有本機帳號」，進而退回到「多人共用單一帳號 (如 `ubuntu`、`root`)」的作法。然而，共用帳號會導致系統日誌無法追查特定自然人，且連線者之間可以在 `/proc` 互相查看記憶體與行程，存在橫向移動風險。

本文件確立 **三個層級的零侵入架構**，並將業界最佳實務標準化為第三層規範：以 **SSH CA 短期憑證 + JIT 帳號密碼鎖定 (`usermod -L`) + 動態 `/etc/sudoers.d/` 權限派發** 處理身分與權限隔離。

This document defines OpenBastion's architectural standards for "Zero-Touch / Agentless" access and Just-In-Time (JIT) account governance. It addresses the practical flaws of shared accounts (lack of non-repudiation, lateral movement risks) by introducing a three-tier model supported by SSH CA certificates and dynamic POSIX privilege management.

---

## 一、 問題背景 (Problem Statement)

### 1. 教條式零侵入的限制
若要求跳板機對目標主機「完全不建立任何本機帳號」，跳板機只能將所有使用者映射至目標主機預先存在的共用帳號（例如固定使用 `app_admin` 或 `ubuntu`）。

### 2. 共用帳號帶來的維運與安全問題
在實務環境中，共用帳號主要存在以下缺陷：
1. **日誌責任無法對應到個人**：
   * 目標系統的 `auditd`、`syslog` 與 `journalctl` 記錄的操作者只有一個 UID（如 UID=1000）。
   * 當發生非預期檔案變更或配置異常時，本機記錄無法直接指認是哪一位連線者執行的動作。
2. **行程窺探與橫向移動風險**：
   * 相同 UID 的使用者具備讀取彼此 `/proc/$PID/mem` 與環境變數的權限，容易取得其他工程師正在使用的連線 Token 或暫存資料。
3. **人工維護成本過高**：
   * 若不用共用帳號，改由管理員手動至數十台機器逐一建立、修改並關閉個人帳號，不僅耗費時間，也容易遺漏未清理的過期帳號。

---

## 二、 零侵入架構的三個層級 (Three Tiers of Zero-Touch Architecture)

OpenBastion 依據目標主機的受控程度與稽核要求，提供三種模式：

```
+-----------------------------------------------------------------------------+
|                     OpenBastion 存取架構分級說明                            |
+-----------------------------------------------------------------------------+
| Level 1: 協定代理模式 (Pure Protocol Proxy)                                 |
|   - 目標主機改動: 0 改動 (不建帳號、不改檔案、不安裝額外程式)                |
|   - 運作機制: 沿用目標端現有帳號，跳板機僅轉發 Port 22 字元流與錄影          |
|   - 適用情境: 網路設備 (交換機/路由器)、黑盒子設備、無 Root 權限之外包主機  |
+-----------------------------------------------------------------------------+
| Level 2: 憑證免密模式 (CA-Based Agentless)                                  |
|   - 目標主機改動: 僅初始納管加入一行 (TrustedUserCAKeys /etc/ssh/cas.pub)    |
|   - 運作機制: 發行 5 分鐘短期 SSH CA 憑證，不留私鑰，日常不改動 sshd 設定    |
|   - 適用情境: 一般企業內網 Linux 伺服器群                                   |
+-----------------------------------------------------------------------------+
| Level 3: JIT 帳號動態治理 (JIT Provisioning & RBAC)                         |
|   - 目標主機改動: 不裝 Agent，連線前透過 SSH 建立獨立 UID 與 Sudoers 設定    |
|   - 運作機制: 密碼維持鎖定 (usermod -L)，只認 CA 憑證；登出保留帳號與目錄    |
|   - 權限管理: 透過 /etc/sudoers.d/ 調整角色權限，即時生效，不需重啟服務      |
|   - 適用情境: 高資安合規需求、需嚴格隔離行程與防止橫向移動的核心主機        |
+-----------------------------------------------------------------------------+
```

### 分級使用指引 (Usage Guidelines)

* **Level 1 (協定代理)**：
  在無法變更目標系統檔案的環境下使用。跳板機提供連線控制、asciinema 錄影與指令過濾，目標端維持原生狀態。
* **Level 2 (憑證免密)**：
  標準 Linux 主機的基礎模式。省去分發 `.ssh/authorized_keys` 的繁瑣工作，避免公私鑰到處殘留。
* **Level 3 (JIT 帳號動態治理 - POSIX 原生標準)**：
  兼顧「受控端免裝常駐程式」與「本機 UID 隔離」。跳板機在連線建立時調用原生指令維護帳號與權限，離線時保持帳號鎖定。

---

## 三、 技術實作規範與安全邊界 (Implementation Standards & Boundaries)

### 1. 主機模式欄位 (Host Provisioning Field)
資料庫 `hosts` 表保留模式設定欄位：
```sql
ALTER TABLE hosts ADD COLUMN provision_mode TEXT DEFAULT 'direct';
-- 'direct': 採用 Level 1 或 Level 2 (純連線轉發，不建立本機帳號)
-- 'jit':    採用 Level 3 (連線時自動確認獨立帳號與對應 Sudoers 權限)
```

### 2. 目標主機互動限制 (Target Boundary Rules)
在 Level 3 運作時，跳板機嚴格遵守以下限制，避免破壞目標系統穩定：
1. **不安裝常駐背景服務**：目標主機不執行任何 OpenBastion 專屬的 daemon 或 agent。
2. **不開啟額外通訊埠**：目標端僅使用標準 SSH Port 22，不增加對外監聽服務。
3. **日常連線不修改 `sshd_config`**：納管設定完成後，日常連線不變更 SSH 設定檔，亦不執行 `kill -HUP sshd`，確保現有服務不受影響。
4. **不使用固定密碼**：JIT 建立的帳號一律執行 `usermod -L` 鎖定密碼，杜絕密碼猜測攻擊，僅接受有效期限內的 SSH CA 憑證。

### 3. Sudoers 權限動態調整 (Dynamic Privilege Adjustment)
使用者職務輪調時（例如從系統管理員轉為日誌檢視人員），權限異動依循以下流程：
* 跳板機連線前，依據最新身分覆寫目標端 `/etc/sudoers.d/bastion_{username}`：
  * **管理員**：`{username} ALL=(ALL) NOPASSWD: ALL`
  * **日誌檢視者**：`{username} ALL=(ALL) NOPASSWD: /usr/bin/journalctl, /usr/bin/tail /var/log/*`
  * **一般使用者 (無 sudo)**：直接移除該設定檔。
* `sudo` 指令每次執行時皆會重新讀取該目錄，設定變更即時生效，不需重啟任何系統服務。

### 4. 帳號保留與過期巡檢 (UID Retention & Cleanup)
* 連線結束時保留本機帳號與 Home 目錄，避免重複登入導致 UID 數字跳動及舊檔案權限孤立。
* 跳板機定期巡檢超過設定期限（例如 90 天）未使用的 JIT 帳號，執行封存標記並安全清理，避免閒置帳號累積。

---

## 四、 稽核規範對照 (Compliance Reference)

| 規範項目 | 條文要求 | 共用帳號模式 | Level 3 JIT 模式 |
| :--- | :--- | :--- | :--- |
| **PCI-DSS v4.0 (8.2.1)** | 存取系統必須具備獨立識別碼 | ❌ 不符合 (多人共用 UID) | ✅ 符合 (具備獨立 UID) |
| **PCI-DSS v4.0 (8.3.6)** | 帳號需具備適當防護，防止未授權存取 | ⚠️ 需額外管控共用密碼或金鑰 | ✅ 符合 (密碼鎖定，憑證驗證) |
| **ISO/IEC 27001 (A.9.2)** | 權限配置需符合最小特權原則 | ❌ 不符合 (難以隨職務調整) | ✅ 符合 (Sudoers 動態收放) |
| **CIS Linux Benchmark** | 避免未綁定人員之泛用管理帳號 | ❌ 不符合 | ✅ 符合 (會話對應明確) |

---

## 五、 結論 (Conclusion)

1. 「零侵入」重點在於受控端不需維護專屬背景軟體與連線通訊埠；在需要責任歸屬的環境下，配合原生 JIT 帳號維護與密碼鎖定，是兼顧安全與維運的可行解法。
2. 整合標準 POSIX 原生 JIT 帳號建立、密碼強制鎖定、Sudo 角色動態收放與閒置巡檢機制，確立為 OpenBastion 的 Level 3 核心實作規格。
3. 後續程式碼與功能規劃，均以本文件定義之三層架構為設計依據。
