"""
OpenBastion Core - SQLite WAL 儲存驅動與會話生命週期持久層 (Storage Driver & Lifecycle Engine)
======================================================================================
依據 docs/SPEC.md §3.2 (資料儲存層) 與 Phase 3 里程碑藍圖規範。
Zero-dependency thread-safe SQLite WAL storage engine powering users, hosts, and sessions.

核心職責 / Responsibilities:
  1. SQLite WAL 模式強制啟用 (PRAGMA journal_mode = WAL) 與外鍵完整性約束。
  2. 雙層 ID 架構 (UUID 對外杜絕 IDOR 遍歷攻擊，INTEGER PRIMARY KEY 對內高效關聯)。
  3. 無實體檔案之伺服器金鑰持久化 (server_host_key 純字串存入 system_config，記憶體直載)。
  4. PBKDF2-HMAC-SHA256 (100,000 次疊代 + 16 位元組隨機 Salt) 軍規密碼加鹽雜湊。
  5. 使用者個人化偏好持久化 (preferences JSON 欄位，自動記住視圖與語系)。
  6. 開機孤兒對帳修復 (Boot Reconciliation)：自動修復異常重啟前殘留的非正常結束會話。
  7. 管理員緊急中斷連線 (Kill Switch) 與智慧現場雙人背書 (Smart Co-Signing)。
"""

import hashlib
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.i18n import t

logger = logging.getLogger("openbastion.storage")

DEFAULT_DB_PATH = Path("data/openbastion.db")
PBKDF2_ITERATIONS = 100_000


def generate_uuid(prefix: str = "") -> str:
    """
    生成不可預測之安全隨機 ID (杜絕 IDOR 遍歷漏洞)。
    Generate an unpredictable cryptographically secure UUID string to prevent IDOR enumeration.
    """
    raw_hex = uuid.uuid4().hex
    return f"{prefix}_{raw_hex}" if prefix else raw_hex


def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """
    使用 PBKDF2-HMAC-SHA256 對密碼進行加鹽雜湊運算。
    Hash password using PBKDF2-HMAC-SHA256 with 100,000 iterations and 16-byte random salt.

    回傳: (password_hash_hex, salt_hex)
    """
    salt_bytes = bytes.fromhex(salt) if salt else secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_bytes,
        PBKDF2_ITERATIONS,
    )
    return dk.hex(), salt_bytes.hex()


def verify_password(plain_password: str, password_hash: str, salt: str) -> bool:
    """
    常數時間比對密碼雜湊，杜絕時序側信道攻擊 (Timing Attack)。
    Verify password against stored hash using constant-time comparison to prevent timing attacks.
    """
    if not plain_password or not password_hash or not salt:
        return False
    try:
        calculated_hash, _ = hash_password(plain_password, salt=salt)
        return secrets.compare_digest(calculated_hash, password_hash)
    except Exception:
        return False


class StorageProvider:
    """
    執行緒安全之 SQLite WAL 核心儲存驅動。
    Thread-safe SQLite WAL core storage driver with schema lifecycle and preferences management.
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        """
        初始化儲存驅動實例並建立資料庫連線目錄與結構。
        Initialize storage provider instance and ensure database directory and schema.
        """
        self.db_path = Path(db_path or DEFAULT_DB_PATH).resolve()
        self._lock = threading.Lock()
        self._ensure_directory()
        self.init_db()

    def _ensure_directory(self) -> None:
        """
        確保資料庫所在目錄存在。
        Ensure that the parent directory for the database file exists.
        """
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _get_connection(self) -> sqlite3.Connection:
        """
        建立配置 WAL 模式與外鍵約束之連線實例。
        Create SQLite connection configured with WAL journal mode and foreign key enforcement.
        """
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=15.0,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def init_db(self) -> None:
        """
        初始化資料庫表結構、欄位遷移與查詢索引。
        Initialize database schemas, column migrations, and query indexes.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    # 0. 結構版本登記表
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS schema_version (
                            version INTEGER PRIMARY KEY,
                            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            description TEXT NOT NULL
                        );
                        """
                    )

                    # 1. 系統全域配置表 (存放無實體檔案之伺服器金鑰、全域策略)
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS system_config (
                            key TEXT PRIMARY KEY,
                            value TEXT NOT NULL,
                            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                        """
                    )

                    # 2. 使用者帳號表 (5 級 RBAC + PBKDF2 加鹽 + 動態偏好收納)
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id TEXT UNIQUE NOT NULL,
                            username TEXT UNIQUE NOT NULL,
                            password_hash TEXT NOT NULL,
                            salt TEXT NOT NULL,
                            role TEXT NOT NULL DEFAULT 'user',
                            display_name TEXT,
                            department TEXT DEFAULT 'default',
                            preferences TEXT NOT NULL DEFAULT '{}',
                            is_active INTEGER NOT NULL DEFAULT 1,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                        """
                    )
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_users_role ON users (role);")

                    # 平滑遷移檢驗：若 users 表已存在但無 preferences 欄位，自動透過 ALTER TABLE 補齊
                    cur = conn.execute("PRAGMA table_info(users);")
                    cols = {row["name"] for row in cur.fetchall()}
                    if "preferences" not in cols:
                        conn.execute("ALTER TABLE users ADD COLUMN preferences TEXT NOT NULL DEFAULT '{}';")

                    # 3. 主機資產表 (雙層 ID 防 IDOR + 78 欄位雙視圖支援)
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS hosts (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            host_id TEXT UNIQUE NOT NULL,
                            name TEXT NOT NULL,
                            host TEXT NOT NULL,
                            port INTEGER NOT NULL DEFAULT 22,
                            internal_ip TEXT,
                            system TEXT,
                            alias TEXT,
                            rack TEXT,
                            dept TEXT DEFAULT 'default',
                            group_name TEXT DEFAULT 'default',
                            status TEXT DEFAULT 'online',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                        """
                    )
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_hosts_host_id ON hosts (host_id);")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_hosts_dept ON hosts (dept);")

                    # 4. 會話生命週期記錄表 (狀態機 + 開機孤兒對帳修復)
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS sessions (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            session_id TEXT UNIQUE NOT NULL,
                            user_id TEXT NOT NULL,
                            username TEXT NOT NULL,
                            host_id TEXT,
                            client_ip TEXT NOT NULL,
                            status TEXT NOT NULL DEFAULT 'ACTIVE',
                            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            ended_at TIMESTAMP
                        );
                        """
                    )
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions (status);")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);")

                    # 寫入初始版本標記
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO schema_version (version, description)
                        VALUES (1, 'Phase 3 Baseline: system_config, users, hosts, sessions with preferences');
                        """
                    )
            finally:
                conn.close()

    # =========================================================================
    # 系統配置管理 (System Config - 無實體檔案主機金鑰)
    # =========================================================================

    def get_config(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """
        讀取系統全域配置鍵值。
        Retrieve a system configuration value by key from system_config table.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.execute("SELECT value FROM system_config WHERE key = ?;", (key,))
                row = cur.fetchone()
                return row["value"] if row else default
            finally:
                conn.close()

    def set_config(self, key: str, value: str) -> None:
        """
        寫入或更新系統全域配置鍵值。
        Insert or update a system configuration key-value pair in system_config table.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO system_config (key, value, updated_at)
                        VALUES (?, ?, CURRENT_TIMESTAMP)
                        ON CONFLICT(key) DO UPDATE SET
                            value = excluded.value,
                            updated_at = CURRENT_TIMESTAMP;
                        """,
                        (key, value),
                    )
            finally:
                conn.close()

    # =========================================================================
    # 使用者帳號、偏好設定與認證 (Users, Preferences & Authentication)
    # =========================================================================

    def count_users(self) -> int:
        """
        取得目前系統內有效使用者總數。
        Count and return the total number of active users in the system.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.execute("SELECT COUNT(*) AS total FROM users;")
                return int(cur.fetchone()["total"])
            finally:
                conn.close()

    def create_user(
        self,
        username: str,
        password: str,
        role: str = "user",
        display_name: Optional[str] = None,
        department: str = "default",
        preferences: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        建立新使用者帳號 (密碼自動加鹽雜湊並建立動態偏好)。
        Create a new user account with PBKDF2 hashed password and default preferences.
        """
        pwd_hash, salt = hash_password(password)
        u_id = generate_uuid("user")
        prefs_json = json.dumps(preferences or {"view": "system", "locale": "zh_TW"}, ensure_ascii=False)
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO users (
                            user_id, username, password_hash, salt,
                            role, display_name, department, preferences, is_active
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1);
                        """,
                        (u_id, username, pwd_hash, salt, role, display_name or username, department, prefs_json),
                    )
                return {
                    "user_id": u_id,
                    "username": username,
                    "role": role,
                    "display_name": display_name or username,
                    "department": department,
                    "preferences": json.loads(prefs_json),
                }
            finally:
                conn.close()

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """
        依帳號名稱查詢使用者詳細資料。
        Retrieve detailed user account record by unique username.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.execute(
                    """
                    SELECT id, user_id, username, password_hash, salt,
                           role, display_name, department, preferences, is_active, created_at
                    FROM users
                    WHERE username = ?;
                    """,
                    (username,),
                )
                row = cur.fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        依公開識別碼 (user_id) 查詢使用者資料。
        Retrieve detailed user account record by unique public user_id.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.execute(
                    """
                    SELECT id, user_id, username, password_hash, salt,
                           role, display_name, department, preferences, is_active, created_at
                    FROM users
                    WHERE user_id = ?;
                    """,
                    (user_id,),
                )
                row = cur.fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def get_user_preferences(self, user_id: str) -> Dict[str, Any]:
        """
        讀取使用者動態偏好設定字典 (自動帶預設兜底值)。
        Retrieve dynamic user preferences dictionary with fallback default values.
        """
        user = self.get_user_by_id(user_id)
        if not user or not user.get("preferences"):
            return {"view": "system", "locale": "zh_TW"}
        try:
            prefs = json.loads(user["preferences"])
            return {
                "view": prefs.get("view", "system"),
                "locale": prefs.get("locale", "zh_TW"),
            }
        except Exception:
            return {"view": "system", "locale": "zh_TW"}

    def update_user_preference(self, user_id: str, key: str, value: Any) -> None:
        """
        更新特定使用者的單項偏好設定並非同步持久化至資料庫。
        Update a single preference key-value pair for a user and persist to database.
        """
        current_prefs = self.get_user_preferences(user_id)
        current_prefs[key] = value
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        "UPDATE users SET preferences = ? WHERE user_id = ?;",
                        (json.dumps(current_prefs, ensure_ascii=False), user_id),
                    )
            finally:
                conn.close()

    def authenticate(self, username: str, plain_password: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        驗證使用者登入憑證是否有效。
        Authenticate user login credentials using PBKDF2 constant-time comparison.
        """
        user = self.get_user_by_username(username)
        if not user:
            return False, None

        if not user.get("is_active", 0):
            logger.warning("[AUTH] 使用者 '%s' 帳號已被停用", username)
            return False, None

        if verify_password(plain_password, user["password_hash"], user["salt"]):
            return True, user
        return False, None

    def bootstrap_admin_if_empty(self) -> Optional[Dict[str, str]]:
        """
        開機安全引導：若系統無任何使用者，生成一組隨機強密碼管理員。
        Bootstrap initial admin account with random password if no users exist in the database.
        """
        if self.count_users() > 0:
            return None

        raw_password = secrets.token_urlsafe(12)
        admin_user = self.create_user(
            username="admin",
            password=raw_password,
            role="admin",
            display_name="系統初始管理員",
            department="IT",
        )
        return {
            "username": admin_user["username"],
            "password": raw_password,
            "user_id": admin_user["user_id"],
        }

    def list_active_managers_and_admins(self, exclude_username: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        查詢除特定使用者以外的所有活躍管理人員 (admin / manager)，用於雙人背書判定。
        List active administrators and managers excluding a specific username for dual authorization.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                if exclude_username:
                    cur = conn.execute(
                        """
                        SELECT id, user_id, username, role, display_name, department
                        FROM users
                        WHERE role IN ('admin', 'manager') AND is_active = 1 AND username != ?
                        ORDER BY id ASC;
                        """,
                        (exclude_username,),
                    )
                else:
                    cur = conn.execute(
                        """
                        SELECT id, user_id, username, role, display_name, department
                        FROM users
                        WHERE role IN ('admin', 'manager') AND is_active = 1
                        ORDER BY id ASC;
                        """
                    )
                return [dict(r) for r in cur.fetchall()]
            finally:
                conn.close()

    def reset_admin_password(self, new_password: str) -> bool:
        """
        重設系統管理員 (admin) 密碼，若帳號不存在則自動補建。
        Reset or provision the admin account password with new salt and PBKDF2 hash.
        """
        pwd_hash, salt = hash_password(new_password)
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    # 檢查 admin 是否存在
                    cur = conn.execute("SELECT user_id FROM users WHERE username = 'admin';")
                    row = cur.fetchone()
                    if row:
                        conn.execute(
                            """
                            UPDATE users
                            SET password_hash = ?, salt = ?, is_active = 1
                            WHERE username = 'admin';
                            """,
                            (pwd_hash, salt),
                        )
                    else:
                        u_id = generate_uuid("user")
                        conn.execute(
                            """
                            INSERT INTO users (
                                user_id, username, password_hash, salt,
                                role, display_name, department, preferences, is_active
                            ) VALUES (?, 'admin', ?, ?, 'admin', '系統管理員', 'IT', '{}', 1);
                            """,
                            (u_id, pwd_hash, salt),
                        )
                return True
            except Exception as e:
                logger.error("重設管理員密碼失敗: %s", e)
                return False
            finally:
                conn.close()

    # =========================================================================
    # 主機資產管理 (Host Assets)
    # =========================================================================

    def add_host(
        self,
        name: str,
        host: str,
        port: int = 22,
        internal_ip: Optional[str] = None,
        system: Optional[str] = None,
        alias: Optional[str] = None,
        rack: Optional[str] = None,
        dept: str = "default",
        group_name: str = "default",
        status: str = "online",
    ) -> Dict[str, Any]:
        """
        新增主機資產記錄 (自動生成 host_<uuid> 對外識別碼)。
        Add a new host asset record with auto-generated host_<uuid> identifier.
        """
        h_id = generate_uuid("host")
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO hosts (
                            host_id, name, host, port, internal_ip,
                            system, alias, rack, dept, group_name, status
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (h_id, name, host, port, internal_ip or host, system or "-", alias or name, rack or "-", dept, group_name, status),
                    )
                return {
                    "host_id": h_id,
                    "name": name,
                    "host": host,
                    "port": port,
                    "internal_ip": internal_ip or host,
                    "system": system,
                    "alias": alias or name,
                    "rack": rack,
                    "dept": dept,
                    "status": status,
                }
            finally:
                conn.close()

    def list_hosts(self, role: str = "admin", department: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        依角色身分與部門維度過濾查詢主機資產清單。
        Filter and list host assets based on RBAC role and organizational department.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                if role in ("admin", "auditor"):
                    cur = conn.execute(
                        """
                        SELECT id, host_id, name, host, port, internal_ip,
                               system, alias, rack, dept, group_name, status
                        FROM hosts
                        ORDER BY id ASC;
                        """
                    )
                elif role == "manager" and department:
                    cur = conn.execute(
                        """
                        SELECT id, host_id, name, host, port, internal_ip,
                               system, alias, rack, dept, group_name, status
                        FROM hosts
                        WHERE dept = ? OR dept = 'default'
                        ORDER BY id ASC;
                        """,
                        (department,),
                    )
                else:
                    dept_filter = department or "default"
                    cur = conn.execute(
                        """
                        SELECT id, host_id, name, host, port, internal_ip,
                               system, alias, rack, dept, group_name, status
                        FROM hosts
                        WHERE dept = ? OR dept = 'default'
                        ORDER BY id ASC;
                        """,
                        (dept_filter,),
                    )
                rows = cur.fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    # =========================================================================
    # 會話生命週期與開機孤兒修復 (Sessions & Reconciliation)
    # =========================================================================

    def create_session(
        self,
        user_id: str,
        username: str,
        client_ip: str,
        host_id: Optional[str] = None,
    ) -> str:
        """
        建立新連線會話紀錄，回傳唯一 session_id (sess_<uuid>)。
        Create a new active session record and return unique session_id.
        """
        s_id = generate_uuid("sess")
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO sessions (
                            session_id, user_id, username, host_id, client_ip, status
                        ) VALUES (?, ?, ?, ?, ?, 'ACTIVE');
                        """,
                        (s_id, user_id, username, host_id, client_ip),
                    )
                return s_id
            finally:
                conn.close()

    def close_session(self, session_id: str) -> None:
        """
        正常關閉活躍會話記錄 (狀態由 ACTIVE 轉為 CLOSED)。
        Close an active session record normally, setting status to CLOSED and recording end time.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        UPDATE sessions
                        SET status = 'CLOSED', ended_at = CURRENT_TIMESTAMP
                        WHERE session_id = ? AND status = 'ACTIVE';
                        """,
                        (session_id,),
                    )
            finally:
                conn.close()

    def kill_session(self, session_id: str) -> bool:
        """
        管理員緊急中斷會話 (狀態由 ACTIVE 轉為 KILLED)。
        Terminate session forcefully by administrator and update status to KILLED.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    cur = conn.execute(
                        """
                        UPDATE sessions
                        SET status = 'KILLED', ended_at = CURRENT_TIMESTAMP
                        WHERE session_id = ? AND status = 'ACTIVE';
                        """,
                        (session_id,),
                    )
                    return cur.rowcount > 0
            finally:
                conn.close()

    def list_active_sessions(self) -> List[Dict[str, Any]]:
        """
        列出當前系統中所有處於活躍狀態 (ACTIVE) 的連線會話清單。
        List all currently active sessions sorted by start timestamp.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.execute(
                    """
                    SELECT session_id, user_id, username, client_ip, started_at
                    FROM sessions
                    WHERE status = 'ACTIVE'
                    ORDER BY started_at DESC;
                    """
                )
                return [dict(r) for r in cur.fetchall()]
            finally:
                conn.close()

    def reconcile_orphan_sessions(self) -> int:
        """
        開機孤兒對帳修復：將異常重啟前遺留的 ACTIVE 會話修復為 ABRUPT。
        Reconcile orphan active sessions after unexpected reboot, updating their status to ABRUPT.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    cur = conn.execute(
                        """
                        UPDATE sessions
                        SET status = 'ABRUPT', ended_at = CURRENT_TIMESTAMP
                        WHERE status = 'ACTIVE';
                        """
                    )
                    count = cur.rowcount
                    if count > 0:
                        logger.warning(
                            "[RECONCILE] 開機對帳修復：已將 %d 筆因前次異常關機中斷之會話標記為 ABRUPT", count
                        )
                    return count
            finally:
                conn.close()
