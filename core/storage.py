"""
OpenBastion Core - SQLite WAL 儲存驅動與會話生命週期持久層 (Storage Driver & Lifecycle Engine)
======================================================================================
依據 docs/SPEC.md §3.2 (資料儲存層) 與 Phase 3 里程碑藍圖規範。
Zero-dependency thread-safe SQLite WAL storage engine powering users, hosts, and sessions.

核心職責 / Responsibilities:
  1. SQLite WAL 模式強制啟用 (PRAGMA journal_mode = WAL) 與外鍵完整性約束。
  2. 雙層 ID 架構 (UUID 對外杜絕 IDOR 遍歷攻擊，INTEGER PRIMARY KEY 對內高效關聯)。
  3. 無實體檔案之伺服器金鑰持久化 (server_host_key 純字串存入 system_config，記憶體直載)。
  4. PBKDF2-HMAC-SHA256 (100,000 次疊代 + 16 位元組隨機 Salt) 密碼加鹽雜湊。
  5. 使用者個人化偏好持久化 (preferences JSON 欄位，自動記住視圖與語系)。
  6. 開機孤兒對帳修復 (Boot Reconciliation)：自動修復異常重啟前殘留的非正常結束會話。
  7. 管理員緊急中斷連線 (Kill Switch) 與現場雙人覆核 (Co-Signing)。
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
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.i18n import t

logger = logging.getLogger("openbastion.storage")

DEFAULT_DB_PATH = Path("data/openbastion.db")
PBKDF2_ITERATIONS = 100_000


def generate_uuid(prefix: str = "") -> str:
    """
    生成符合動靜分離與時序排序 (K-Sortable) 規範之安全隨機 ID (杜絕 IDOR 遍歷漏洞)。
    Generate cryptographically secure IDs adhering to static/dynamic separation and K-sortable standards.
    - 靜態資產 (host, user): 12 碼十六進位純隨機 (總長 17 碼)
    - 動態時序 (sess, cmd): 西元 4 碼日期 + 12 碼十六進位 (總長 24~25 碼)
    """
    raw_hex = uuid.uuid4().hex[:12]
    now_date = datetime.now().strftime("%Y%m%d")
    if prefix in ("sess", "session"):
        return f"sess_{now_date}_{raw_hex}"
    elif prefix in ("cmd", "audit", "command"):
        return f"cmd_{now_date}_{raw_hex}"
    elif prefix in ("host", "h"):
        return f"host_{raw_hex}"
    elif prefix in ("user", "u"):
        return f"user_{raw_hex}"
    elif prefix:
        return f"{prefix}_{raw_hex}"
    return raw_hex


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

                    # 1.5 組織部門實體表 (樹狀組織架構支援)
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS departments (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            name TEXT UNIQUE NOT NULL,
                            code TEXT UNIQUE NOT NULL,
                            parent_id INTEGER,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (parent_id) REFERENCES departments (id)
                        );
                        """
                    )
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_departments_code ON departments (code);")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_departments_name ON departments (name);")

                    # 2. 使用者帳號表 (5 級 RBAC + PBKDF2 加鹽 + 動態偏好收納 + 組織關聯)
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id TEXT UNIQUE NOT NULL,
                            username TEXT UNIQUE NOT NULL,
                            password_hash TEXT NOT NULL,
                            salt TEXT NOT NULL,
                            role TEXT NOT NULL DEFAULT 'user',
                            display_name TEXT DEFAULT '',
                            department TEXT DEFAULT '',
                            department_id INTEGER,
                            preferences TEXT NOT NULL DEFAULT '{}',
                            is_active INTEGER NOT NULL DEFAULT 1,
                            created_by TEXT DEFAULT 'system',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            updated_by TEXT DEFAULT '',
                            updated_at TIMESTAMP,
                            FOREIGN KEY (department_id) REFERENCES departments (id)
                        );
                        """
                    )
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_users_role ON users (role);")

                    # 平滑遷移檢驗：若 users 表已存在但無相關欄位，自動透過 ALTER TABLE 補齊
                    cur = conn.execute("PRAGMA table_info(users);")
                    cols = {row["name"] for row in cur.fetchall()}
                    if "preferences" not in cols:
                        conn.execute("ALTER TABLE users ADD COLUMN preferences TEXT NOT NULL DEFAULT '{}';")
                    if "department_id" not in cols:
                        conn.execute("ALTER TABLE users ADD COLUMN department_id INTEGER;")
                    if "created_by" not in cols:
                        conn.execute("ALTER TABLE users ADD COLUMN created_by TEXT DEFAULT 'system';")
                    if "updated_by" not in cols:
                        conn.execute("ALTER TABLE users ADD COLUMN updated_by TEXT DEFAULT '';")
                    if "updated_at" not in cols:
                        conn.execute("ALTER TABLE users ADD COLUMN updated_at TIMESTAMP;")

                    # 3. 主機資產表 (雙層 ID 防 IDOR + 78 欄位雙視圖支援 + 組織關聯)
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS hosts (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            host_id TEXT UNIQUE NOT NULL,
                            name TEXT NOT NULL,
                            host TEXT NOT NULL,
                            port INTEGER NOT NULL DEFAULT 22,
                            internal_ip TEXT DEFAULT '',
                            system TEXT DEFAULT '',
                            alias TEXT DEFAULT '',
                            rack TEXT DEFAULT '',
                            dept TEXT DEFAULT '',
                            department_id INTEGER,
                            group_name TEXT DEFAULT '',
                            status TEXT DEFAULT 'offline',
                            provision_mode TEXT DEFAULT 'direct',
                            default_user TEXT DEFAULT '{username}',
                            auth_type TEXT DEFAULT 'key',
                            credential_encrypted TEXT,
                            created_by TEXT DEFAULT 'system',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            updated_by TEXT DEFAULT '',
                            updated_at TIMESTAMP,
                            FOREIGN KEY (department_id) REFERENCES departments (id)
                        );
                        """
                    )
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_hosts_host_id ON hosts (host_id);")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_hosts_dept ON hosts (dept);")

                    # 平滑遷移檢驗：若 hosts 表已存在但無相關欄位，自動透過 ALTER TABLE 補齊
                    cur = conn.execute("PRAGMA table_info(hosts);")
                    h_cols = {row["name"] for row in cur.fetchall()}
                    if "provision_mode" not in h_cols:
                        conn.execute("ALTER TABLE hosts ADD COLUMN provision_mode TEXT DEFAULT 'direct';")
                    if "default_user" not in h_cols:
                        conn.execute("ALTER TABLE hosts ADD COLUMN default_user TEXT DEFAULT '{username}';")
                    if "auth_type" not in h_cols:
                        conn.execute("ALTER TABLE hosts ADD COLUMN auth_type TEXT DEFAULT 'key';")
                    if "credential_encrypted" not in h_cols:
                        conn.execute("ALTER TABLE hosts ADD COLUMN credential_encrypted TEXT;")
                    if "department_id" not in h_cols:
                        conn.execute("ALTER TABLE hosts ADD COLUMN department_id INTEGER;")
                    if "created_by" not in h_cols:
                        conn.execute("ALTER TABLE hosts ADD COLUMN created_by TEXT DEFAULT 'system';")
                    if "updated_by" not in h_cols:
                        conn.execute("ALTER TABLE hosts ADD COLUMN updated_by TEXT DEFAULT '';")
                    if "updated_at" not in h_cols:
                        conn.execute("ALTER TABLE hosts ADD COLUMN updated_at TIMESTAMP;")

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

                    # 5. 僅追加審計日誌表 (Append-Only Audit Trail with K-Sortable audit_id)
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS audit_logs (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            audit_id TEXT UNIQUE,
                            session_id TEXT NOT NULL,
                            user_id TEXT NOT NULL,
                            username TEXT NOT NULL,
                            host_id TEXT NOT NULL,
                            host_ip TEXT DEFAULT '',
                            host_name TEXT DEFAULT '',
                            event_type TEXT NOT NULL,
                            command_raw TEXT,
                            command_clean TEXT,
                            action_taken TEXT NOT NULL DEFAULT 'LOG',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                        """
                    )
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_logs (session_id);")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs (user_id);")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_host ON audit_logs (host_id);")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs (created_at);")

                    # 平滑遷移檢驗：若 audit_logs 表已存在但無 audit_id / host_ip / host_name 欄位，自動補齊
                    cur = conn.execute("PRAGMA table_info(audit_logs);")
                    a_cols = {row["name"] for row in cur.fetchall()}
                    if "audit_id" not in a_cols:
                        conn.execute("ALTER TABLE audit_logs ADD COLUMN audit_id TEXT;")
                    if "host_ip" not in a_cols:
                        conn.execute("ALTER TABLE audit_logs ADD COLUMN host_ip TEXT DEFAULT '';")
                    if "host_name" not in a_cols:
                        conn.execute("ALTER TABLE audit_logs ADD COLUMN host_name TEXT DEFAULT '';")
                    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_id ON audit_logs (audit_id);")

                    # 6. 會話錄影紀錄表 (asciinema v2 Metadata)
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS recordings (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            session_id TEXT UNIQUE NOT NULL,
                            file_path TEXT NOT NULL,
                            file_size INTEGER NOT NULL DEFAULT 0,
                            sha256_hash TEXT NOT NULL,
                            duration_seconds REAL NOT NULL DEFAULT 0.0,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                        """
                    )
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_recordings_session ON recordings (session_id);")

                    # 寫入版本標記
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO schema_version (version, description)
                        VALUES (1, 'Phase 3 Baseline: system_config, users, hosts, sessions with preferences');
                        """
                    )
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO schema_version (version, description)
                        VALUES (2, 'Phase 4: audit_logs, recordings, and host provision_mode credentials');
                        """
                    )
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO schema_version (version, description)
                        VALUES (3, 'Phase 5: departments table and zero magic defaults');
                        """
                    )
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO schema_version (version, description)
                        VALUES (4, 'Phase 6: audit_logs audit_id/host_ip/host_name, hosts/users lifecycle metadata');
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
    # 組織架構與部門實體管理 (Departments & Organizational Hierarchy)
    # =========================================================================

    def create_department(
        self,
        name: str,
        code: str,
        parent_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        建立新組織部門節點。
        Create a new department node in the organization hierarchy.
        """
        clean_name = name.strip()
        clean_code = code.strip().lower()
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    cur = conn.execute(
                        """
                        INSERT INTO departments (name, code, parent_id)
                        VALUES (?, ?, ?);
                        """,
                        (clean_name, clean_code, parent_id),
                    )
                    dept_id = cur.lastrowid
                return {
                    "id": dept_id,
                    "name": clean_name,
                    "code": clean_code,
                    "parent_id": parent_id,
                }
            finally:
                conn.close()

    def get_department_by_id(self, dept_id: int) -> Optional[Dict[str, Any]]:
        """
        透過 ID 查詢部門實體。
        Query department entity record by its unique database ID.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.execute(
                    "SELECT id, name, code, parent_id, created_at FROM departments WHERE id = ?;",
                    (dept_id,),
                )
                row = cur.fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def get_department_by_code(self, code: str) -> Optional[Dict[str, Any]]:
        """
        透過 code 唯一代碼查詢部門實體。
        Query department entity record by its unique department code.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.execute(
                    "SELECT id, name, code, parent_id, created_at FROM departments WHERE code = ?;",
                    (code.strip().lower(),),
                )
                row = cur.fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def get_department_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """
        透過名稱查詢部門實體。
        Query department entity record by its name string.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.execute(
                    "SELECT id, name, code, parent_id, created_at FROM departments WHERE name = ?;",
                    (name.strip(),),
                )
                row = cur.fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def list_departments(self) -> List[Dict[str, Any]]:
        """
        查詢系統內所有組織部門清單。
        List all organizational departments ordered by ID ascending.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.execute("SELECT id, name, code, parent_id, created_at FROM departments ORDER BY id ASC;")
                return [dict(r) for r in cur.fetchall()]
            finally:
                conn.close()

    def ensure_department(
        self,
        name: str,
        code: Optional[str] = None,
        parent_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        冪等確保部門存在：若已存在則直接回傳，若不存在則自動建立。
        Idempotently ensure department exists; return existing or create new.
        """
        existing = self.get_department_by_name(name)
        if existing:
            return existing
        dept_code = (code or name).strip().lower().replace(" ", "-")
        if self.get_department_by_code(dept_code):
            dept_code = f"{dept_code}-{secrets.token_hex(2)}"
        return self.create_department(name=name, code=dept_code, parent_id=parent_id)

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
        display_name: str = "",
        department: str = "",
        department_id: Optional[int] = None,
        preferences: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        建立新使用者帳號 (密碼自動加鹽雜湊並建立動態偏好，未指定資訊嚴格存為空值)。
        Create a new user account with PBKDF2 hashed password and zero magic defaults.
        """
        pwd_hash, salt = hash_password(password)
        u_id = generate_uuid("user")
        prefs_json = json.dumps(preferences or {"view": "system", "locale": "zh_TW"}, ensure_ascii=False)
        clean_display = (display_name or "").strip()
        clean_dept = (department or "").strip()

        # 若有指定部門文字但未傳入 department_id，嘗試自動掛接
        if clean_dept and department_id is None:
            dept_entity = self.get_department_by_name(clean_dept)
            if dept_entity:
                department_id = dept_entity["id"]

        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO users (
                            user_id, username, password_hash, salt,
                            role, display_name, department, department_id, preferences, is_active
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1);
                        """,
                        (u_id, username.strip(), pwd_hash, salt, role, clean_display, clean_dept, department_id, prefs_json),
                    )
                return {
                    "user_id": u_id,
                    "username": username.strip(),
                    "role": role,
                    "display_name": clean_display,
                    "department": clean_dept,
                    "department_id": department_id,
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
                           role, display_name, department, department_id, preferences, is_active, created_at
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
                           role, display_name, department, department_id, preferences, is_active, created_at
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
            logger.warning("[AUTH] 使用者 '%s' 帳號已被停用 (User account is disabled)", username)
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

        it_dept = self.ensure_department(name="IT", code="it")
        raw_password = secrets.token_urlsafe(12)
        admin_user = self.create_user(
            username="admin",
            password=raw_password,
            role="admin",
            display_name="系統初始管理員",
            department="IT",
            department_id=it_dept["id"],
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
                        SELECT id, user_id, username, role, display_name, department, department_id
                        FROM users
                        WHERE role IN ('admin', 'manager') AND is_active = 1 AND username != ?
                        ORDER BY id ASC;
                        """,
                        (exclude_username,),
                    )
                else:
                    cur = conn.execute(
                        """
                        SELECT id, user_id, username, role, display_name, department, department_id
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
        it_dept = self.ensure_department(name="IT", code="it")
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
                                role, display_name, department, department_id, preferences, is_active
                            ) VALUES (?, 'admin', ?, ?, 'admin', '系統管理員', 'IT', ?, '{}', 1);
                            """,
                            (u_id, pwd_hash, salt, it_dept["id"]),
                        )
                return True
            except Exception as e:
                logger.error("[STORAGE_ERROR] 重設管理員密碼失敗: %s (Failed to reset admin password: %s)", e, e)
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
        internal_ip: str = "",
        system: str = "",
        alias: str = "",
        rack: str = "",
        dept: str = "",
        department_id: Optional[int] = None,
        group_name: str = "",
        status: str = "offline",
        provision_mode: str = "direct",
        default_user: str = "{username}",
        auth_type: str = "key",
        credential_encrypted: Optional[str] = None,
        created_by: str = "system",
    ) -> Dict[str, Any]:
        """
        新增主機資產記錄 (自動生成 host_<uuid> 對外識別碼，嚴格落實零魔術預設值)。
        Add a new host asset record with auto-generated host_<uuid> and zero magic defaults.
        """
        h_id = generate_uuid("host")
        internal_ip_val = (internal_ip or "").strip()
        system_val = (system or "").strip()
        alias_val = (alias or "").strip()
        rack_val = (rack or "").strip()
        dept_val = (dept or "").strip()
        group_val = (group_name or "").strip()
        status_val = (status or "offline").strip()
        created_by_val = (created_by or "system").strip()

        # 若有指定部門名稱但未提供 department_id，嘗試自動掛聯
        if dept_val and department_id is None:
            d_entity = self.get_department_by_name(dept_val)
            if d_entity:
                department_id = d_entity["id"]

        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO hosts (
                            host_id, name, host, port, internal_ip,
                            system, alias, rack, dept, department_id, group_name, status,
                            provision_mode, default_user, auth_type, credential_encrypted,
                            created_by
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            h_id, name.strip(), host.strip(), port, internal_ip_val,
                            system_val, alias_val, rack_val, dept_val, department_id,
                            group_val, status_val, provision_mode, default_user, auth_type,
                            credential_encrypted, created_by_val,
                        ),
                    )
                return {
                    "host_id": h_id,
                    "name": name.strip(),
                    "host": host.strip(),
                    "port": port,
                    "internal_ip": internal_ip_val,
                    "system": system_val,
                    "alias": alias_val,
                    "rack": rack_val,
                    "dept": dept_val,
                    "department_id": department_id,
                    "group_name": group_val,
                    "status": status_val,
                    "provision_mode": provision_mode,
                    "default_user": default_user,
                    "auth_type": auth_type,
                    "credential_encrypted": credential_encrypted,
                    "created_by": created_by_val,
                }
            finally:
                conn.close()

    def get_host_by_endpoint(self, host: str, port: int = 22) -> Optional[Dict[str, Any]]:
        """
        依據主機端點 (host, port) 檢索主機，用於登錄前防重複唯一性檢核。
        Query host asset record by network endpoint (host, port) for uniqueness pre-flight checks.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.execute(
                    """
                    SELECT id, host_id, name, host, port, internal_ip,
                           system, alias, rack, dept, department_id, group_name, status,
                           provision_mode, default_user, auth_type, credential_encrypted,
                           created_by, created_at
                    FROM hosts
                    WHERE host = ? AND port = ?
                    LIMIT 1;
                    """,
                    (host.strip(), int(port)),
                )
                row = cur.fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def get_host_by_index(
        self,
        index: int,
        role: str = "admin",
        department: str = "",
    ) -> Optional[Dict[str, Any]]:
        """
        依據選單序號 (1-based index) 檢索目標主機。
        Retrieve target host by 1-based menu index.
        """
        hosts = self.list_hosts(role=role, department=department)
        if 1 <= index <= len(hosts):
            return hosts[index - 1]
        return None

    def get_host_by_id(self, host_id: str) -> Optional[Dict[str, Any]]:
        """
        透過 host_id 取得單一主機完整資產與連線配置。
        Get complete host asset and transport credential details by host_id.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.execute(
                    """
                    SELECT id, host_id, name, host, port, internal_ip,
                           system, alias, rack, dept, department_id, group_name, status,
                           provision_mode, default_user, auth_type, credential_encrypted
                    FROM hosts
                    WHERE host_id = ?;
                    """,
                    (host_id,),
                )
                row = cur.fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def update_host_credential(
        self,
        host_id: str,
        default_user: str = "{username}",
        auth_type: str = "key",
        credential_encrypted: Optional[str] = None,
        provision_mode: str = "direct",
    ) -> bool:
        """
        更新目標主機的連線憑證與特權治理模式。
        Update host credential metadata, authentication type, and provisioning mode.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    cur = conn.execute(
                        """
                        UPDATE hosts
                        SET default_user = ?, auth_type = ?, credential_encrypted = ?, provision_mode = ?
                        WHERE host_id = ?;
                        """,
                        (default_user, auth_type, credential_encrypted, provision_mode, host_id),
                    )
                    return cur.rowcount > 0
            finally:
                conn.close()

    def list_hosts(self, role: str = "admin", department: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        依角色身分與部門維度過濾查詢主機資產清單 (支援空值公共主機訪問)。
        Filter and list host assets based on RBAC role and organizational department.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                if role in ("admin", "auditor"):
                    cur = conn.execute(
                        """
                        SELECT id, host_id, name, host, port, internal_ip,
                               system, alias, rack, dept, department_id, group_name, status,
                               provision_mode, default_user, auth_type, credential_encrypted
                        FROM hosts
                        ORDER BY id ASC;
                        """
                    )
                elif role == "manager" and department and department.strip():
                    cur = conn.execute(
                        """
                        SELECT id, host_id, name, host, port, internal_ip,
                               system, alias, rack, dept, department_id, group_name, status,
                               provision_mode, default_user, auth_type, credential_encrypted
                        FROM hosts
                        WHERE dept = ? OR dept = '' OR dept IS NULL
                        ORDER BY id ASC;
                        """,
                        (department.strip(),),
                    )
                else:
                    if department and department.strip():
                        cur = conn.execute(
                            """
                            SELECT id, host_id, name, host, port, internal_ip,
                                   system, alias, rack, dept, department_id, group_name, status,
                                   provision_mode, default_user, auth_type, credential_encrypted
                            FROM hosts
                            WHERE dept = ? OR dept = '' OR dept IS NULL
                            ORDER BY id ASC;
                            """,
                            (department.strip(),),
                        )
                    else:
                        cur = conn.execute(
                            """
                            SELECT id, host_id, name, host, port, internal_ip,
                                   system, alias, rack, dept, department_id, group_name, status,
                                   provision_mode, default_user, auth_type, credential_encrypted
                            FROM hosts
                            WHERE dept = '' OR dept IS NULL
                            ORDER BY id ASC;
                            """
                        )
                rows = cur.fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    # =========================================================================
    # 僅追加審計與錄影紀錄 (Audit Logs & Recordings)
    # =========================================================================

    def log_audit_event(
        self,
        session_id: str,
        user_id: str,
        username: str,
        host_id: str,
        event_type: str,
        command_raw: Optional[str] = None,
        command_clean: Optional[str] = None,
        action_taken: str = "LOG",
        audit_id: Optional[str] = None,
        host_ip: str = "",
        host_name: str = "",
    ) -> str:
        """
        寫入單筆審計日誌 (Append-Only)，自動生成時序唯一識別碼 (cmd_YYYYMMDD_<12hex>)。
        Append a single audit event to audit_logs table with auto-generated K-sortable audit_id.
        """
        a_id = audit_id or generate_uuid("cmd")
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO audit_logs (
                            audit_id, session_id, user_id, username, host_id,
                            host_ip, host_name, event_type, command_raw,
                            command_clean, action_taken
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            a_id, session_id, user_id, username, str(host_id),
                            host_ip, host_name, event_type, command_raw,
                            command_clean, action_taken,
                        ),
                    )
                return a_id
            finally:
                conn.close()

    def list_audit_events(
        self,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None,
        host_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        查詢審計日誌清單，支援會話 ID、使用者與目標主機篩選。
        Query audit events with optional session_id, user_id, and host_id filtering.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                query = "SELECT * FROM audit_logs WHERE 1=1"
                params: List[Any] = []
                if session_id:
                    query += " AND session_id = ?"
                    params.append(session_id)
                if user_id:
                    query += " AND user_id = ?"
                    params.append(user_id)
                if host_id:
                    query += " AND (host_id = ? OR host_ip = ?)"
                    params.append(str(host_id))
                    params.append(str(host_id))
                query += " ORDER BY id DESC LIMIT ?;"
                params.append(limit)

                cur = conn.execute(query, tuple(params))
                return [dict(r) for r in cur.fetchall()]
            finally:
                conn.close()

    def save_recording_metadata(
        self,
        session_id: str,
        file_path: str,
        file_size: int,
        sha256_hash: str,
        duration_seconds: float,
    ) -> bool:
        """
        儲存或更新會話錄影元資料與 SHA-256 雜湊值。
        Save or update session recording metadata with SHA-256 integrity hash.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT INTO recordings (
                            session_id, file_path, file_size, sha256_hash, duration_seconds
                        ) VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(session_id) DO UPDATE SET
                            file_path = excluded.file_path,
                            file_size = excluded.file_size,
                            sha256_hash = excluded.sha256_hash,
                            duration_seconds = excluded.duration_seconds;
                        """,
                        (session_id, file_path, file_size, sha256_hash, duration_seconds),
                    )
                    return True
            finally:
                conn.close()

    def get_recording_by_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        依會話識別碼查詢錄影檔案紀錄與雜湊值。
        Retrieve recording file metadata by session_id.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.execute(
                    "SELECT * FROM recordings WHERE session_id = ?;",
                    (session_id,),
                )
                row = cur.fetchone()
                return dict(row) if row else None
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

    def update_session_host(self, session_id: str, host_id: str) -> None:
        """
        更新會話所關聯之目標主機 ID。
        Update target host_id associated with an active session.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        UPDATE sessions
                        SET host_id = ?
                        WHERE session_id = ?;
                        """,
                        (str(host_id), session_id),
                    )
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

    def get_recent_login_for_user(
        self,
        username: str,
        host_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        查詢指定使用者在特定主機或系統上的最近歷史登入紀錄 (排除當前執行中的 ACTIVE 會話)。
        Query most recent historical login record for user on target host or bastion.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                if host_id:
                    cur = conn.execute(
                        """
                        SELECT started_at, client_ip, host_id FROM sessions
                        WHERE username = ? AND host_id = ? AND status != 'ACTIVE'
                        ORDER BY id DESC LIMIT 1;
                        """,
                        (username, str(host_id)),
                    )
                else:
                    cur = conn.execute(
                        """
                        SELECT started_at, client_ip, host_id FROM sessions
                        WHERE username = ? AND status != 'ACTIVE'
                        ORDER BY id DESC LIMIT 1;
                        """,
                        (username,),
                    )
                row = cur.fetchone()
                return dict(row) if row else None
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
                            "[RECONCILE] 開機對帳修復：已將 %d 筆因前次異常關機中斷之會話標記為 ABRUPT (Startup reconciliation marked interrupted sessions as ABRUPT: %d)",
                            count,
                            count,
                        )
                    return count
            finally:
                conn.close()
