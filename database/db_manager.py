import sqlite3
from datetime import datetime, timedelta

DB_NAME = "network_logs.db"


def init_db():
    """Initialize the database and create tables if they don't exist"""
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            
            # Create logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    protocol TEXT,
                    port INTEGER,
                    country TEXT,
                    provider TEXT,
                    timestamp TEXT
                )
            ''')
            
            # Create blacklist table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blacklist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE,
                    reason TEXT,
                    created_at TEXT,
                    expires_at TEXT,
                    is_active INTEGER DEFAULT 1
                )
            ''')

            cursor.execute('''
                    CREATE TABLE IF NOT EXISTS settings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT UNIQUE,
                        value TEXT
                    )
                ''')
            # Insert default settings if they don't exist
            default_settings = [
                    ('notifications_enabled', '1'),
                    ('log_level', 'Medium'),
                    ('auto_blacklist_threshold', '5'),
                    ('log_retention_days', '30'),
                    ('dark_mode', '0'),
                    ('start_minimized', '0')
            ]
                
            cursor.executemany('''
                    INSERT OR IGNORE INTO settings (name, value)
                    VALUES (?, ?)
            ''', default_settings)

            conn.commit()
        print("Database and tables initialized successfully.")
    except sqlite3.Error as e:
        print(f"Error initializing the database: {e}")


# ===== Logs functions =====
def save_log(ip, protocol, port, country, provider):
    """Save a log entry into the database"""
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute('''
                INSERT INTO logs (ip, protocol, port, country, provider, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (ip, protocol, port, country, provider, timestamp))
            conn.commit()
        print("Log saved to the database.")
    except sqlite3.Error as e:
        print(f"Error saving the log: {e}")


def get_all_logs():
    """Retrieve all logs from the database"""
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ip, protocol, port, country, provider, timestamp FROM logs ORDER BY timestamp DESC")
            rows = cursor.fetchall()
        return rows
    except sqlite3.Error as e:
        print(f"Error retrieving logs: {e}")
        return []


def delete_old_logs(days=30):
    """Delete logs older than the specified number of days (default is 30 days)"""
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cutoff_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("DELETE FROM logs WHERE timestamp < ?", (cutoff_date,))
            conn.commit()
        print(f"Logs older than {days} days have been deleted.")
    except sqlite3.Error as e:
        print(f"Error deleting old logs: {e}")


# ===== Blacklist functions =====
def add_to_blacklist(ip, reason=None, days_active=None):
    """Add an IP address to the blacklist"""
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            expires_at = None
            if days_active:
                expires_at = (datetime.now() + timedelta(days=days_active)).strftime("%Y-%m-%d %H:%M:%S")
            
            cursor.execute('''
                INSERT INTO blacklist (ip, reason, created_at, expires_at)
                VALUES (?, ?, ?, ?)
            ''', (ip, reason, created_at, expires_at))
            conn.commit()
        print(f"IP {ip} added to blacklist.")
        return True
    except sqlite3.Error as e:
        print(f"Error adding to blacklist: {e}")
        return False


def remove_from_blacklist(ip):
    """Remove an IP address from the blacklist"""
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM blacklist WHERE ip = ?", (ip,))
            conn.commit()
        print(f"IP {ip} removed from blacklist.")
        return True
    except sqlite3.Error as e:
        print(f"Error removing from blacklist: {e}")
        return False


def is_ip_blacklisted(ip):
    """Check if an IP address is in the blacklist and active"""
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT ip FROM blacklist 
                WHERE ip = ? 
                AND is_active = 1
                AND (expires_at IS NULL OR expires_at > ?)
            ''', (ip, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            return cursor.fetchone() is not None
    except sqlite3.Error as e:
        print(f"Error checking blacklist: {e}")
        return False


def get_blacklist():
    """Get all active blacklist entries"""
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT ip, reason, created_at, expires_at 
                FROM blacklist 
                WHERE is_active = 1
                AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY created_at DESC
            ''', (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),))
            return cursor.fetchall()
    except sqlite3.Error as e:
        print(f"Error retrieving blacklist: {e}")
        return []


def deactivate_expired_entries():
    """Deactivate expired blacklist entries"""
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE blacklist 
                SET is_active = 0 
                WHERE expires_at IS NOT NULL 
                AND expires_at <= ?
            ''', (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),))
            conn.commit()
        print("Expired blacklist entries deactivated.")
    except sqlite3.Error as e:
        print(f"Error deactivating expired entries: {e}")


def update_blacklist_status(ip, is_active):
    """Activate or deactivate a blacklist entry"""
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE blacklist 
                SET is_active = ? 
                WHERE ip = ?
            ''', (1 if is_active else 0, ip))
            conn.commit()
        print(f"Blacklist entry for IP {ip} updated.")
        return True
    except sqlite3.Error as e:
        print(f"Error updating blacklist status: {e}")
        return False

def get_setting(name, default=None):
    """Get a setting value from the database"""
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM settings WHERE name = ?", (name,))
            result = cursor.fetchone()
            return result[0] if result else default
    except sqlite3.Error as e:
        print(f"Error getting setting {name}: {e}")
        return default

def set_setting(name, value):
    """Set a setting value in the database"""
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO settings (name, value)
                VALUES (?, ?)
            ''', (name, str(value)))
            conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"Error setting {name}: {e}")
        return False
