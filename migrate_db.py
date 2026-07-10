"""
Database Migration Script
Upgrades database schema to support RBAC and new features
Run this ONCE: python migrate_db.py
"""

import sqlite3
import os
from datetime import datetime

from database import connect, is_postgres_enabled

DB_PATH = os.path.join(
    os.path.dirname(__file__),
    "database.db"
)

def migrate_database():
    """Run all database migrations"""
    
    with connect() as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        print("🔄 Starting database migration...\n")
        
        if is_postgres_enabled():
            print("1️⃣  Checking users table...")
            cursor.execute("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = 'users'
            """)
            columns = [row[0] for row in cursor.fetchall()]
            if "role" not in columns:
                print("   ✅ Adding 'role' column to users table")
                cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'viewer'")
                conn.commit()
            else:
                print("   ✅ 'role' column already exists")

            print("\n2️⃣  Creating system_settings table...")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_settings (
                    id SERIAL PRIMARY KEY,
                    key TEXT UNIQUE,
                    value TEXT,
                    setting_type TEXT DEFAULT 'string',
                    description TEXT,
                    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            print("   ✅ system_settings table created/exists")

            print("\n3️⃣  Creating notifications table...")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS notifications (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER,
                    title TEXT,
                    message TEXT,
                    notification_type TEXT DEFAULT 'info',
                    is_read INTEGER DEFAULT 0,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            conn.commit()
            print("   ✅ notifications table created/exists")

            print("\n4️⃣  Creating audit_logs table...")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id SERIAL PRIMARY KEY,
                    username TEXT,
                    action TEXT,
                    details TEXT,
                    log_time TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            print("   ✅ audit_logs table created/exists")

            print("\n5️⃣  Creating backup_logs table...")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS backup_logs (
                    id SERIAL PRIMARY KEY,
                    backup_type TEXT,
                    file_path TEXT,
                    size_bytes INTEGER,
                    status TEXT DEFAULT 'pending',
                    created_by TEXT,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    restored_at TIMESTAMPTZ
                )
            """)
            conn.commit()
            print("   ✅ backup_logs table created/exists")
        else:
            # 1. Check if users table has role column
            print("1️⃣  Checking users table...")
            cursor.execute("PRAGMA table_info(users)")
            columns = [row[1] for row in cursor.fetchall()]

            if "role" not in columns:
                print("   ✅ Adding 'role' column to users table")
                cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'viewer'")
                conn.commit()
            else:
                print("   ✅ 'role' column already exists")

            # 2. Create system_settings table
            print("\n2️⃣  Creating system_settings table...")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_settings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE,
                    value TEXT,
                    setting_type TEXT DEFAULT 'string',
                    description TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            print("   ✅ system_settings table created/exists")

            # 3. Create notifications table
            print("\n3️⃣  Creating notifications table...")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    title TEXT,
                    message TEXT,
                    notification_type TEXT DEFAULT 'info',
                    is_read INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            conn.commit()
            print("   ✅ notifications table created/exists")

            # 4. Create audit_logs table (for detailed audit trail)
            print("\n4️⃣  Creating audit_logs table...")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    action TEXT,
                    details TEXT,
                    log_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            print("   ✅ audit_logs table created/exists")

            # 5. Create backup_logs table
            print("\n5️⃣  Creating backup_logs table...")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS backup_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    backup_type TEXT,
                    file_path TEXT,
                    size_bytes INTEGER,
                    status TEXT DEFAULT 'pending',
                    created_by TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    restored_at TIMESTAMP
                )
            """)
            conn.commit()
            print("   ✅ backup_logs table created/exists")
        
        # 6. Insert default system settings if they don't exist
        print("\n6️⃣  Initializing system settings...")
        default_settings = [
            ("company_name", "Cyber Security Automation", "string", "Your organization name"),
            ("smtp_server", "smtp.gmail.com", "string", "Email server for alerts"),
            ("smtp_port", "587", "string", "Email server port"),
            ("smtp_email", "", "string", "Email account for sending alerts"),
            ("smtp_password", "", "string", "Email password"),
            ("scan_timeout", "300", "string", "Scan timeout in seconds"),
            ("default_network", "192.168.1.0/24", "string", "Default network for scanning"),
            ("password_min_length", "8", "string", "Minimum password length"),
            ("password_require_uppercase", "1", "string", "Require uppercase letters"),
            ("password_require_numbers", "1", "string", "Require numbers"),
            ("password_require_symbols", "1", "string", "Require special characters"),
            ("theme_color", "primary", "string", "Theme color (primary/dark/light)"),
            ("report_logo_url", "/static/images/logo.png", "string", "URL for report header logo"),
            ("max_login_attempts", "5", "string", "Max login attempts before lockout"),
            ("lockout_duration", "900", "string", "Lockout duration in seconds (15 min)"),
            ("enable_email_alerts", "1", "string", "Enable email notifications"),
            ("enable_two_factor", "0", "string", "Enable two-factor authentication"),
        ]
        
        for key, value, setting_type, description in default_settings:
            cursor.execute("SELECT id FROM system_settings WHERE key = ?", (key,))
            if not cursor.fetchone():
                if is_postgres_enabled():
                    cursor.execute("""
                        INSERT INTO system_settings (key, value, setting_type, description)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (key) DO NOTHING
                    """, (key, value, setting_type, description))
                else:
                    cursor.execute("""
                        INSERT INTO system_settings (key, value, setting_type, description)
                        VALUES (?, ?, ?, ?)
                    """, (key, value, setting_type, description))
                print(f"   ✅ Setting '{key}' initialized")
        
        conn.commit()
        
        # 7. Ensure admin user exists and has super_admin role
        print("\n7️⃣  Ensuring admin user has super_admin role...")
        cursor.execute("SELECT id, role FROM users WHERE username = 'admin'")
        admin = cursor.fetchone()
        
        if admin:
            if admin["role"] != "super_admin":
                cursor.execute("UPDATE users SET role = 'super_admin' WHERE username = 'admin'")
                conn.commit()
                print("   ✅ Admin role updated to super_admin")
            else:
                print("   ✅ Admin already has super_admin role")
        else:
            print("   ⚠️  Admin user not found - create one first!")
        
        print("\n✅ Database migration completed successfully!")
        print("\n📋 Summary:")
        print("   - Tables created: system_settings, notifications, audit_logs, backup_logs")
        print("   - Default settings initialized")
        print("   - Admin user role set to super_admin")
        print("\n🎉 Your database is now ready for production!")

if __name__ == "__main__":
    migrate_database()
