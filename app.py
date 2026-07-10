from flask import (
    Flask,
    render_template,
    request,
    redirect,
    send_file,
    jsonify,
    flash,
    make_response
)

from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user
)

from functools import wraps
from flask import abort
from io import BytesIO

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)
from urllib.parse import urlparse

from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer
)

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

from scanners.port_scanner import scan
from scanners.network_scanner import scan_network

from security.password_checker import check
from security.log_analyzer import analyze_log
from security.integrity_monitor import calculate_hash
from scanners.nmap_scanner import run_nmap_scan
from security.vulnerability_scanner import scan_vulnerabilities
from security.malware_scanner import scan_path as scan_malware_path
from security.threat_intel import lookup_indicator
from security.ai_assistant import summarize_security_state
from security.email_alerts import send_email_alert
from backup_manager import create_backup, list_backups, restore_backup, BACKUP_DIR

# RBAC and Production Features
from rbac import (
    require_permission, require_any_permission, 
    require_all_permissions, require_role,
    user_can, user_has_role, get_user_permissions, get_user_role_info, log_action
)
from roles import ROLES, has_permission, get_role_permissions
from settings import SystemSettings, get_setting, set_setting
from notifications import NotificationManager, create_notification
from database import connect, is_postgres_enabled

import re
import json
import secrets
import sqlite3
import os
import socket
import ipaddress
import hashlib
import hmac
from urllib import request as urllib_request
from urllib import error as urllib_error
from datetime import datetime, timedelta
from typing import Any


DB_PATH = os.path.join(
    os.path.dirname(__file__),
    "database.db"
)

PAYMENT_LIVE_KEYS = {
    "mixbyyas_endpoint",
    "mixbyyas_api_key",
    "mixbyyas_webhook_secret",
    "mixbyyas_allowed_ips",
    "halopesa_endpoint",
    "halopesa_api_key",
    "halopesa_webhook_secret",
    "halopesa_allowed_ips",
    "payment_webhook_tolerance_seconds"
}

PRIVILEGED_ROLES = {"admin", "super_admin", "security_admin"}


def is_management_role(role_name):
    return role_name in PRIVILEGED_ROLES

LANGUAGES = {
    "en": "English",
    "sw": "Kiswahili"
}

TRANSLATIONS = {
    "en": {
        "Cyber Security Automation": "Cyber Security Automation",
        "Dashboard": "Dashboard",
        "History": "History",
        "Export PDF": "Export PDF",
        "Users": "Users",
        "Signed in as": "Signed in as",
        "Logout": "Logout",
        "Login": "Login",
        "Register": "Register",
        "Create a professional account": "Create a professional account",
        "New here?": "New here?",
        "Username": "Username",
        "Password": "Password",
        "Email": "Email",
        "Confirm Password": "Confirm Password",
        "Create a Professional Account": "Create a Professional Account",
        "Register for secure access to the Cyber Security Automation platform.": "Register for secure access to the Cyber Security Automation platform.",
        "Already have an account?": "Already have an account?",
        "Sign in here": "Sign in here",
        "Security Dashboard": "Security Dashboard",
        "Overview of scan activity and quick access to tools.": "Overview of scan activity and quick access to tools.",
        "Total scans recorded": "Total scans recorded",
        "Scan types tracked": "Scan types tracked",
        "Recent scan entries": "Recent scan entries",
        "Total users": "Total users",
        "new in 30d": "new in 30d",
        "Modules": "Modules",
        "Port Scanner": "Port Scanner",
        "Network Scanner": "Network Scanner",
        "Password Checker": "Password Checker",
        "Log Analyzer": "Log Analyzer",
        "Integrity Monitor": "Integrity Monitor",
        "User Management": "User Management",
        "Scan History": "Scan History",
        "Change Password": "Change Password",
        "Current Password": "Current Password",
        "New Password": "New Password",
        "Confirm New Password": "Confirm New Password",
        "Search and review recorded scan activity.": "Search and review recorded scan activity.",
        "Search by scan type or target...": "Search by scan type or target...",
        "Search": "Search",
        "No scan history found.": "No scan history found.",
        "Type": "Type",
        "Target": "Target",
        "Date": "Date",
        "Result": "Result",
        "Scan Results": "Scan Results",
        "Discovered Devices": "Discovered Devices",
        "IP Address": "IP Address",
        "MAC Address": "MAC Address",
        "Hostname": "Hostname",
        "No devices found.": "No devices found.",
        "Score": "Score",
        "Use a mix of upper/lowercase letters, numbers, and symbols for a stronger password.": "Use a mix of upper/lowercase letters, numbers, and symbols for a stronger password.",
        "Use at least 6 characters for admin-created accounts.": "Use at least 6 characters for admin-created accounts.",
        "Use at least 8 characters with uppercase, lowercase, numbers, and symbols.": "Use at least 8 characters with uppercase, lowercase, numbers, and symbols.",
        "Enter username": "Enter username",
        "Enter password": "Enter password",
        "Repeat password": "Repeat password",
        "Scan": "Scan",
        "Check": "Check",
        "Analyze": "Analyze",
        "Scan Network": "Scan Network",
        "Number of Scans": "Number of Scans",
        "Scan Statistics": "Scan Statistics",
        "Recent Activity": "Recent Activity",
        "Port": "Port",
        "Status": "Status",
        "Action": "Action",
        "ID": "ID",
        "Role": "Role",
        "app.py": "app.py",
        "sample.log": "sample.log",
        "127.0.0.1": "127.0.0.1",
        "192.168.1.0/24": "192.168.1.0/24",
        "you@example.com": "you@example.com",
        "Analysis Results": "Analysis Results",
        "Generate Hash": "Generate Hash",
        "SHA256 Hash": "SHA256 Hash",
        "File Integrity Monitor": "File Integrity Monitor",
        "Add New User": "Add New User",
        "Add User": "Add User",
        "Delete": "Delete",
        "Please fill in all fields.": "Please fill in all fields.",
        "Username must be at least 3 characters long and may not contain spaces.": "Username must be at least 3 characters long and may not contain spaces.",
        "Please enter a valid email address.": "Please enter a valid email address.",
        "Passwords do not match.": "Passwords do not match.",
        "Password must be at least 8 characters long.": "Password must be at least 8 characters long.",
        "Choose a stronger password. Use uppercase, lowercase, numbers, and symbols.": "Choose a stronger password. Use uppercase, lowercase, numbers, and symbols.",
        "Username or email already exists.": "Username or email already exists.",
        "Account created successfully. Please log in.": "Account created successfully. Please log in.",
        "An error occurred while creating your account. Please try again.": "An error occurred while creating your account. Please try again.",
        "Current password is incorrect.": "Current password is incorrect.",
        "Password changed successfully.": "Password changed successfully.",
        "Username, email, and password are required.": "Username, email, and password are required.",
        "Incorrect password.": "Incorrect password.",
        "Login successful.": "Login successful.",
        "Too many login attempts. Try again after 15 minutes.": "Too many login attempts. Try again after 15 minutes.",
        "Username and password are required.": "Username and password are required.",
        "Username not found.": "Username not found.",
        "Username must be at least 3 characters and contain no spaces.": "Username must be at least 3 characters and contain no spaces.",
        "Password must be at least 6 characters long.": "Password must be at least 6 characters long.",
        "User added successfully.": "User added successfully.",
        "An error occurred while adding the user.": "An error occurred while adding the user.",
        "Invalid network range.": "Invalid network range.",
        "Log file not found or invalid path.": "Log file not found or invalid path.",
        "File not found or invalid path.": "File not found or invalid path.",
        "Admin cannot be deleted.": "Admin cannot be deleted.",
        "Admin access required.": "Admin access required."
    },
    "sw": {
        "Cyber Security Automation": "Ulinzi wa Mtandao",
        "Dashboard": "Kioshi",
        "History": "Historia",
        "Export PDF": "Hamisha PDF",
        "Users": "Watumiaji",
        "Signed in as": "Imeingia kama",
        "Logout": "Toka",
        "Login": "Ingia",
        "Register": "Jisajili",
        "Create a professional account": "Tengeneza akaunti ya kitaalamu",
        "New here?": "Mpya hapa?",
        "Username": "Jina la mtumiaji",
        "Password": "Nenosiri",
        "Email": "Barua pepe",
        "Confirm Password": "Thibitisha nenosiri",
        "Create a Professional Account": "Tengeneza Akaunti ya Kitaalamu",
        "Register for secure access to the Cyber Security Automation platform.": "Jisajili kwa upatikanaji salama kwa mfumo wa ulinzi wa mtandao.",
        "Already have an account?": "Tayari una akaunti?",
        "Sign in here": "Ingia hapa",
        "Security Dashboard": "Kioshi la Usalama",
        "Overview of scan activity and quick access to tools.": "Muhtasari wa shughuli za skanu na ufikiaji wa zana kwa haraka.",
        "Total scans recorded": "Skani zote zilizorekodiwa",
        "Scan types tracked": "Aina za skani zinazoangaliwa",
        "Recent scan entries": "Kuingia za skani za hivi karibuni",
        "Total users": "Watumiaji wote",
        "new in 30d": "mpya ndani ya siku 30",
        "Modules": "Moduli",
        "Port Scanner": "Kichunguzi cha Bandari",
        "Network Scanner": "Kichunguzi cha Mtandao",
        "Password Checker": "Kikagua Nenosiri",
        "Log Analyzer": "Mchambuzi wa Logi",
        "Integrity Monitor": "Kikagua Uadilifu",
        "User Management": "Usimamizi wa Watumiaji",
        "Scan History": "Historia ya Skani",
        "Change Password": "Badilisha Nenosiri",
        "Current Password": "Nenosiri la sasa",
        "New Password": "Nenosiri jipya",
        "Confirm New Password": "Thibitisha nenosiri jipya",
        "Search and review recorded scan activity.": "Tafuta na uangalie shughuli za skani zilizorekodiwa.",
        "Search by scan type or target...": "Tafuta kwa aina ya skani au lengo...",
        "Search": "Tafuta",
        "No scan history found.": "Hakuna historia ya skani iliyopatikana.",
        "Type": "Aina",
        "Target": "Lengo",
        "Date": "Tarehe",
        "Result": "Matokeo",
        "Scan Results": "Matokeo ya Skani",
        "Discovered Devices": "Vifaa vilivyogunduliwa",
        "IP Address": "Anuani ya IP",
        "MAC Address": "Anuani ya MAC",
        "Hostname": "Jina la mwenyeji",
        "No devices found.": "Hakuna vifaa vilivyopatikana.",
        "Score": "Alama",
        "Use a mix of upper/lowercase letters, numbers, and symbols for a stronger password.": "Tumia mchanganyiko wa herufi kubwa/ndogo, nambari, na alama kwa nenosiri thabiti.",
        "Use at least 6 characters for admin-created accounts.": "Tumia angalau herufi 6 kwa akaunti za msimamizi.",
        "Use at least 8 characters with uppercase, lowercase, numbers, and symbols.": "Tumia angalau herufi 8, herufi kubwa na ndogo, nambari, na alama.",
        "Enter username": "Ingiza jina la mtumiaji",
        "Enter password": "Ingiza nenosiri",
        "Repeat password": "Rudia nenosiri",
        "Scan": "Fanya skani",
        "Check": "Kagua",
        "Analyze": "Chambua",
        "Scan Network": "Fanya skani ya mtandao",
        "Number of Scans": "Idadi ya skani",
        "Scan Statistics": "Takwimu za skani",
        "Recent Activity": "Shughuli za hivi karibuni",
        "Port": "Bandari",
        "Status": "Hali",
        "Action": "Kitendo",
        "ID": "Kitambulisho",
        "Role": "Kazi",
        "app.py": "app.py",
        "sample.log": "sample.log",
        "127.0.0.1": "127.0.0.1",
        "192.168.1.0/24": "192.168.1.0/24",
        "you@example.com": "you@example.com",
        "Use a mix of upper/lowercase letters, numbers, and symbols for a stronger password.": "Tumia mchanganyiko wa herufi kubwa/ndogo, nambari, na alama kwa nenosiri thabiti.",
        "Analysis Results": "Matokeo ya Uchambuzi",
        "Generate Hash": "Tengeneza Hash",
        "SHA256 Hash": "SHA256 Hash",
        "File Integrity Monitor": "Kikagua Uadilifu wa Faili",
        "Add New User": "Ongeza Mtumiaji Mpya",
        "Add User": "Ongeza Mtumiaji",
        "Delete": "Futa",
        "Please fill in all fields.": "Tafadhali jaza sehemu zote.",
        "Username must be at least 3 characters long and may not contain spaces.": "Jina la mtumiaji linapaswa kuwa angalau herufi 3 na bila nafasi.",
        "Please enter a valid email address.": "Tafadhali ingiza anwani halali ya barua pepe.",
        "Passwords do not match.": "Nenosiri hazilingani.",
        "Password must be at least 8 characters long.": "Nenosiri linapaswa kuwa angalau herufi 8.",
        "Choose a stronger password. Use uppercase, lowercase, numbers, and symbols.": "Chagua nenosiri thabiti zaidi. Tumia herufi kubwa, ndogo, nambari, na alama.",
        "Username or email already exists.": "Jina la mtumiaji au barua pepe tayari ipo.",
        "Account created successfully. Please log in.": "Akaunti imetengenezwa kwa mafanikio. Tafadhali ingia.",
        "An error occurred while creating your account. Please try again.": "Kosa limetokea wakati wa kuunda akaunti. Tafadhali jaribu tena.",
        "Current password is incorrect.": "Nenosiri la sasa si sahihi.",
        "Password changed successfully.": "Nenosiri limebadilishwa kwa mafanikio.",
        "Username, email, and password are required.": "Jina la mtumiaji, barua pepe, na nenosiri vinahitajika.",
        "Incorrect password.": "Nenosiri si sahihi.",
        "Login successful.": "Umefanikiwa kuingia.",
        "Too many login attempts. Try again after 15 minutes.": "Jaribio nyingi za kuingia. Jaribu tena baada ya dakika 15.",
        "Username and password are required.": "Jina la mtumiaji na nenosiri vinahitajika.",
        "Username not found.": "Jina la mtumiaji halikupatikana.",
        "Username must be at least 3 characters and contain no spaces.": "Jina la mtumiaji linapaswa kuwa angalau herufi 3 na lisijumuishe nafasi.",
        "Password must be at least 6 characters long.": "Nenosiri linapaswa kuwa angalau herufi 6.",
        "User added successfully.": "Mtumiaji ameongezwa kwa mafanikio.",
        "An error occurred while adding the user.": "Kosa limetokea wakati wa kuongeza mtumiaji.",
        "Invalid network range.": "Eneo la mtandao si sahihi.",
        "Log file not found or invalid path.": "Faili la logi halikupatikana au njia si sahihi.",
        "File not found or invalid path.": "Faili halikupatikana au njia si sahihi.",
        "Admin cannot be deleted.": "Msimamizi hawezi kufutwa.",
        "Admin access required.": "Ufikiaji wa msimamizi unahitajika."
    }
}


def get_locale():
    lang = request.cookies.get("lang", "en")
    return lang if lang in LANGUAGES else "en"


def translate(text):
    locale = get_locale()
    return TRANSLATIONS.get(locale, {}).get(text, text)


app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

database_initialized = False

login_manager = LoginManager()
login_manager.init_app(app)

setattr(login_manager, "login_view", "login")

@app.context_processor
def inject_translations():
    notification_count = 0
    if current_user.is_authenticated:
        notification_count = NotificationManager.get_unread_count(current_user.id)

    return {
        "_": translate,
        "current_language": get_locale(),
        "available_languages": LANGUAGES,
        "notification_count": notification_count,
        "user_can": user_can,
        "user_has_role": user_has_role,
        "get_user_permissions": get_user_permissions,
        "get_user_role_info": get_user_role_info,
        "is_management_role": is_management_role
    }


@app.route("/language/<lang>")
def set_language(lang):
    if lang not in LANGUAGES:
        lang = "en"
    response = make_response(redirect(request.referrer or "/"))
    response.set_cookie("lang", lang, max_age=60 * 60 * 24 * 365)
    return response


def init_database():
    with connect() as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        if is_postgres_enabled():
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users(
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE,
                    password TEXT,
                    role TEXT DEFAULT 'user',
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    email TEXT DEFAULT ''
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs(
                    id SERIAL PRIMARY KEY,
                    username TEXT,
                    action TEXT,
                    details TEXT,
                    log_time TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_history(
                    id SERIAL PRIMARY KEY,
                    scan_type TEXT,
                    target TEXT,
                    result TEXT,
                    scan_date TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS backup_logs(
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

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS payments(
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id),
                    plan_name TEXT DEFAULT 'Monthly Subscription',
                    amount NUMERIC(12, 2) NOT NULL,
                    currency TEXT DEFAULT 'TZS',
                    payment_method TEXT,
                    reference TEXT UNIQUE,
                    status TEXT DEFAULT 'pending',
                    notes TEXT,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    paid_at TIMESTAMPTZ
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS notifications(
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id),
                    title TEXT,
                    message TEXT,
                    notification_type TEXT DEFAULT 'info',
                    is_read INTEGER DEFAULT 0,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_settings(
                    id SERIAL PRIMARY KEY,
                    key TEXT UNIQUE,
                    value TEXT,
                    setting_type TEXT DEFAULT 'string',
                    description TEXT,
                    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)
        else:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT,
                    role TEXT DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    email TEXT DEFAULT ''
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    action TEXT,
                    details TEXT,
                    log_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_history(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT,
                    target TEXT,
                    result TEXT,
                    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS backup_logs(
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

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS payments(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    plan_name TEXT DEFAULT 'Monthly Subscription',
                    amount REAL NOT NULL,
                    currency TEXT DEFAULT 'TZS',
                    payment_method TEXT,
                    reference TEXT UNIQUE,
                    status TEXT DEFAULT 'pending',
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    paid_at TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS notifications(
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

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_settings(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE,
                    value TEXT,
                    setting_type TEXT DEFAULT 'string',
                    description TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

        default_settings = [
            ("company_name", "Cyber Security Automation", "string", "Organization name"),
            ("default_network", "192.168.1.0/24", "string", "Default network range"),
            ("scan_timeout", "300", "string", "Scan timeout in seconds"),
            ("password_min_length", "8", "string", "Minimum password length"),
            ("max_login_attempts", "5", "string", "Failed login limit before lockout"),
            ("lockout_duration", "900", "string", "Lockout duration in seconds"),
            ("enable_email_alerts", "1", "string", "Enable email notifications"),
            ("mixbyyas_endpoint", "", "string", "Mix by YAS payment API endpoint"),
            ("mixbyyas_api_key", "", "string", "Mix by YAS API key"),
            ("mixbyyas_webhook_secret", "", "string", "Mix by YAS webhook signing secret"),
            ("mixbyyas_allowed_ips", "", "string", "Comma separated Mix by YAS callback IPs"),
            ("halopesa_endpoint", "", "string", "HaloPesa payment API endpoint"),
            ("halopesa_api_key", "", "string", "HaloPesa API key"),
            ("halopesa_webhook_secret", "", "string", "HaloPesa webhook signing secret"),
            ("halopesa_allowed_ips", "", "string", "Comma separated HaloPesa callback IPs"),
            ("payment_webhook_tolerance_seconds", "300", "string", "Allowed callback timestamp drift in seconds")
        ]

        for key, value, setting_type, description in default_settings:
            cursor.execute("SELECT id FROM system_settings WHERE key = ?", (key,))
            if cursor.fetchone() is None:
                cursor.execute(
                    "INSERT INTO system_settings (key, value, setting_type, description) VALUES (?, ?, ?, ?)",
                    (key, value, setting_type, description)
                )

        cursor.execute("""
            SELECT id
            FROM users
            WHERE username = ?
        """, ("admin",))

        admin = cursor.fetchone()

        if admin is None:
            if is_postgres_enabled():
                cursor.execute("""
                    INSERT INTO users(
                        username,
                        password,
                        role
                    )
                    VALUES(%s,%s,%s)
                    ON CONFLICT (username) DO NOTHING
                """, (
                    "admin",
                    generate_password_hash("admin123"),
                    "super_admin"
                ))
            else:
                cursor.execute("""
                    INSERT OR IGNORE INTO users(
                        username,
                        password,
                        role
                    )
                    VALUES(?,?,?)
                """, (
                    "admin",
                    generate_password_hash("admin123"),
                    "super_admin"
                ))

        if is_postgres_enabled():
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS login_attempts(
                    id SERIAL PRIMARY KEY,
                    ip TEXT UNIQUE,
                    attempts INTEGER DEFAULT 0,
                    last_attempt TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS payment_webhook_events(
                    id SERIAL PRIMARY KEY,
                    provider TEXT,
                    event_id TEXT UNIQUE,
                    reference TEXT,
                    status TEXT,
                    source_ip TEXT,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)
        else:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS login_attempts(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE,
                    attempts INTEGER DEFAULT 0,
                    last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS payment_webhook_events(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    provider TEXT,
                    event_id TEXT UNIQUE,
                    reference TEXT,
                    status TEXT,
                    source_ip TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)


def ensure_database_initialized():
    global database_initialized
    if database_initialized:
        return
    init_database()
    database_initialized = True


@app.before_request
def bootstrap_database():
    ensure_database_initialized()


def get_db():
    conn = connect()
    conn.row_factory = sqlite3.Row
    return conn


def get_client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


def is_valid_host(host):
    if not host:
        return False
    try:
        socket.gethostbyname(host)
        return True
    except OSError:
        return False


def is_valid_network(network):
    try:
        ipaddress.ip_network(network, strict=False)
        return True
    except ValueError:
        return False


def is_valid_file(filename):
    if not filename:
        return False
    return os.path.isfile(os.path.abspath(filename))


def is_valid_email(email):
    if not email:
        return False
    email_regex = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    return re.match(email_regex, email) is not None


def get_login_attempts(ip):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT attempts, last_attempt FROM login_attempts WHERE ip = ?",
            (ip,)
        )
        row = cursor.fetchone()
    if not row:
        return 0, None

    last_attempt = None
    try:
        last_attempt = datetime.fromisoformat(row["last_attempt"])
    except Exception:
        pass

    return row["attempts"], last_attempt


def record_failed_login(ip):
    attempts, last_attempt = get_login_attempts(ip)
    now = datetime.utcnow()

    if last_attempt and now - last_attempt > timedelta(minutes=15):
        attempts = 0

    attempts += 1

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO login_attempts(ip, attempts, last_attempt) VALUES(?,?,?)"
            "ON CONFLICT(ip) DO UPDATE SET attempts = excluded.attempts, last_attempt = excluded.last_attempt",
            (ip, attempts, now.isoformat())
        )
        conn.commit()


def clear_login_attempts(ip):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM login_attempts WHERE ip = ?", (ip,))
        conn.commit()


def is_login_blocked(ip):
    attempts, last_attempt = get_login_attempts(ip)
    if not last_attempt:
        return False
    if attempts >= 5 and datetime.utcnow() - last_attempt <= timedelta(minutes=15):
        return True
    return False


def admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not is_management_role(getattr(current_user, "role", "")):
            flash("Admin access required.", "danger")
            return redirect("/")
        return view_func(*args, **kwargs)
    return wrapper


class User(UserMixin):

    def __init__(self, id, username=None, role="user"):
        self.id = id
        self.username = username
        self.role = role


@login_manager.user_loader
def load_user(user_id):

    conn = connect()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id,
               username,
               role
        FROM users
        WHERE id=?
    """, (user_id,))

    user = cursor.fetchone()

    conn.close()

    if user:
        return User(
            user["id"],
            user["username"],
            user["role"]
        )

    return None


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect("/")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not email or not password or not confirm_password:
            flash("Please fill in all fields.", "danger")
            return render_template("register.html")

        if len(username) < 3 or " " in username:
            flash("Username must be at least 3 characters long and may not contain spaces.", "danger")
            return render_template("register.html")

        if not is_valid_email(email):
            flash("Please enter a valid email address.", "danger")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return render_template("register.html")

        password_score = check(password)
        if password_score < 4:
            flash("Choose a stronger password. Use uppercase, lowercase, numbers, and symbols.", "danger")
            return render_template("register.html")

        hashed_password = generate_password_hash(password)

        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id FROM users WHERE username = ? OR email = ?
                """, (username, email))
                existing_user = cursor.fetchone()
                if existing_user:
                    flash("Username or email already exists.", "danger")
                    return render_template("register.html")

                cursor.execute("""
                    INSERT INTO users(
                        username,
                        password,
                        role,
                        email
                    ) VALUES (?, ?, 'user', ?)
                """, (username, hashed_password, email))
                conn.commit()
            flash("Account created successfully. Please log in.", "success")
            return redirect("/login")
        except sqlite3.DatabaseError:
            flash("An error occurred while creating your account. Please try again.", "danger")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    # Kama user tayari amelogin, mpeleke Dashboard
    if current_user.is_authenticated:
        return redirect("/")

    if request.method == "POST":
        client_ip = get_client_ip()

        if is_login_blocked(client_ip):
            flash(
                "Too many login attempts. Try again after 15 minutes.",
                "danger"
            )
            return render_template("login.html")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Hakikisha username na password zimejazwa
        if not username or not password:
            flash(
                "Username and password are required.",
                "danger"
            )
            return render_template("login.html")

        # Fungua database
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT id,
                    username,
                    password,
                    role
            FROM users
            WHERE username=?
            """, (username,))
            user = cursor.fetchone()

        # Hakikisha user yupo
        if user is None:
            record_failed_login(client_ip)
            flash(
                "Username not found.",
                "danger"
            )
            return render_template("login.html")

        # Hakiki password
        if check_password_hash(user["password"], password):
            clear_login_attempts(client_ip)
            login_user(User(user["id"], user["username"], user["role"]))
            save_audit(
                user["username"],
                "LOGIN",
                "User logged into the system."
            )
            flash(
                "Login successful.",
                "success"
            )

            next_page = request.args.get("next")
            if not next_page or urlparse(next_page).netloc != "":
                next_page = "/"
            return redirect(next_page)
        else:
            record_failed_login(client_ip)
            flash(
                "Incorrect password.",
                "danger"
            )

    return render_template("login.html")


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():

    if request.method == "POST":

        current_password = request.form["current_password"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT password
                FROM users
                WHERE id = ?
            """, (current_user.id,))
            user = cursor.fetchone()

        if not user or not check_password_hash(user["password"], current_password):
            flash("Current password is incorrect.", "danger")
            return redirect("/change_password")

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect("/change_password")

        hashed_password = generate_password_hash(new_password)

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users
                SET password = ?
                WHERE id = ?
            """, (hashed_password, current_user.id))
            conn.commit()

        flash("Password changed successfully.", "success")

        return redirect("/")

    return render_template("change_password.html")


@app.route("/")
@login_required
def dashboard():
    with get_db() as conn:
        cursor = conn.cursor()

        # Total scans
        cursor.execute(
            "SELECT COUNT(*) FROM scan_history"
        )
        total_scans = cursor.fetchone()[0]

        # Statistics for Chart
        cursor.execute("""
            SELECT scan_type,
                   COUNT(*)
            FROM scan_history
            GROUP BY scan_type
        """)
        stats = cursor.fetchall()

        cursor.execute("""
            SELECT scan_date,
                   result,
                   target
            FROM scan_history
            ORDER BY scan_date DESC
            LIMIT 500
        """) 
        scan_rows = cursor.fetchall()

        # Recent Scans
        cursor.execute("""
            SELECT scan_type,
                   target,
                   scan_date
            FROM scan_history
            ORDER BY scan_date DESC
            LIMIT 5
        """)
        recent_scans = cursor.fetchall()

        total_users = 0
        new_users_last_30 = 0
        if current_user.is_authenticated and is_management_role(current_user.role):
            cursor.execute("SELECT COUNT(*) FROM users")
            total_users = cursor.fetchone()[0]
            cursor.execute(
                "SELECT COUNT(*) FROM users WHERE created_at >= datetime('now', '-30 days')"
            )
            new_users_last_30 = cursor.fetchone()[0]

    now_utc = datetime.utcnow()
    scans_today = 0
    scans_last_7_days = 0
    success_count = 0
    parsed_scan_dates = []
    targets_counter = {}

    for row in scan_rows:
        raw_date = row[0]
        result_text = str(row[1] or "")
        target_text = str(row[2] or "unknown")

        scan_dt = None
        if isinstance(raw_date, datetime):
            scan_dt = raw_date
        elif isinstance(raw_date, str):
            date_text = raw_date.replace("Z", "").replace("T", " ")
            try:
                scan_dt = datetime.fromisoformat(date_text)
            except ValueError:
                try:
                    scan_dt = datetime.strptime(date_text, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    scan_dt = None

        if scan_dt:
            parsed_scan_dates.append(scan_dt)
            if scan_dt.date() == now_utc.date():
                scans_today += 1
            if now_utc - scan_dt <= timedelta(days=7):
                scans_last_7_days += 1

        targets_counter[target_text] = targets_counter.get(target_text, 0) + 1

        lowered_result = result_text.lower()
        if not any(token in lowered_result for token in ["error", "failed", "not installed", "invalid"]):
            success_count += 1

    success_rate = round((success_count / total_scans) * 100, 1) if total_scans else 0.0
    top_target = "-"
    if targets_counter:
        top_target = max(targets_counter, key=targets_counter.get)

    trend_counts = {}
    for day_offset in range(6, -1, -1):
        day = (now_utc - timedelta(days=day_offset)).date()
        trend_counts[day.isoformat()] = 0

    for scan_dt in parsed_scan_dates:
        key = scan_dt.date().isoformat()
        if key in trend_counts:
            trend_counts[key] += 1

    trend_labels = list(trend_counts.keys())
    trend_values = list(trend_counts.values())

    return render_template(
        "dashboard.html",
        total_scans=total_scans,
        recent_scans=recent_scans,
        stats=stats,
        total_users=total_users,
        new_users_last_30=new_users_last_30,
        scans_today=scans_today,
        scans_last_7_days=scans_last_7_days,
        success_rate=success_rate,
        top_target=top_target,
        trend_labels=trend_labels,
        trend_values=trend_values
    )


@app.route("/users")
@login_required
@admin_required
def users():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id,
                   username,
                   email,
                   role
            FROM users
        """)
        records = cursor.fetchall()

    return render_template(
        "users.html",
        records=records
    )

@app.route("/add_user", methods=["GET", "POST"])
@login_required
@admin_required
def add_user():

    if request.method == "POST":

        username = request.form["username"].strip()
        email = request.form.get("email", "").strip()
        password = request.form["password"]

        if username == "" or email == "" or password == "":
            flash("Username, email, and password are required.", "danger")
            return redirect("/add_user")

        if len(username) < 3 or " " in username:
            flash("Username must be at least 3 characters and contain no spaces.", "danger")
            return redirect("/add_user")

        if not is_valid_email(email):
            flash("Please enter a valid email address.", "danger")
            return redirect("/add_user")

        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            return redirect("/add_user")

        hashed_password = generate_password_hash(password)

        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id FROM users WHERE username = ? OR email = ?
                """, (username, email))
                existing_user = cursor.fetchone()
                if existing_user:
                    flash("Username or email already exists.", "danger")
                    return redirect("/add_user")

                cursor.execute("""
                    INSERT INTO users (
                        username,
                        password,
                        email
                    )
                    VALUES (?, ?, ?)
                """, (
                    username,
                    hashed_password,
                    email
                ))
                conn.commit()

            flash("User added successfully.", "success")

        except sqlite3.DatabaseError:
            flash("An error occurred while adding the user.", "danger")

        return redirect("/users")

    return render_template("add_user.html")


@app.route("/port", methods=["GET", "POST"])
@login_required
def port():

    results = []
    error = None

    if request.method == "POST":
        host = request.form["host"].strip()

        if not is_valid_host(host):
            error = "Please enter a valid hostname or IP address."
        else:
            try:
                open_ports = scan(host, 1, 1000)
                results = {port: "Open" for port in open_ports}

                save_scan(
                    "PORT",
                    host,
                    results
                )
                save_audit(
                current_user.username,
                    "PORT SCAN",
                     f"Scanned host {host}"
)
            except Exception as e:
                error = str(e)

    return render_template(
        "port_scanner.html",
        results=results,
        error=error
    )


@app.route("/network", methods=["GET", "POST"])
@login_required
def network():

    devices = []

    if request.method == "POST":
        network_range = request.form["network"].strip()

        if not is_valid_network(network_range):
            flash("Invalid network range.", "danger")
        else:
            devices = scan_network(network_range)
            save_scan(
                "NETWORK",
                network_range,
                devices
            )

            save_audit(
                current_user.username,
               "NETWORK SCAN",
               f"Scanned network {network_range}"
)
    return render_template(
        "network_scanner.html",
        devices=devices
    )

@app.route("/password", methods=["GET","POST"])
@login_required
def password():

    score = None

    if request.method == "POST":

        password_value = request.form["password"]

        score = check(password_value)

        save_audit(
           current_user.username,
           "PASSWORD CHECK",
           "Password strength analyzed."
)

    return render_template(
        "password_checker.html",
        score=score
    )


@app.route("/logs", methods=["GET","POST"])
@login_required
def logs():

    results = []

    if request.method == "POST":
        logfile = request.form["logfile"].strip()

        if not is_valid_file(logfile):
            flash("Log file not found or invalid path.", "danger")
        else:
            results = analyze_log(logfile)
            save_scan(
                "LOG_ANALYSIS",
                logfile,
                results
            )

            save_audit(
                current_user.username,
                "LOG ANALYSIS",
                f"Analyzed {logfile}"
)

    return render_template(
        "log_analyzer.html",
        results=results
    )


@app.route("/integrity", methods=["GET", "POST"])
@login_required
def integrity():

    file_hash = None

    if request.method == "POST":
        filename = request.form["filename"].strip()

        if not is_valid_file(filename):
            flash("File not found or invalid path.", "danger")
        else:
            file_hash = calculate_hash(filename)
            save_scan(
                "FILE_INTEGRITY",
                filename,
                file_hash
            )

            save_audit(
               current_user.username,
               "FILE INTEGRITY",
                filename
)

    return render_template(
        "integrity_monitor.html",
        file_hash=file_hash
    )

def save_scan(scan_type, target, result):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_history(
                scan_type,
                target,
                result
            )
            VALUES (?, ?, ?)
        """, (scan_type, target, str(result)))
        conn.commit()


def save_backup_log(backup_type, file_path, size_bytes, status, created_by, restored_at=None):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO backup_logs (
                backup_type,
                file_path,
                size_bytes,
                status,
                created_by,
                restored_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (backup_type, file_path, size_bytes, status, created_by, restored_at)
        )
        conn.commit()


def get_backup_log_entries():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM backup_logs ORDER BY created_at DESC LIMIT 50")
        return cursor.fetchall()

def save_audit(username, action, details):
    with connect() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_logs(
                username,
                action,
                details
            )
            VALUES (?, ?, ?)
        """, (
            username,
            action,
            details
        ))
        conn.commit()


def fetch_payment_stats(records):
    total_count = len(records)
    pending_count = 0
    paid_count = 0
    paid_total = 0.0
    paid_usd = 0.0
    paid_eur = 0.0

    for row in records:
        status = str(row["status"] or "").lower()
        amount = float(row["amount"] or 0)
        currency = str(row["currency"] or "").upper()
        if status == "pending":
            pending_count += 1
        if status == "paid":
            paid_count += 1
            paid_total += amount
            if currency == "USD":
                paid_usd += amount
            if currency == "EUR":
                paid_eur += amount

    return {
        "total_count": total_count,
        "pending_count": pending_count,
        "paid_count": paid_count,
        "paid_total": round(paid_total, 2),
        "paid_usd": round(paid_usd, 2),
        "paid_eur": round(paid_eur, 2)
    }


def get_live_payment_setting(key: str, default: str = "") -> str:
    if key in PAYMENT_LIVE_KEYS:
        env_key = f"CSA_{key.upper()}"
        env_value = os.environ.get(env_key)
        if env_value is not None and str(env_value).strip() != "":
            return str(env_value).strip()
    return str(get_setting(key, default) or default).strip()


def is_live_payment_setting_from_env(key: str) -> bool:
    if key not in PAYMENT_LIVE_KEYS:
        return False
    env_key = f"CSA_{key.upper()}"
    env_value = os.environ.get(env_key)
    return env_value is not None and str(env_value).strip() != ""


def extract_first_value(payload: dict[str, Any], keys: list[str]) -> str:
    for key in keys:
        value = payload.get(key)
        if value not in (None, ""):
            return str(value)

    nested = payload.get("data")
    if isinstance(nested, dict):
        for key in keys:
            value = nested.get(key)
            if value not in (None, ""):
                return str(value)

    return ""


def map_gateway_status(raw_status: object) -> str:
    status_value = str(raw_status or "pending").strip().lower()
    if status_value in {"success", "successful", "complete", "completed", "paid"}:
        return "paid"
    if status_value in {"failed", "failure", "declined", "rejected", "error"}:
        return "failed"
    if status_value in {"cancelled", "canceled", "void"}:
        return "cancelled"
    return "pending"


def verify_callback_signature(provider: str, raw_body: bytes) -> bool:
    if provider not in {"mixbyyas", "halopesa"}:
        return True

    secret = get_live_payment_setting(f"{provider}_webhook_secret", "")
    if not secret:
        return True

    incoming_signature = (
        str(request.headers.get("X-Signature", "") or "").strip()
        or str(request.headers.get("X-Callback-Signature", "") or "").strip()
    )
    if not incoming_signature:
        return False

    expected_signature = hmac.new(
        secret.encode("utf-8"),
        raw_body,
        hashlib.sha256
    ).hexdigest()

    ts_header = str(request.headers.get("X-Signature-Timestamp", "") or "").strip()
    signed_with_ts = ""
    if ts_header:
        signed_with_ts = hmac.new(
            secret.encode("utf-8"),
            f"{ts_header}.{raw_body.decode('utf-8', errors='ignore')}".encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

    if ts_header:
        try:
            tolerance_seconds = int(get_live_payment_setting("payment_webhook_tolerance_seconds", "300"))
            ts_value = int(ts_header)
            if abs(int(datetime.utcnow().timestamp()) - ts_value) > tolerance_seconds:
                return False
        except ValueError:
            return False

    ts_match = False
    if signed_with_ts:
        ts_match = hmac.compare_digest(incoming_signature, signed_with_ts)

    return hmac.compare_digest(incoming_signature, expected_signature) or ts_match


def is_allowed_callback_ip(provider: str) -> bool:
    source_ip = get_client_ip()
    allowlist = get_live_payment_setting(f"{provider}_allowed_ips", "")
    if not allowlist:
        return True

    allowed_ips = [item.strip() for item in allowlist.split(",") if item.strip()]
    return source_ip in allowed_ips


def record_webhook_event(provider: str, event_id: str, reference: str, status: str) -> None:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO payment_webhook_events (
                provider,
                event_id,
                reference,
                status,
                source_ip
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (provider, event_id, reference, status, get_client_ip())
        )


def is_replayed_webhook_event(event_id: str) -> bool:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM payment_webhook_events WHERE event_id = ?",
            (event_id,)
        )
        return cursor.fetchone() is not None


def process_mobile_money_payment(provider, amount, currency, reference, phone_number, description):
    endpoint_key = f"{provider}_endpoint"
    api_key_name = f"{provider}_api_key"
    endpoint = get_live_payment_setting(endpoint_key, "")
    api_key = get_live_payment_setting(api_key_name, "")

    if not endpoint or not api_key:
        return {
            "ok": False,
            "status": "pending",
            "message": f"{provider} gateway is not configured in system settings.",
            "provider_reference": ""
        }

    payload = {
        "reference": reference,
        "amount": round(float(amount), 2),
        "currency": currency,
        "phone": phone_number,
        "description": description,
        "callback_url": request.host_url.rstrip("/") + "/payments/callback"
    }

    if provider == "mixbyyas":
        payload.update({
            "merchant_reference": reference,
            "customer_msisdn": phone_number,
            "provider": "mixbyyas"
        })
    elif provider == "halopesa":
        payload.update({
            "external_reference": reference,
            "msisdn": phone_number,
            "provider": "halopesa"
        })

    body = json.dumps(payload).encode("utf-8")
    req = urllib_request.Request(
        endpoint,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        },
        method="POST"
    )

    try:
        with urllib_request.urlopen(req, timeout=15) as response:
            raw = response.read().decode("utf-8") if response else "{}"
            data = json.loads(raw or "{}")

        normalized_status = map_gateway_status(data.get("status", "pending"))
        provider_reference = str(extract_first_value(data, [
            "transaction_id", "transaction_ref", "reference", "external_reference", "merchant_reference"
        ]))
        if normalized_status == "paid":
            return {
                "ok": True,
                "status": "paid",
                "message": data.get("message", "Payment completed successfully."),
                "provider_reference": provider_reference
            }

        return {
            "ok": False,
            "status": normalized_status,
            "message": data.get("message", "Payment request submitted and is pending confirmation."),
            "provider_reference": provider_reference
        }
    except (urllib_error.URLError, TimeoutError, ValueError, OSError) as exc:
        return {
            "ok": False,
            "status": "pending",
            "message": f"Gateway request failed: {exc}",
            "provider_reference": ""
        }


@app.route("/payments", methods=["GET", "POST"])
@login_required
@require_permission("payments.view")
def payments_page():
    allowed_methods = {"mixbyyas", "halopesa", "card", "bank", "cash"}
    allowed_currencies = {"USD", "EUR"}
    provider_labels = {
        "mixbyyas": "Mix by YAS",
        "halopesa": "HaloPesa",
        "card": "Card",
        "bank": "Bank",
        "cash": "Cash"
    }

    if request.method == "POST":
        if not user_can("payments.create"):
            flash("You do not have permission to create payments.", "danger")
            return redirect("/payments")

        plan_name = request.form.get("plan_name", "Monthly Subscription").strip() or "Monthly Subscription"
        amount_text = request.form.get("amount", "").strip()
        currency = request.form.get("currency", "USD").strip().upper()
        payment_method = request.form.get("payment_method", "mixbyyas").strip().lower()
        phone_number = request.form.get("phone_number", "").strip()
        notes = request.form.get("notes", "").strip()

        try:
            amount = float(amount_text)
        except ValueError:
            flash("Please provide a valid amount.", "danger")
            return redirect("/payments")

        if amount <= 0:
            flash("Amount must be greater than zero.", "danger")
            return redirect("/payments")

        if payment_method not in allowed_methods:
            flash("Unsupported payment method selected.", "danger")
            return redirect("/payments")

        if currency not in allowed_currencies:
            flash("Currency must be USD or EUR.", "danger")
            return redirect("/payments")

        if payment_method in {"mixbyyas", "halopesa"} and not phone_number:
            flash("Phone number is required for mobile money payments.", "danger")
            return redirect("/payments")

        reference = f"PAY-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(3).upper()}"

        status = "pending"
        paid_at = None
        gateway_message = ""

        if payment_method in {"mixbyyas", "halopesa"}:
            gateway_result = process_mobile_money_payment(
                payment_method,
                amount,
                currency,
                reference,
                phone_number,
                f"{plan_name} for {current_user.username}"
            )
            status = gateway_result["status"]
            if status == "paid":
                paid_at = datetime.utcnow().isoformat()
            provider_ref = gateway_result.get("provider_reference", "")
            gateway_message = gateway_result.get("message", "")
            if provider_ref:
                notes = f"{notes} ProviderRef: {provider_ref}".strip()
            if gateway_message:
                notes = f"{notes} Gateway: {gateway_message}".strip()

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO payments (
                    user_id,
                    plan_name,
                    amount,
                    currency,
                    payment_method,
                    reference,
                    status,
                    notes,
                    paid_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (current_user.id, plan_name, amount, currency, payment_method, reference, status, notes, paid_at)
            )

        save_audit(
            current_user.username,
            "PAYMENT_CREATE",
            f"Created payment {reference} with amount {amount:.2f} {currency} via {provider_labels[payment_method]}"
        )

        create_notification(
            current_user.id,
            "Payment Created",
            f"Payment request {reference} was created successfully.",
            "info"
        )

        if gateway_message:
            flash(gateway_message, "info")
        flash("Payment created successfully.", "success")
        return redirect("/payments")

    with get_db() as conn:
        cursor = conn.cursor()
        if is_management_role(current_user.role):
            cursor.execute(
                """
                SELECT p.id,
                       p.user_id,
                       u.username,
                       p.plan_name,
                       p.amount,
                       p.currency,
                       p.payment_method,
                       p.reference,
                       p.status,
                       p.notes,
                       p.created_at,
                       p.paid_at
                FROM payments p
                LEFT JOIN users u ON u.id = p.user_id
                ORDER BY p.created_at DESC
                LIMIT 200
                """
            )
        else:
            cursor.execute(
                """
                SELECT p.id,
                       p.user_id,
                       u.username,
                       p.plan_name,
                       p.amount,
                       p.currency,
                       p.payment_method,
                       p.reference,
                       p.status,
                       p.notes,
                       p.created_at,
                       p.paid_at
                FROM payments p
                LEFT JOIN users u ON u.id = p.user_id
                WHERE p.user_id = ?
                ORDER BY p.created_at DESC
                LIMIT 200
                """,
                (current_user.id,)
            )
        records = cursor.fetchall()

    return render_template(
        "payments.html",
        records=records,
        stats=fetch_payment_stats(records),
        can_manage=is_management_role(current_user.role)
    )


@app.route("/payments/<int:payment_id>/status", methods=["POST"])
@login_required
@require_permission("payments.approve")
def update_payment_status(payment_id):
    next_status = request.form.get("status", "").strip().lower()
    allowed_statuses = {"pending", "paid", "failed", "cancelled"}

    if next_status not in allowed_statuses:
        flash("Invalid payment status.", "danger")
        return redirect("/payments")

    paid_at = datetime.utcnow().isoformat() if next_status == "paid" else None

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT reference FROM payments WHERE id = ?", (payment_id,))
        payment = cursor.fetchone()
        if payment is None:
            flash("Payment not found.", "danger")
            return redirect("/payments")

        cursor.execute(
            "UPDATE payments SET status = ?, paid_at = ? WHERE id = ?",
            (next_status, paid_at, payment_id)
        )

    save_audit(
        current_user.username,
        "PAYMENT_STATUS_UPDATE",
        f"Updated {payment['reference']} to {next_status}"
    )
    flash("Payment status updated.", "success")
    return redirect("/payments")


@app.route("/payments/<int:payment_id>/invoice")
@login_required
@require_permission("payments.invoice")
def payment_invoice(payment_id):
    with get_db() as conn:
        cursor = conn.cursor()
        if is_management_role(current_user.role):
            cursor.execute(
                """
                SELECT p.*, u.username, u.email
                FROM payments p
                LEFT JOIN users u ON u.id = p.user_id
                WHERE p.id = ?
                """,
                (payment_id,)
            )
        else:
            cursor.execute(
                """
                SELECT p.*, u.username, u.email
                FROM payments p
                LEFT JOIN users u ON u.id = p.user_id
                WHERE p.id = ? AND p.user_id = ?
                """,
                (payment_id, current_user.id)
            )
        payment = cursor.fetchone()

    if payment is None:
        flash("Payment not found.", "danger")
        return redirect("/payments")

    payment_record = dict(payment)

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        title=f"Invoice {payment_record['reference']}",
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch
    )
    styles = getSampleStyleSheet()

    elements = [
        Paragraph("Cyber Security Automation - Payment Invoice", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Invoice Reference: {payment_record['reference']}", styles["Heading3"]),
        Paragraph(f"Customer: {payment_record['username'] or 'Unknown'}", styles["Normal"]),
        Paragraph(f"Email: {payment_record['email'] or '-'}", styles["Normal"]),
        Paragraph(f"Plan: {payment_record['plan_name']}", styles["Normal"]),
        Paragraph(f"Payment Method: {str(payment_record['payment_method']).upper()}", styles["Normal"]),
        Paragraph(f"Status: {str(payment_record['status']).upper()}", styles["Normal"]),
        Paragraph(f"Amount: {float(payment_record['amount']):.2f} {payment_record['currency']}", styles["Normal"]),
        Paragraph(f"Created At: {payment_record['created_at']}", styles["Normal"]),
        Paragraph(f"Paid At: {payment_record['paid_at'] or '-'}", styles["Normal"]),
        Spacer(1, 12),
        Paragraph(f"Notes: {payment_record['notes'] or '-'}", styles["Normal"])
    ]

    doc.build(elements)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"invoice_{payment_record['reference']}.pdf",
        mimetype="application/pdf"
    )


@app.route("/payments/callback", methods=["POST"])
def payments_callback():
    raw_body = request.get_data(cache=True)
    payload = request.get_json(silent=True) or {}

    provider_raw = (
        payload.get("provider")
        or request.args.get("provider")
        or request.headers.get("X-Payment-Provider", "")
    )
    provider = str(provider_raw or "").strip().lower()

    if provider and not is_allowed_callback_ip(provider):
        return jsonify({"ok": False, "message": "callback IP is not allowed"}), 403

    if not verify_callback_signature(provider, raw_body):
        return jsonify({"ok": False, "message": "invalid callback signature"}), 401

    reference = str(extract_first_value(payload, [
        "reference", "merchant_reference", "external_reference", "order_id", "invoice_id", "transaction_ref"
    ])).strip()
    normalized_status = map_gateway_status(extract_first_value(payload, ["status", "transaction_status"]))

    if not reference:
        return jsonify({"ok": False, "message": "reference is required"}), 400

    event_raw = extract_first_value(payload, ["event_id", "id", "transaction_id", "callback_id"])
    event_id = str(event_raw or "").strip()
    if not event_id:
        digest = hashlib.sha256(raw_body).hexdigest()[:16]
        event_id = f"{provider or 'gateway'}:{reference}:{digest}"

    if is_replayed_webhook_event(event_id):
        return jsonify({"ok": True, "reference": reference, "status": "duplicate"})

    paid_at = datetime.utcnow().isoformat() if normalized_status == "paid" else None

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, user_id FROM payments WHERE reference = ?", (reference,))
        payment = cursor.fetchone()
        if payment is None:
            return jsonify({"ok": False, "message": "payment not found"}), 404

        cursor.execute(
            "UPDATE payments SET status = ?, paid_at = ? WHERE reference = ?",
            (normalized_status, paid_at, reference)
        )

    record_webhook_event(provider or "unknown", event_id, reference, normalized_status)

    payment_user_id = dict(payment).get("user_id")
    if normalized_status == "paid" and payment_user_id is not None:
        create_notification(
            payment_user_id,
            "Payment Confirmed",
            f"Payment {reference} has been confirmed.",
            "success"
        )

    return jsonify({"ok": True, "reference": reference, "status": normalized_status})


@app.route("/payments/gateway-health")
@login_required
@require_permission("payments.approve")
def payments_gateway_health():
    providers = ["mixbyyas", "halopesa"]
    rows = []

    with get_db() as conn:
        cursor = conn.cursor()
        for provider in providers:
            cursor.execute(
                """
                SELECT event_id, reference, status, source_ip, created_at
                FROM payment_webhook_events
                WHERE provider = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (provider,)
            )
            last_event = cursor.fetchone()
            rows.append({
                "provider": provider,
                "endpoint": get_live_payment_setting(f"{provider}_endpoint", ""),
                "has_api_key": bool(get_live_payment_setting(f"{provider}_api_key", "")),
                "has_webhook_secret": bool(get_live_payment_setting(f"{provider}_webhook_secret", "")),
                "allowed_ips": get_live_payment_setting(f"{provider}_allowed_ips", ""),
                "endpoint_from_env": is_live_payment_setting_from_env(f"{provider}_endpoint"),
                "api_key_from_env": is_live_payment_setting_from_env(f"{provider}_api_key"),
                "webhook_secret_from_env": is_live_payment_setting_from_env(f"{provider}_webhook_secret"),
                "last_event": dict(last_event) if last_event else None
            })

    return render_template(
        "payments_health.html",
        gateways=rows,
        webhook_tolerance=get_live_payment_setting("payment_webhook_tolerance_seconds", "300")
    )


@app.route("/notifications")
@login_required
def notifications():
    unread_only = request.args.get("unread") == "1"
    items = NotificationManager.get_user_notifications(
        current_user.id,
        unread_only=unread_only,
        limit=50
    )

    return render_template(
        "notifications.html",
        notifications=items,
        unread_count=NotificationManager.get_unread_count(current_user.id)
    )


@app.route("/notifications/<int:notification_id>/read", methods=["POST"])
@login_required
def mark_notification_read(notification_id):
    NotificationManager.mark_as_read(notification_id)
    return redirect(request.referrer or "/notifications")


@app.route("/notifications/read-all", methods=["POST"])
@login_required
def mark_all_notifications_read():
    NotificationManager.mark_all_as_read(current_user.id)
    return redirect("/notifications")


@app.route("/settings", methods=["GET", "POST"])
@login_required
@require_role("super_admin", "security_admin", "admin")
def settings_page():
    if request.method == "POST":
        for key, setting in SystemSettings.get_all().items():
            form_value = request.form.get(f"setting_{key}")
            if form_value is None:
                continue
            set_setting(key, form_value, setting.get("type", "string"), setting.get("description", ""))

        save_audit(current_user.username, "SETTINGS_UPDATE", "System settings updated.")
        flash("Settings updated successfully.", "success")
        return redirect("/settings")

    return render_template(
        "settings.html",
        settings=SystemSettings.get_all()
    )


@app.route("/audit")
@login_required
@require_role("super_admin", "security_admin", "admin")
def audit_logs():
    search = request.args.get("search", "").strip()

    with get_db() as conn:
        cursor = conn.cursor()
        if search:
            cursor.execute(
                """
                SELECT *
                FROM audit_logs
                WHERE username LIKE ?
                   OR action LIKE ?
                   OR details LIKE ?
                ORDER BY log_time DESC
                LIMIT 200
                """,
                (f"%{search}%", f"%{search}%", f"%{search}%")
            )
        else:
            cursor.execute(
                """
                SELECT *
                FROM audit_logs
                ORDER BY log_time DESC
                LIMIT 200
                """
            )
        records = cursor.fetchall()

    return render_template(
        "audit_logs.html",
        records=records,
        search=search
    )


@app.route("/backup", methods=["GET", "POST"])
@login_required
@require_role("super_admin", "security_admin", "admin")
def backup_center():
    message = None

    if request.method == "POST":
        action = request.form.get("action", "create")

        if action == "create":
            backup_path = create_backup()
            size_bytes = os.path.getsize(backup_path)
            save_backup_log("database", backup_path, size_bytes, "success", current_user.username)
            save_audit(current_user.username, "BACKUP_CREATE", backup_path)
            create_notification(current_user.id, "Backup Created", f"Backup saved to {backup_path}", "success")
            flash("Backup created successfully.", "success")
            return redirect("/backup")

        if action == "restore":
            backup_name = request.form.get("backup_name", "").strip()
            if not backup_name:
                flash("Please choose a backup file.", "danger")
                return redirect("/backup")

            backup_path = os.path.join(BACKUP_DIR, backup_name)
            try:
                restore_backup(backup_path)
                size_bytes = os.path.getsize(backup_path)
                save_backup_log("database", backup_path, size_bytes, "restored", current_user.username, datetime.utcnow().isoformat())
                save_audit(current_user.username, "BACKUP_RESTORE", backup_path)
                flash("Backup restored successfully. Restart the app to reload the database file if needed.", "success")
                return redirect("/backup")
            except FileNotFoundError:
                flash("Backup file not found.", "danger")

    return render_template(
        "backup.html",
        backups=list_backups(),
        backup_logs=get_backup_log_entries(),
        backup_dir=BACKUP_DIR,
        message=message
    )


@app.route("/api")
@login_required
def api_dashboard():
    return render_template("api_dashboard.html")


@app.route("/api/health")
@login_required
def api_health():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        users_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM scan_history")
        scans_count = cursor.fetchone()[0]

    return jsonify({
        "status": "ok",
        "database": "postgresql" if is_postgres_enabled() else "sqlite",
        "users": users_count,
        "scans": scans_count,
        "timestamp": datetime.utcnow().isoformat(),
    })


@app.route("/api/scans")
@login_required
def api_scans():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT scan_type, target, result, scan_date
            FROM scan_history
            ORDER BY scan_date DESC
            LIMIT 25
            """
        )
        records = [dict(row) for row in cursor.fetchall()]

    return jsonify({"items": records})


@app.route("/api/notifications")
@login_required
def api_notifications():
    items = [item.to_dict() for item in NotificationManager.get_user_notifications(current_user.id, limit=25)]
    return jsonify({"items": items})


@app.route("/api/settings")
@login_required
@require_role("super_admin", "security_admin", "admin")
def api_settings():
    return jsonify(SystemSettings.get_all())


@app.route("/email-alerts", methods=["GET", "POST"])
@login_required
@require_role("super_admin", "security_admin", "admin")
def email_alerts_page():
    result = None

    if request.method == "POST":
        smtp_server = request.form.get("smtp_server", "").strip()
        smtp_port = request.form.get("smtp_port", "587").strip()
        smtp_email = request.form.get("smtp_email", "").strip()
        smtp_password = request.form.get("smtp_password", "")
        recipients = [item.strip() for item in request.form.get("recipients", "").split(",") if item.strip()]
        subject = request.form.get("subject", "Cyber Security Alert").strip()
        body = request.form.get("body", "Test alert from Cyber Security Automation.").strip()

        if smtp_server:
            set_setting("smtp_server", smtp_server, "string", "Email server for alerts")
        if smtp_port:
            set_setting("smtp_port", smtp_port, "string", "Email server port")
        if smtp_email:
            set_setting("smtp_email", smtp_email, "string", "Email account for alerts")
        if smtp_password:
            set_setting("smtp_password", smtp_password, "string", "Email password")

        if recipients:
            result = send_email_alert(subject, body, recipients)
            if result.get("sent"):
                save_audit(current_user.username, "EMAIL_ALERT_SENT", subject)
                create_notification(current_user.id, "Email Alert Sent", subject, "success")
                flash("Email alert sent successfully.", "success")
            else:
                flash(result.get("reason", "Email alert could not be sent."), "warning")
        else:
            flash("Please provide at least one recipient.", "danger")

    return render_template(
        "email_alerts.html",
        smtp_server=get_setting("smtp_server", "smtp.gmail.com"),
        smtp_port=get_setting("smtp_port", "587"),
        smtp_email=get_setting("smtp_email", ""),
        email_enabled=get_setting("enable_email_alerts", "1"),
        result=result
    )


@app.route("/nmap", methods=["GET", "POST"])
@login_required
def nmap_page():
    result = None

    if request.method == "POST":
        target = request.form.get("target", "").strip()
        if not target:
            flash("Please enter a target host.", "danger")
        else:
            result = run_nmap_scan(target)
            save_scan("NMAP", target, result)
            save_audit(current_user.username, "NMAP_SCAN", target)
            create_notification(current_user.id, "Nmap Scan Complete", f"Scan finished for {target}", "success")

    return render_template("nmap_scanner.html", result=result)


@app.route("/vulnerabilities", methods=["GET", "POST"])
@login_required
def vulnerability_page():
    result = None

    if request.method == "POST":
        target = request.form.get("target", "").strip()
        if not is_valid_host(target):
            flash("Please enter a valid hostname or IP address.", "danger")
        else:
            open_ports = scan(target, 1, 1000)
            result = scan_vulnerabilities(open_ports, target)
            save_scan("VULNERABILITY", target, result)
            save_audit(current_user.username, "VULNERABILITY_SCAN", target)
            if any(item.get("severity") == "high" for item in result):
                create_notification(current_user.id, "High Risk Vulnerability", f"High-risk exposure found on {target}", "danger")

    return render_template("vulnerability_scanner.html", result=result)


@app.route("/malware", methods=["GET", "POST"])
@login_required
def malware_page():
    result = None

    if request.method == "POST":
        path_value = request.form.get("path", "").strip()
        if not path_value or (not os.path.exists(path_value)):
            flash("File not found or invalid path.", "danger")
        else:
            result = scan_malware_path(path_value)
            save_scan("MALWARE", path_value, result)
            save_audit(current_user.username, "MALWARE_SCAN", path_value)
            if result.get("risk") == "high":
                create_notification(current_user.id, "Malware Risk Detected", f"High-risk indicators found in {path_value}", "danger")

    return render_template("malware_scanner.html", result=result)


@app.route("/threat-intel", methods=["GET", "POST"])
@login_required
def threat_intel_page():
    result = None

    if request.method == "POST":
        indicator = request.form.get("indicator", "").strip()
        if not indicator:
            flash("Please enter an IP, domain, or network indicator.", "danger")
        else:
            result = lookup_indicator(indicator)
            save_scan("THREAT_INTEL", indicator, result)
            save_audit(current_user.username, "THREAT_INTEL_LOOKUP", indicator)

    return render_template("threat_intel.html", result=result)


@app.route("/assistant", methods=["GET", "POST"])
@login_required
def assistant_page():
    result = None
    user_context = ""

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT scan_type, target, result
            FROM scan_history
            ORDER BY scan_date DESC
            LIMIT 5
            """
        )
        recent_scans = cursor.fetchall()

    if request.method == "POST":
        user_context = request.form.get("context", "").strip()
        result = summarize_security_state(
            scan_results={"recent_scans": [list(row) for row in recent_scans]},
            vulnerability_results=[],
            malware_results={},
            threat_results={}
        )
        if user_context:
            result["summary"] = f"{result['summary']} Context: {user_context}"
        save_audit(current_user.username, "AI_ASSISTANT_QUERY", user_context or "general review")

    return render_template(
        "ai_assistant.html",
        result=result,
        recent_scans=recent_scans,
        user_context=user_context
    )


@app.route("/deployment")
@login_required
def deployment_page():
    return render_template("deployment.html")


@app.route("/history")
@login_required
def history():
    search = request.args.get("search", "").strip()

    with get_db() as conn:
        cursor = conn.cursor()
        if search:
            cursor.execute("""
                SELECT *
                FROM scan_history
                WHERE scan_type LIKE ?
                   OR target LIKE ?
                ORDER BY scan_date DESC
            """,
            (
                f"%{search}%",
                f"%{search}%"
            ))
        else:
            cursor.execute("""
                SELECT *
                FROM scan_history
                ORDER BY scan_date DESC
            """)
        records = cursor.fetchall()

    return render_template(
        "history.html",
        records=records,
        search=search
    )

@app.route("/report")
@login_required
def report():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT scan_type,
                   target,
                   scan_date
            FROM scan_history
            ORDER BY scan_date DESC
        """)
        records = cursor.fetchall()

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer)

    styles = getSampleStyleSheet()

    elements = []

    title = Paragraph(
        "Cyber Security Automation Report",
        styles["Title"]
    )

    elements.append(title)

    elements.append(Spacer(1, 12))

    data = [["Scan Type", "Target", "Date"]]

    for row in records:
        data.append([
            row[0],
            row[1],
            str(row[2])
        ])

    table = Table(data)

    table.setStyle(
        TableStyle([
            ('BACKGROUND',(0,0),(-1,0),colors.grey),
            ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
            ('GRID',(0,0),(-1,-1),1,colors.black),
            ('BACKGROUND',(0,1),(-1,-1),colors.beige)
        ])
    )

    elements.append(table)
    doc.build(elements)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="scan_report.pdf",
        mimetype="application/pdf"
    )


@app.route("/delete_user/<int:user_id>")
@login_required
@admin_required
def delete_user(user_id):

    if user_id == 1:
        flash("Admin cannot be deleted.", "danger")
        return redirect("/users")

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM users WHERE id=?",
            (user_id,)
        )

    return redirect("/users")

@app.route("/logout")
@login_required
def logout():

    save_audit(current_user.username, "LOGOUT", "User logged out.")
    logout_user()

    return redirect("/login")



if __name__ == "__main__":

    init_database()

    app.run(debug=True)