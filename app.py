from flask import (
    Flask,
    render_template,
    request,
    redirect,
    send_file,
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

from scanners.port_scanner import scan
from scanners.network_scanner import scan_network

from security.password_checker import check
from security.log_analyzer import analyze_log
from security.integrity_monitor import calculate_hash

import re
import secrets
import sqlite3
import os
import socket
import ipaddress
from datetime import datetime, timedelta


DB_PATH = os.path.join(
    os.path.dirname(__file__),
    "database.db"
)

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
        "Total scans recorded": "Skanu zote zilizorekodiwa",
        "Scan types tracked": "Aina za skanu zinazoangaliwa",
        "Recent scan entries": "Kuingia za skanu za hivi karibuni",
        "Total users": "Watumiaji wote",
        "new in 30d": "mpya ndani ya siku 30",
        "Modules": "Moduli",
        "Port Scanner": "Kichunguzi cha Bandari",
        "Network Scanner": "Kichunguzi cha Mtandao",
        "Password Checker": "Kikagua Nenosiri",
        "Log Analyzer": "Mchambuzi wa Logi",
        "Integrity Monitor": "Kikagua Uadilifu",
        "User Management": "Usimamizi wa Watumiaji",
        "Scan History": "Historia ya Skanu",
        "Change Password": "Badilisha Nenosiri",
        "Current Password": "Nenosiri la sasa",
        "New Password": "Nenosiri jipya",
        "Confirm New Password": "Thibitisha nenosiri jipya",
        "Search and review recorded scan activity.": "Tafuta na uangalie shughuli za skanu zilizorekodiwa.",
        "Search by scan type or target...": "Tafuta kwa aina ya skanu au lengo...",
        "Search": "Tafuta",
        "No scan history found.": "Hakuna historia ya skanu iliyopatikana.",
        "Type": "Aina",
        "Target": "Lengo",
        "Date": "Tarehe",
        "Result": "Matokeo",
        "Scan Results": "Matokeo ya Skanu",
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
        "Scan": "Fanya skanu",
        "Check": "Kagua",
        "Analyze": "Chambua",
        "Scan Network": "Fanya skanu ya mtandao",
        "Number of Scans": "Idadi ya skanu",
        "Scan Statistics": "Takwimu za skanu",
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

app.secret_key = secrets.token_hex(32)

login_manager = LoginManager()
login_manager.init_app(app)

setattr(login_manager, "login_view", "login")

@app.context_processor
def inject_translations():
    return {
        "_": translate,
        "current_language": get_locale(),
        "available_languages": LANGUAGES
    }


@app.route("/language/<lang>")
def set_language(lang):
    if lang not in LANGUAGES:
        lang = "en"
    response = make_response(redirect(request.referrer or "/"))
    response.set_cookie("lang", lang, max_age=60 * 60 * 24 * 365)
    return response


def init_database():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Create users table
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

        # Create scan history table
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
            SELECT id
            FROM users
            WHERE username = ?
        """, ("admin",))

        admin = cursor.fetchone()

        if admin is None:
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
                "admin"
            ))

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                attempts INTEGER DEFAULT 0,
                last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)


def get_db():
    conn = sqlite3.connect(DB_PATH)
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
        if current_user.role != "admin":
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
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id,
                   username,
                   role
            FROM users
            WHERE id = ?
        """, (user_id,))
        user = cursor.fetchone()

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
                SELECT
                    id,
                    username,
                    password,
                    role
                FROM users
                WHERE username = ?
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
        if current_user.is_authenticated and current_user.role == "admin":
            cursor.execute("SELECT COUNT(*) FROM users")
            total_users = cursor.fetchone()[0]
            cursor.execute(
                "SELECT COUNT(*) FROM users WHERE created_at >= datetime('now', '-30 days')"
            )
            new_users_last_30 = cursor.fetchone()[0]

    return render_template(
        "dashboard.html",
        total_scans=total_scans,
        recent_scans=recent_scans,
        stats=stats,
        total_users=total_users,
        new_users_last_30=new_users_last_30
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

    logout_user()

    return redirect("/login")



if __name__ == "__main__":

    init_database()

    app.run(debug=True)