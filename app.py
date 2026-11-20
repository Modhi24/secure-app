"""
Secure Web Application - User Management System
Student 1 part: basic app (register, login, dashboard, logout)
and SQL Injection detection and mitigation.
"""

import os
import sqlite3
from datetime import timedelta
from pathlib import Path
from flask import Flask, render_template, request, session, redirect, abort
from functools import wraps
import re      # regular expressions - used to check password rules
import bcrypt  # strong password hashing (salted + slow on purpose)
import bleach  # removes dangerous HTML/JavaScript from user input (XSS protection)
from session_security import EncryptedSessionInterface

app = Flask(__name__)
app.config.update(
    SESSION_COOKIE_SECURE=True,    # Send the session cookie over HTTPS.
    SESSION_COOKIE_HTTPONLY=True,  # Prevent browser scripts from reading it.
    SESSION_COOKIE_SAMESITE="Lax", # Restrict cross-site sending.
    SESSION_COOKIE_NAME="secure_app_session",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
)

session_key = os.environ.get("SESSION_ENCRYPTION_KEY")
if not session_key:
    raise RuntimeError("Set SESSION_ENCRYPTION_KEY to a Fernet key before starting the app.")
app.session_interface = EncryptedSessionInterface(session_key)


# Create the users table if it does not exist.
# 'role' column is used later for role-based access control (user/admin)
def init_db():
    conn = sqlite3.connect("database.db")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    """)

    # Comments table: stores user comments (used to demonstrate XSS)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            content TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# Home page redirects to the login page
@app.route("/")
def home():
    return redirect("/login")

# Password policy: at least 8 characters, one uppercase, one lowercase,
# one number and one special character. Weak passwords are rejected.
def is_strong_password(p):
    return (len(p) >= 8
            and re.search(r"[A-Z]", p)
            and re.search(r"[a-z]", p)
            and re.search(r"\d", p)
            and re.search(r"[^A-Za-z0-9]", p))

# Registration: create a new user account
@app.route("/register", methods=["GET", "POST"])
def register():
    message = ""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        # Reject weak passwords before saving anything
        if not is_strong_password(password) or len(password.encode("utf-8")) > 72:
            message = "Password does not meet the requirements below"
            return render_template("register.html", message=message)
        conn = sqlite3.connect("database.db")
        try:
            # bcrypt adds a random salt and makes each password guess costly.
            # Bind form values separately from SQL to prevent SQL injection.
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed)
            )
            conn.commit()
            message = "Registered successfully!"
        except Exception as e:
            message = "Error: " + str(e)
        conn.close()
    return render_template("register.html", message=message)


def password_matches(password, stored_hash):
    if len(password.encode("utf-8")) > 72:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
    except ValueError:
        # Earlier demo accounts used plaintext or MD5. Require re-registration.
        return False


# Login: check the user's credentials and start a session
@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = sqlite3.connect("database.db")
        # Bind the username and verify the stored bcrypt hash separately.
        row = conn.execute(
            "SELECT username, password, role FROM users WHERE username=?",
            (username,)
        ).fetchone()
        conn.close()
        if row and password_matches(password, row[1]):
            # Replace any previous session after successful authentication.
            session.clear()
            session["username"] = row[0]
            session["role"] = row[2]
            return redirect("/dashboard")
        message = "Invalid username or password"
    return render_template("login.html", message=message)


# Only logged-in users can see the dashboard; others are redirected to login
@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect("/login")
    return render_template("dashboard.html", username=session["username"], role=session["role"])
def clean_comment(content):
    # Allow simple formatting and remove every HTML attribute.
    return bleach.clean(content, tags={"b", "i", "u"}, attributes={}, strip=True)


# Comments page: logged-in users can post and read comments
@app.route("/comments", methods=["GET", "POST"])
def comments():
    if "username" not in session:
        return redirect("/login")
    conn = sqlite3.connect("database.db")
    if request.method == "POST":
        content = clean_comment(request.form["content"])
        conn.execute(
            "INSERT INTO comments (username, content) VALUES (?, ?)",
            (session["username"], content)
        )
        conn.commit()
    rows = conn.execute("SELECT username, content FROM comments ORDER BY id DESC").fetchall()
    conn.close()
    # Clean earlier comments too, since they may predate the save-time filter.
    safe_rows = [(username, clean_comment(content)) for username, content in rows]
    return render_template("comments.html", comments=safe_rows)

# Admin page: shows all registered users
# VULNERABLE: it only checks that the user is logged in, NOT their role,
# so any normal user can open /admin and see every account.
# RBAC (Role-Based Access Control):
# A decorator that protects a page so only users with the required role
# can open it. The role comes from the database at login and is stored in
# the encrypted and authenticated session, so users cannot change it themselves.
def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "username" not in session:      # Authentication: who are you?
                return redirect("/login")
            if session.get("role") != role:    # Authorization: are you allowed?
                abort(403)                     # 403 Forbidden
            return f(*args, **kwargs)
        return wrapper
    return decorator

# Admin page: shows all registered users
# BEFORE (vulnerable): only checked login, so any user could open /admin.
# SECURE: @role_required("admin") allows admins only; others get 403.
@app.route("/admin")
@role_required("admin")
def admin():
    conn = sqlite3.connect("database.db")
    users = conn.execute("SELECT id, username, role FROM users").fetchall()
    conn.close()
    return render_template("admin.html", users=users)




# Clear the whole session so the user is fully logged out
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# Prevent browser from caching pages, so the Back button
# cannot show the dashboard after logout
@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


if __name__ == "__main__":
    init_db()
    # Use TLS on loopback for the course demo and leave the debugger disabled.
    tls_dir = Path(__file__).resolve().parent / ".local-tls"
    cert = tls_dir / "cert.pem"
    key = tls_dir / "key.pem"
    if not cert.is_file() or not key.is_file():
        raise SystemExit("Run python setup_local_tls.py before starting the app.")
    app.run(host="127.0.0.1", port=5000, debug=False, ssl_context=(str(cert), str(key)))
