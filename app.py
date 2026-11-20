"""
Secure Web Application - User Management System
Student 1 part: basic app (register, login, dashboard, logout)
and SQL Injection detection and mitigation.
"""

import sqlite3
from flask import Flask, render_template, request, session, redirect
import hashlib  # used for MD5 hashing (weak - for demonstration only)
import re      # regular expressions - used to check password rules
import bcrypt  # strong password hashing (salted + slow on purpose)
import bleach  # removes dangerous HTML/JavaScript from user input (XSS protection)
app = Flask(__name__)

# Secret key used to sign the session cookie so users cannot modify it
app.secret_key = "change-this-secret-key"


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
        if not is_strong_password(password):
            message = "Password does not meet the requirements below"
            return render_template("register.html", message=message)
        conn = sqlite3.connect("database.db")
        try:
            # VULNERABLE VERSION (before fix):
            #   query = f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')"
            # User input was inserted directly into the SQL string,
            # so an attacker could inject SQL code.
            #
            # SECURE: parameterized query - user input is treated as data, not SQL code
            # BEFORE (weak): hashed = hashlib.md5(password.encode()).hexdigest()
            # MD5 is fast and unsalted -> cracked instantly by crackstation.
            # SECURE: bcrypt adds a random salt to every password (so the same
            # password gives a different hash each time) and is slow on purpose,
            # which makes rainbow tables and brute-force attacks impractical.
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


# Login: check the user's credentials and start a session
@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = sqlite3.connect("database.db")
        # VULNERABLE VERSION (before fix):
        #   query = f"SELECT ... WHERE username='{username}' AND password='{password}'"
        # Entering  ' OR '1'='1' --  as username bypassed the login,
        # because '1'='1' is always true and -- comments out the password check.
        #
        # SECURE: parameterized query prevents SQL Injection
        # bcrypt hashes contain a random salt, so we cannot compare them
        # inside SQL. Get the user by username, then let bcrypt check it.
        row = conn.execute(
            "SELECT username, password, role FROM users WHERE username=?",
            (username,)
        ).fetchone()
        conn.close()
        if row and bcrypt.checkpw(password.encode(), row[1].encode()):
            # Store user info in the session to keep them logged in
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
# Comments page: logged-in users can post and read comments
@app.route("/comments", methods=["GET", "POST"])
def comments():
    if "username" not in session:
        return redirect("/login")
    conn = sqlite3.connect("database.db")
    if request.method == "POST":
                # BEFORE (vulnerable): content = request.form["content"]
        # The comment was saved as typed, so <script> tags ran in the browser.
        # SECURE: bleach removes every HTML tag except a few harmless
        # formatting tags (<b>, <i>, <u>). <script>, onerror=, onclick=, etc.
        # are stripped, so the browser can no longer run attacker code.
        content = bleach.clean(
            request.form["content"],
            tags={"b", "i", "u"},
            strip=True
        )
        conn.execute(
            "INSERT INTO comments (username, content) VALUES (?, ?)",
            (session["username"], content)
        )
        conn.commit()
    rows = conn.execute("SELECT username, content FROM comments ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("comments.html", comments=rows)

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
    app.run(debug=True)