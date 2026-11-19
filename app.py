"""
Secure Web Application - User Management System
Student 1 part: basic app (register, login, dashboard, logout)
and SQL Injection detection and mitigation.
"""

import sqlite3
from flask import Flask, render_template, request, session, redirect

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
    conn.commit()
    conn.close()


# Home page redirects to the login page
@app.route("/")
def home():
    return redirect("/login")


# Registration: create a new user account
@app.route("/register", methods=["GET", "POST"])
def register():
    message = ""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = sqlite3.connect("database.db")
        try:
            # VULNERABLE VERSION (before fix):
            #   query = f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')"
            # User input was inserted directly into the SQL string,
            # so an attacker could inject SQL code.
            #
            # SECURE: parameterized query - user input is treated as data, not SQL code
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, password)
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
        user = conn.execute(
            "SELECT username, role FROM users WHERE username=? AND password=?",
            (username, password)
        ).fetchone()
        conn.close()
        if user:
            # Store user info in the session to keep them logged in
            session["username"] = user[0]
            session["role"] = user[1]
            return redirect("/dashboard")
        message = "Invalid username or password"
    return render_template("login.html", message=message)


# Only logged-in users can see the dashboard; others are redirected to login
@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect("/login")
    return render_template("dashboard.html", username=session["username"], role=session["role"])


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