"""
Helper script: give a user the 'admin' role.
Roles are changed only by the server owner, never from the website,
so a normal user cannot make themselves admin.
Usage: python make_admin.py <username>
"""
import sqlite3
import sys

username = sys.argv[1]
conn = sqlite3.connect("database.db")
conn.execute("UPDATE users SET role='admin' WHERE username=?", (username,))
conn.commit()
conn.close()
print(username, "is now admin")