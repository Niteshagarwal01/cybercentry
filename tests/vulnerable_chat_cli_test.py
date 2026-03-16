"""Deliberately vulnerable file for chat CLI end-to-end testing.

This file is intentionally insecure and should never be used in production.
"""

import hashlib
import sqlite3
import subprocess


def insecure_login_lookup(username: str):
    """SQL injection: direct string concatenation."""
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cur.execute(query)
    return cur.fetchone()


def insecure_ping(host: str) -> str:
    """Command injection: shell=True with user-controlled input."""
    result = subprocess.run(
        f"ping -n 1 {host}",
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def weak_hash(password: str) -> str:
    """Weak cryptography: MD5 for security-sensitive hashing."""
    return hashlib.md5(password.encode("utf-8")).hexdigest()
