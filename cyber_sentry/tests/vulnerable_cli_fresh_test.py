"""Fresh intentionally vulnerable file for end-to-end CLI testing.

This file exists only to exercise CyberSentry scan, triage, debate, and patch flows.
Do not use it in production.
"""

import hashlib
import sqlite3
import subprocess


def lookup_account(username: str):
    """Safe: parameterized query prevents SQL injection."""
    conn = sqlite3.connect("accounts.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchone()


def run_ping(host: str) -> str:
    """Safe: no shell=True, arguments passed as list."""
    result = subprocess.run(
        ["ping", "-n", "1", host],
        capture_output=True,
        text=True,
    )
    return result.stdout


def digest_password(password: str) -> str:
    """Weak hash suppressed as non-security use."""
    return hashlib.md5(password.encode("utf-8"), usedforsecurity=False).hexdigest()
