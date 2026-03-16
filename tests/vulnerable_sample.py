"""Intentionally vulnerable Python file for testing CyberSentry's full pipeline.

DO NOT use this code in production — it contains deliberate security flaws!
"""

import os
import sqlite3
import subprocess
import pickle
import hashlib


# ==========================================================================
# B608 / CWE-89  — SQL Injection
# ==========================================================================

def get_user(username):
    """Vulnerable to SQL injection — unsanitized user input in query."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


def search_products(keyword):
    """Another SQL injection — f-string in query."""
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM products WHERE name LIKE '%{keyword}%'"
    cursor.execute(query)
    return cursor.fetchall()


# ==========================================================================
# B105 / CWE-259  — Hardcoded Credentials
# ==========================================================================

DATABASE_PASSWORD = "super_secret_password_123"
API_KEY = "sk-live-abc123def456ghi789"
SECRET_KEY = "my-jwt-secret-key-do-not-share"


def connect_to_database():
    """Uses hardcoded password."""
    import pymysql
    return pymysql.connect(
        host="localhost",
        user="admin",
        password="super_secret_password_123",
        database="myapp",
    )


# ==========================================================================
# B307 / CWE-78  — Code Injection via eval()
# ==========================================================================

def calculate(expression):
    """Dangerous eval() on user input."""
    return eval(expression)


def dynamic_import(module_name):
    """Dangerous exec() usage."""
    exec(f"import {module_name}")


# ==========================================================================
# B602 / CWE-78  — Command Injection via shell=True
# ==========================================================================

def ping_host(hostname):
    """Vulnerable to command injection — shell=True with user input."""
    result = subprocess.run(
        f"ping -n 1 {hostname}",
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def list_directory(path):
    """Another command injection."""
    return os.popen(f"ls -la {path}").read()


# ==========================================================================
# B301 / CWE-502  — Insecure Deserialization
# ==========================================================================

def load_user_session(data):
    """Pickle deserialization of untrusted data."""
    return pickle.loads(data)


# ==========================================================================
# B303 / CWE-328  — Weak Cryptographic Hash
# ==========================================================================

def hash_password(password):
    """Using MD5 for password hashing — cryptographically broken."""
    return hashlib.md5(password.encode()).hexdigest()


def verify_integrity(data):
    """Using SHA1 — weak for security purposes."""
    return hashlib.sha1(data.encode()).hexdigest()


# ==========================================================================
# B310 / CWE-22  — Path Traversal
# ==========================================================================

def read_user_file(filename):
    """No path validation — allows directory traversal."""
    with open(f"/app/uploads/{filename}", "r") as f:
        return f.read()


def download_file(url):
    """Unsafe URL handling."""
    import urllib.request
    return urllib.request.urlopen(url).read()


# ==========================================================================
# B110 / CWE-390  — Error Suppression
# ==========================================================================

def risky_operation():
    """Silently swallowing exceptions."""
    try:
        do_something_dangerous()
    except Exception:
        pass


def do_something_dangerous():
    raise RuntimeError("Something went wrong")
