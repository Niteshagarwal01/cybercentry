"""Deliberately vulnerable code for security scanner testing only.

WARNING: Never deploy this code.
"""

import hashlib
import os
import pickle
import random
import sqlite3
import subprocess
import tempfile
from urllib.request import urlopen

import yaml


# Hardcoded secrets (CWE-259 / CWE-798)
DB_USER = "admin"
DB_PASSWORD = "password123"
API_TOKEN = "prod-token-very-secret"


def sql_injection_get_user(username: str):
    """Unsafe string concatenation in SQL query."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


def command_injection(user_input: str) -> str:
    """Runs user-controlled shell command."""
    completed = subprocess.run(
        f"echo scanning {user_input}",
        shell=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def dangerous_eval(expression: str):
    """Directly evaluates untrusted expression."""
    return eval(expression)


def insecure_deserialization(blob: bytes):
    """Deserializes untrusted bytes with pickle."""
    return pickle.loads(blob)


def weak_password_hash(password: str) -> str:
    """Weak hash function for passwords."""
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def unsafe_temp_file() -> str:
    """Insecure temporary file creation."""
    return tempfile.mktemp(prefix="agent-test-")


def weak_token() -> str:
    """Predictable token generated from non-crypto RNG."""
    return str(random.randint(100000, 999999))


def path_traversal_read(filename: str) -> str:
    """Reads arbitrary path by trusting user filename."""
    with open("uploads/" + filename, "r", encoding="utf-8") as handle:
        return handle.read()


def ssl_bypass(url: str) -> bytes:
    """Fetches URL without TLS verification protections."""
    import requests

    response = requests.get(url, verify=False, timeout=10)
    return response.content


def unsafe_yaml_load(yaml_text: str):
    """Executes arbitrary constructors with unsafe loader."""
    return yaml.load(yaml_text, Loader=yaml.Loader)


def broad_exception_suppression() -> None:
    """Hides security-relevant failures."""
    try:
        os.remove("/tmp/definitely-not-here")
    except Exception:
        pass


def assert_for_auth(is_admin: bool) -> None:
    """Uses assert for access control."""
    assert is_admin


def insecure_http_fetch(host: str) -> bytes:
    """Uses plain HTTP and no validation."""
    return urlopen(f"http://{host}/admin/export").read()
