"""Synthetic fixture: correctly-written auth code that superficially
resembles vulnerable patterns (variable named 'password', a raw-looking
SQL string) but is actually safe. Used to test that validate_findings_tool
correctly flags fabricated findings against this file as false positives."""

import bcrypt
import sqlite3
from flask import Flask, request, session

app = Flask(__name__)


def get_db():
    return sqlite3.connect("app.db")


def hash_password(password: str) -> bytes:
    # Safe: bcrypt with a random per-call salt.
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def verify_password(password: str, stored_hash: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), stored_hash)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    db = get_db()
    cursor = db.cursor()
    # Safe: parameterized query -- the "?" placeholder is bound, not
    # string-interpolated, despite the query text visually resembling the
    # vulnerable f-string pattern elsewhere in this test set.
    cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()

    if row is None or not verify_password(password, row[1]):
        return {"error": "invalid credentials"}, 401

    session["user_id"] = row[0]
    return {"status": "logged in"}


@app.route("/invoices/<int:invoice_id>")
def get_invoice(invoice_id: int):
    if "user_id" not in session:
        return {"error": "not authenticated"}, 401

    db = get_db()
    cursor = db.cursor()
    # Safe: ownership is enforced in the WHERE clause itself, not just an
    # authentication check.
    cursor.execute(
        "SELECT * FROM invoices WHERE id = ? AND owner_id = ?",
        (invoice_id, session["user_id"]),
    )
    row = cursor.fetchone()
    if row is None:
        return {"error": "not found"}, 404
    return {"invoice": row}
