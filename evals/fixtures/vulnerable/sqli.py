"""Synthetic fixture: unambiguous SQL injection via string formatting.
Used by evals to check whether sast_agent/injection_agent catch it."""

import sqlite3
from flask import Flask, request

app = Flask(__name__)


def get_db():
    return sqlite3.connect("app.db")


@app.route("/users/search")
def search_users():
    name = request.args.get("name")
    db = get_db()
    cursor = db.cursor()
    # VULNERABLE: user input concatenated directly into the query string.
    query = f"SELECT id, email, is_admin FROM users WHERE name = '{name}'"
    cursor.execute(query)
    return {"results": cursor.fetchall()}


@app.route("/orders")
def list_orders():
    status = request.args.get("status", "pending")
    db = get_db()
    cursor = db.cursor()
    # VULNERABLE: same pattern with % formatting instead of f-string.
    cursor.execute("SELECT * FROM orders WHERE status = '%s'" % status)
    return {"orders": cursor.fetchall()}
