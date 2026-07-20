"""Synthetic fixture: SSRF via unvalidated user-supplied URL."""

import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch-preview")
def fetch_preview():
    url = request.args.get("url")
    # VULNERABLE: no allowlist/scheme check -- an attacker can pass
    # "http://169.254.169.254/latest/meta-data/" to reach cloud metadata
    # endpoints, or "http://localhost:6379/" to probe internal services.
    resp = requests.get(url, timeout=5)
    return {"content_type": resp.headers.get("content-type"), "body": resp.text[:500]}


@app.route("/webhook-test")
def test_webhook():
    webhook_url = request.json.get("webhook_url")
    # VULNERABLE: same pattern -- server-side request to attacker-controlled
    # destination, with no validation at all.
    requests.post(webhook_url, json={"test": True})
    return {"status": "sent"}
