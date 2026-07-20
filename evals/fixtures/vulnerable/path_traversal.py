"""Synthetic fixture: path traversal via unsanitized filename."""

import os
from flask import Flask, request, send_file

app = Flask(__name__)

UPLOAD_DIR = "/var/app/uploads"


@app.route("/files/<path:filename>")
def get_file(filename: str):
    # VULNERABLE: no normalization/containment check -- a filename of
    # "../../../../etc/passwd" escapes UPLOAD_DIR entirely.
    full_path = os.path.join(UPLOAD_DIR, filename)
    return send_file(full_path)


@app.route("/read-log")
def read_log():
    log_name = request.args.get("name")
    # VULNERABLE: same pattern, second endpoint.
    with open(f"/var/log/app/{log_name}.log") as f:
        return {"content": f.read()}
