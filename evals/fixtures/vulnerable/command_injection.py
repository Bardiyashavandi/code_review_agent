"""Synthetic fixture: command injection via shell=True with user input."""

import os
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping_host():
    host = request.args.get("host")
    # VULNERABLE: shell=True + unsanitized user input -> attacker can chain
    # commands with "; rm -rf /" or similar.
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return {"output": result.stdout.decode()}


@app.route("/convert")
def convert_file():
    filename = request.args.get("filename")
    # VULNERABLE: os.system with unsanitized input.
    os.system(f"convert {filename} {filename}.png")
    return {"status": "converted"}
