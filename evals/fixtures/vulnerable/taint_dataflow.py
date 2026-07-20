"""Synthetic fixture: multi-hop taint flow -- user input travels through
two helper functions before reaching a dangerous sink, with no sanitizer
anywhere on the path. Designed to test data_flow_agent's ability to trace
taint across function boundaries, not just spot an inline pattern."""

import os
from flask import Flask, request

app = Flask(__name__)


def _normalize_report_name(raw_name: str) -> str:
    # Looks like sanitization, but only strips whitespace -- does nothing
    # to prevent shell metacharacters or path traversal.
    return raw_name.strip()


def _build_export_command(report_name: str) -> str:
    normalized = _normalize_report_name(report_name)
    return f"wkhtmltopdf /reports/{normalized}.html /exports/{normalized}.pdf"


@app.route("/reports/export")
def export_report():
    report_name = request.args.get("report_name")
    # SOURCE: report_name comes straight from the query string.
    # -> _normalize_report_name (no real sanitization)
    # -> _build_export_command (builds a shell command string)
    # SINK: os.system executes it with shell interpretation.
    command = _build_export_command(report_name)
    os.system(command)
    return {"status": "export started"}
