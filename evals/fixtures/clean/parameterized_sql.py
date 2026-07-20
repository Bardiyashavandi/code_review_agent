"""Synthetic fixture: SQL built with string formatting for the TABLE NAME
(never attacker-controlled -- comes from a fixed internal enum) while the
actual user-supplied VALUE goes through a bound parameter. Deliberately
looks similar to the sqli.py fixture's f-string pattern at a glance, to
test whether the pipeline distinguishes "string formatting present" from
"string formatting of untrusted data"."""

import sqlite3
from enum import Enum


class ReportTable(Enum):
    DAILY = "daily_reports"
    WEEKLY = "weekly_reports"
    MONTHLY = "monthly_reports"


def get_db():
    return sqlite3.connect("app.db")


def get_report_rows(table: ReportTable, report_date: str) -> list:
    db = get_db()
    cursor = db.cursor()
    # Safe: `table.value` is one of three fixed, hardcoded enum strings --
    # never derived from request input -- so the f-string here cannot be
    # attacker-influenced. `report_date` (the actual variable input) is
    # bound as a parameter, not interpolated.
    query = f"SELECT * FROM {table.value} WHERE report_date = ?"
    cursor.execute(query, (report_date,))
    return cursor.fetchall()
