"""
tracing.py
----------
Lightweight structured observability for the Code Review Agent pipeline.

Every pipeline run emits one JSON object per span to traces/trace.jsonl
(appended, never overwritten). Three span types are captured:

    run       — wraps the entire review_repo() call
    stage     — wraps each of fetch / scan / review
    llm_call  — wraps each _call_model() invocation in gemini_reviewer.py

Usage (context-manager style):

    with tracing.span("run", "review_repo", repo_url=url) as s:
        result = do_stuff()
        s.set(files_fetched=len(result.files))

The span writes itself to disk on __exit__, capturing duration and any
exception. Exceptions are recorded but never suppressed.

run_id threading
----------------
The first "run" span generates a UUID and stores it in thread-local state.
All spans opened while that run span is active inherit the same run_id,
which is what ties a full trace tree together in view_trace.py. Nested
spans track their own parent_id via a per-thread span-id stack.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Default trace file location. Override with TRACE_FILE env var.
_DEFAULT_TRACE_FILE = Path("traces/trace.jsonl")

# Thread-local state: a stack of active span-ids and the current run_id.
_local = threading.local()


def _stack() -> list[str]:
    if not hasattr(_local, "stack"):
        _local.stack = []
    return _local.stack


def _get_run_id() -> str | None:
    return getattr(_local, "run_id", None)


def _set_run_id(value: str | None) -> None:
    _local.run_id = value


# ---------------------------------------------------------------------------
# Span
# ---------------------------------------------------------------------------

class Span:
    """Context manager that records one structured span on exit."""

    def __init__(self, span_type: str, name: str, initial_fields: dict[str, Any]) -> None:
        self._span_type = span_type
        self._name = name
        self._span_id = uuid.uuid4().hex[:8]
        self._parent_id: str | None = _stack()[-1] if _stack() else None
        self._run_id: str | None = _get_run_id()
        self._is_root = (span_type == "run")
        self._fields: dict[str, Any] = dict(initial_fields)
        self._start_ts: datetime | None = None
        self._status = "ok"
        self._error: str | None = None

    # ------------------------------------------------------------------

    def set(self, **kwargs: Any) -> None:
        """Add or update fields on this span (before it is written)."""
        self._fields.update(kwargs)

    # ------------------------------------------------------------------

    def __enter__(self) -> "Span":
        self._start_ts = datetime.now(timezone.utc)
        if self._is_root:
            # This span IS the run — its own span_id becomes the run_id for
            # all child spans opened while it is active.
            _set_run_id(self._span_id)
            self._run_id = self._span_id
        _stack().append(self._span_id)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        end_ts = datetime.now(timezone.utc)
        _stack().pop()

        if self._is_root:
            _set_run_id(None)

        if exc_type is not None:
            self._status = "error"
            self._error = f"{exc_type.__name__}: {exc_val}"

        duration_s = (end_ts - self._start_ts).total_seconds() if self._start_ts else 0.0

        record: dict[str, Any] = {
            "span_id":    self._span_id,
            "parent_id":  self._parent_id,
            "run_id":     self._run_id,
            "span_type":  self._span_type,
            "name":       self._name,
            "start_ts":   self._start_ts.isoformat().replace("+00:00", "Z") if self._start_ts else None,
            "end_ts":     end_ts.isoformat().replace("+00:00", "Z"),
            "duration_s": round(duration_s, 3),
            "status":     self._status,
            "error":      self._error,
            "fields":     self._fields,
        }

        _write(record)
        return False  # never suppress exceptions


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------

def span(span_type: str, name: str, **initial_fields: Any) -> Span:
    """
    Create a Span context manager.

    Example:
        with tracing.span("stage", "fetch", repo_url=url) as s:
            result = fetcher.fetch(...)
            s.set(files_fetched=len(result.files))
    """
    return Span(span_type, name, initial_fields)


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------

def _write(record: dict[str, Any]) -> None:
    trace_file = Path(os.environ.get("TRACE_FILE", str(_DEFAULT_TRACE_FILE)))
    try:
        trace_file.parent.mkdir(parents=True, exist_ok=True)
        with open(trace_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")
    except OSError:
        # Never let tracing failures crash the pipeline.
        pass
