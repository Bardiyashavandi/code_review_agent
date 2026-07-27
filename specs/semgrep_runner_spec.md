# Spec: `semgrep_runner` Module

**Project:** AI Code Review Agent
**Module:** `semgrep_runner.py`
**Version:** 1.0
**Status:** Draft

---

## 1. Purpose

Run Semgrep static analysis over the `FileResult` objects produced by `github_fetcher`, and return structured, typed findings ready to hand to the Gemini review step. This module owns all interaction with the Semgrep CLI/subprocess boundary so the rest of the pipeline never touches the filesystem or a shell directly.

---

## 2. Public Interface

```python
from semgrep_runner import SemgrepRunner

runner = SemgrepRunner(config="auto")
report = runner.scan(files)  # files: list[FileResult] from github_fetcher
# Returns: ScanReport
```

### `Finding` (dataclass)

| Field        | Type  | Description                                      |
|--------------|-------|---------------------------------------------------|
| `path`       | `str` | File path the finding belongs to                   |
| `line_start` | `int` | 1-indexed start line                                |
| `line_end`   | `int` | 1-indexed end line                                  |
| `rule_id`    | `str` | Semgrep rule identifier                             |
| `severity`   | `str` | One of `"ERROR"`, `"WARNING"`, `"INFO"`             |
| `message`    | `str` | Human-readable finding description                 |
| `snippet`    | `str` | The matched source snippet                          |

### `ScanReport` (dataclass)

| Field        | Type             | Description                              |
|--------------|------------------|-------------------------------------------|
| `findings`   | `list[Finding]`  | All findings across all scanned files      |
| `scanned`    | `int`            | Count of files successfully scanned        |
| `skipped`    | `list[str]`      | Paths skipped (e.g. Semgrep parse errors)  |
| `duration_s` | `float`          | Wall-clock scan time                       |

### `SemgrepRunner`

| Method  | Signature                              | Returns      | Description |
|---------|-----------------------------------------|--------------|--------------|
| `__init__` | `(config: str = "auto", timeout: int = 60)` | — | Validates `semgrep` binary is on `PATH`; raises `SemgrepNotInstalledError` if missing |
| `scan`  | `(files: list[FileResult]) → ScanReport` | `ScanReport` | Writes files to a temp dir, invokes Semgrep, parses JSON output, cleans up |

---

## 3. Behavior

### 3.1 Execution Model
- Files are written to an isolated `tempfile.TemporaryDirectory()` — never the user's real filesystem, never the cwd.
- Semgrep is invoked via `subprocess.run` with an **explicit argument list** (no `shell=True`, no string interpolation into a shell command).
- Command: `semgrep scan --config {config} --json --timeout {timeout} {tmpdir}`.
- `config` defaults to `"auto"` (Semgrep's default ruleset registry pull). Caller may pass a local ruleset path or registry id instead.

### 3.2 Input Validation
- `files` must be non-empty; raise `ValueError("No files to scan")` if empty.
- Each `FileResult.path` is sanitized before being joined to the temp dir: reject any path containing `..`, leading `/`, or backslashes, to prevent path traversal outside the temp sandbox. Raise `UnsafeFilePathError` for any offending file and skip it (does not abort the whole scan).
- `config` string is validated against an allow-list pattern (`^[a-zA-Z0-9_\-./:]+$`) before being placed on the command line, to prevent argument/flag injection.

### 3.3 Timeouts & Process Control
- `subprocess.run(..., timeout=timeout)`. On `subprocess.TimeoutExpired`, raise `SemgrepTimeoutError`.
- Semgrep's own non-zero exit codes: `0` = clean, `1` = findings present (not an error), anything else = raise `SemgrepExecutionError(returncode, stderr)`. `stderr` is truncated to 2000 chars in the exception to avoid leaking huge dumps.

### 3.4 Output Parsing
- Parse Semgrep's `--json` stdout. Each entry under `results` maps to a `Finding`:
  - `path` → relative path stripped of the temp-dir prefix, mapped back to the original repo-relative path.
  - `start.line` / `end.line` → `line_start` / `line_end`.
  - `check_id` → `rule_id`.
  - `extra.severity` → `severity`, normalized to uppercase.
  - `extra.message` → `message`.
  - `extra.lines` → `snippet`, truncated to 500 chars.
- Files Semgrep reports under `errors` (parse failures, etc.) are added to `ScanReport.skipped`, not raised as exceptions — a single bad file should not fail the whole scan.
- Unknown/missing JSON keys are tolerated with safe defaults (`""`, `0`) rather than raising — Semgrep's JSON schema can vary slightly by version.

### 3.5 Cleanup
- Temp directory is always removed (via context manager), even on exception.
- No findings, file content, or temp paths are logged at INFO; only counts and durations are logged at INFO. Full findings are returned to the caller, not printed.

### 3.6 Security
- No `shell=True` anywhere.
- No file is ever written outside the `TemporaryDirectory`.
- `config` argument is allow-list validated (see 3.2) before reaching the subprocess argument list.
- Subprocess inherits no extra environment beyond what's needed (`env=os.environ` is acceptable; do not inject secrets into Semgrep's env).

---

## 4. Error Hierarchy

```
SemgrepRunnerError (base)
├── SemgrepNotInstalledError
├── SemgrepTimeoutError
├── SemgrepExecutionError
└── UnsafeFilePathError
```

All errors include `.message`; `SemgrepExecutionError` additionally includes `.returncode`.

---

## 5. Configuration

| Parameter | Default  | Description                                  |
|-----------|----------|------------------------------------------------|
| `config`  | `"auto"` | Semgrep ruleset: `"auto"`, registry id, or local path |
| `timeout` | `60`     | Max seconds for the Semgrep subprocess           |

No environment variables read by this module — config is passed explicitly by the caller, same convention as `github_fetcher`.

---

## 6. Tests (`tests/test_semgrep_runner.py`)

All tests mock `subprocess.run` — no real Semgrep binary required in CI, and no real filesystem scanning outside a test-local temp dir where unavoidable.

| Test ID | Scenario | Expected |
|---------|----------|----------|
| `test_empty_files_raises` | `scan([])` | `ValueError` |
| `test_missing_semgrep_binary_raises` | `shutil.which` returns `None` | `SemgrepNotInstalledError` |
| `test_rejects_path_traversal` | `FileResult.path = "../../etc/passwd"` | File skipped, `UnsafeFilePathError` recorded, scan continues |
| `test_rejects_invalid_config_string` | `config="auto; rm -rf /"` | `ValueError` before subprocess invoked |
| `test_clean_scan_no_findings` | Semgrep exit 0, empty `results` | `ScanReport.findings == []` |
| `test_parses_findings_correctly` | Mocked JSON with 2 results | 2 `Finding` objects with correct fields |
| `test_severity_normalized_uppercase` | `extra.severity = "warning"` | `Finding.severity == "WARNING"` |
| `test_skipped_files_from_errors_key` | JSON `errors` has 1 entry | `ScanReport.skipped` contains that path, no exception |
| `test_nonzero_exit_code_1_is_findings_not_error` | exit code `1` with results | No exception raised |
| `test_nonzero_exit_code_other_raises` | exit code `2` | `SemgrepExecutionError` |
| `test_timeout_raises` | `subprocess.run` raises `TimeoutExpired` | `SemgrepTimeoutError` |
| `test_temp_dir_cleaned_up` | Successful scan | Temp dir no longer exists after `scan()` returns |
| `test_no_shell_true_used` | Inspect call args to `subprocess.run` | `shell` kwarg absent or `False` |
| `test_stderr_truncated_in_exception` | 5000-char stderr, exit code 2 | Exception message ≤ 2000 chars |

---

## 7. File Layout

```
code-review-agent/
├── github_fetcher.py
├── semgrep_runner.py        ← this module
├── tests/
│   ├── test_github_fetcher.py
│   └── test_semgrep_runner.py
└── ...
```

---

## 8. Dependencies

```
semgrep                # CLI tool, invoked as subprocess — not imported as a library
```

`semgrep` must be installed in the environment (`pip install semgrep` or system package). No new Python library dependencies beyond stdlib (`subprocess`, `tempfile`, `json`).

---

## 9. Out of Scope

- Custom rule authoring/management (use `--config auto` or a path to existing rules)
- Incremental/diff-only scanning
- SARIF output format (JSON only, for now)
- Scanning languages other than Python

---

## 10. Acceptance Criteria

- [ ] All tests in `tests/test_semgrep_runner.py` pass with `pytest -v`
- [ ] No `shell=True` anywhere in the module
- [ ] Path traversal attempts are rejected, not silently resolved
- [ ] Temp directories are always cleaned up, even on exception
- [ ] A real `semgrep scan --config auto` against `github_fetcher.py` itself completes and parses without error
