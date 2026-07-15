"""
dependency_scanner.py
---------------------
Checks Python dependencies against the OSV (Open Source Vulnerabilities)
database — https://osv.dev — which aggregates CVEs, GitHub Security Advisories,
and other vulnerability sources.

No API key required. Uses the free OSV batch endpoint.
"""

from __future__ import annotations

import re
import logging

import httpx

logger = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_TIMEOUT = 20


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_requirements(content: str) -> list[tuple[str, str]]:
    """Parse requirements.txt into (package_name, version) tuples.

    Handles: pkg==1.0, pkg>=1.0, pkg~=1.0, pkg (no version), comments, extras.
    Returns version="" when no version is pinned.
    """
    packages: list[tuple[str, str]] = []
    for raw_line in content.splitlines():
        line = raw_line.split("#")[0].strip()  # strip comments
        if not line or line.startswith(("-r", "-c", "--")):
            continue
        # Strip extras: requests[security]==2.28.0 → requests, 2.28.0
        line = re.sub(r"\[.*?\]", "", line)
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*[=~><!\^]+\s*([^\s,;]+)", line)
        if m:
            packages.append((m.group(1), m.group(2)))
        else:
            m2 = re.match(r"^([A-Za-z0-9_\-\.]+)", line)
            if m2:
                packages.append((m2.group(1), ""))
    return packages


# ---------------------------------------------------------------------------
# OSV API
# ---------------------------------------------------------------------------

def _query_osv_batch(packages: list[tuple[str, str]]) -> list[dict]:
    """Query OSV batch endpoint. Returns one result dict per package."""
    queries = []
    for name, version in packages:
        q: dict = {"package": {"name": name, "ecosystem": "PyPI"}}
        if version:
            q["version"] = version
        queries.append(q)

    with httpx.Client(timeout=OSV_TIMEOUT) as client:
        resp = client.post(OSV_BATCH_URL, json={"queries": queries})
        resp.raise_for_status()
        return resp.json().get("results", [])


def _cvss_to_severity(score_str: str) -> str:
    """Convert a CVSS score string to a severity label."""
    try:
        score = float(score_str)
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"
    except (ValueError, TypeError):
        return "UNKNOWN"


def _extract_cve_info(vuln: dict) -> dict:
    """Extract the most useful fields from one OSV vulnerability record."""
    aliases = vuln.get("aliases", [])
    cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln.get("id", ""))

    # Severity — try CVSS_V3 first, fall back to CVSS_V2
    severity = "UNKNOWN"
    for sev in vuln.get("severity", []):
        if sev.get("type") in ("CVSS_V3", "CVSS_V2"):
            severity = _cvss_to_severity(sev.get("score", "0"))
            break

    # Fixed versions
    fixed_in: list[str] = []
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    fixed_in.append(event["fixed"])

    summary = vuln.get("summary") or vuln.get("details") or ""
    return {
        "id": cve_id or vuln.get("id", ""),
        "summary": summary[:300],
        "severity": severity,
        "fixed_in": list(dict.fromkeys(fixed_in))[:3],  # deduplicate, cap at 3
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_dependencies(requirements_content: str) -> dict:
    """Scan requirements.txt content for known CVEs via the OSV database.

    Parameters
    ----------
    requirements_content : str
        Raw text of a requirements.txt file.

    Returns
    -------
    dict with keys:
        packages_checked  int
        vulnerable        list of {package, version, cve_count, cves: [...]}
        clean             list of "package==version" strings
        no_version        list of package names with no pinned version
        error             str — only present if the OSV API call failed
    """
    packages = parse_requirements(requirements_content)
    if not packages:
        return {
            "packages_checked": 0,
            "vulnerable": [],
            "clean": [],
            "no_version": [],
        }

    versioned = [(n, v) for n, v in packages if v]
    unversioned = [n for n, v in packages if not v]

    if not versioned:
        return {
            "packages_checked": 0,
            "vulnerable": [],
            "clean": [],
            "no_version": unversioned,
        }

    try:
        results = _query_osv_batch(versioned)
    except Exception as exc:
        logger.warning("OSV API call failed: %s", exc)
        return {
            "packages_checked": 0,
            "vulnerable": [],
            "clean": [],
            "no_version": unversioned,
            "error": str(exc),
        }

    vulnerable: list[dict] = []
    clean: list[str] = []

    for (name, version), result in zip(versioned, results):
        vulns = result.get("vulns", [])
        if vulns:
            vulnerable.append({
                "package": name,
                "version": version,
                "cve_count": len(vulns),
                "cves": [_extract_cve_info(v) for v in vulns],
            })
        else:
            clean.append(f"{name}=={version}")

    return {
        "packages_checked": len(versioned),
        "vulnerable": vulnerable,
        "clean": clean,
        "no_version": unversioned,
    }
