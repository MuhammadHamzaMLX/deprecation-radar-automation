"""Job 1: known vulnerabilities in the pip packages listed in watchlist/requirements.txt, from OSV.dev.
The file is only read as text: nothing in it is installed or run. Only package names and versions are sent."""
import re

from radar import net
from radar.findings import ACTION, PREPARE, Finding, Problem

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"
OSV_PAGE = "https://osv.dev/vulnerability/{}"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,80}")
_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)\s*$")
_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(text: str) -> tuple[list[tuple[str, str]], list[str]]:
    """(pinned [(name, version)], skipped lines). Only `name==version` can be checked exactly; ranges like
    `>=2.0`, includes (-r) and URLs are reported as skipped so you know they weren't checked."""
    pinned, skipped, seen = [], [], set()
    for raw in text.replace("\\\n", " ").splitlines():
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()
        if not line:
            continue
        line = re.sub(r"\s--hash[=\s]\S+", "", line).split(";", 1)[0].strip()  # hashes and environment markers
        match = _PIN.match(line)
        if match and "*" not in match.group(2):
            key = (normalize(match.group(1)), match.group(2))
            if key not in seen:
                seen.add(key)
                pinned.append(key)
        else:
            skipped.append(line[:120])
    return pinned, skipped


def _version_key(version: str) -> tuple:
    match = re.match(r"v?(\d+(?:\.\d+)*)", version or "")
    if not match:
        return ()
    parts = [int(p) for p in match.group(1).split(".")]
    while parts and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def _fixed_versions(vuln: dict, package: str) -> list[str]:
    fixed = set()
    for affected in vuln.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem") == "PyPI" and normalize(pkg.get("name", "")) == package:
            for rng in affected.get("ranges") or []:
                fixed |= {e["fixed"] for e in rng.get("events") or [] if isinstance(e.get("fixed"), str)}
    return sorted(fixed, key=_version_key)


def _severity(vuln: dict) -> str:
    value = str((vuln.get("database_specific") or {}).get("severity") or "").upper()
    return value if value in SEVERITY_ORDER else "UNKNOWN"


def _text(value, limit: int) -> str:
    value = " ".join(str(value or "").split())
    return value if len(value) <= limit else value[: limit - 1] + "…"


def check(requirements_text: str) -> tuple[list[Finding], list[Problem]]:
    pinned, skipped = parse_requirements(requirements_text)
    problems = []
    if skipped:
        problems.append(Problem("requirements.txt", "Not checked (pin them as name==version): " + "; ".join(skipped[:15])
                                + (f" and {len(skipped) - 15} more" if len(skipped) > 15 else "")))
    if not pinned:
        if not skipped:
            problems.append(Problem("requirements.txt", "No packages listed, so no vulnerabilities were checked."))
        return [], problems

    findings = []
    try:
        batch = []
        for start in range(0, len(pinned), 500):
            chunk = pinned[start:start + 500]
            reply = net.post_json(OSV_BATCH, {"queries": [
                {"package": {"name": name, "ecosystem": "PyPI"}, "version": version} for name, version in chunk]})
            results = reply.get("results") or []
            if len(results) != len(chunk):
                raise net.NetError("OSV returned an unexpected number of results")
            batch += results
    except (net.NetError, ValueError) as exc:
        return [], [*problems, Problem("Vulnerabilities (OSV.dev)", str(exc))]

    details: dict[str, dict] = {}
    for (name, version), result in zip(pinned, batch):
        ids = [v["id"] for v in result.get("vulns") or [] if isinstance(v.get("id"), str) and _ID.fullmatch(v["id"])]
        if not ids:
            continue
        ids.sort(key=lambda i: (not i.startswith("GHSA-"), i))  # GitHub advisories carry a severity; prefer them
        covered, entries = set(), []
        for vuln_id in ids:
            if vuln_id in covered:
                continue
            try:
                vuln = details.get(vuln_id) or net.get_json(OSV_VULN.format(vuln_id))
            except (net.NetError, ValueError) as exc:
                problems.append(Problem("Vulnerabilities (OSV.dev)", f"details for {vuln_id}: {exc}"))
                continue
            details[vuln_id] = vuln
            aliases = [a for a in vuln.get("aliases") or [] if isinstance(a, str)]
            covered |= {vuln_id, *aliases}
            fixes = [f for f in _fixed_versions(vuln, name) if _version_key(f) > _version_key(version)]
            entries.append({"id": vuln_id, "severity": _severity(vuln), "fix": fixes[0] if fixes else None,
                            "summary": _text(vuln.get("summary") or vuln.get("details") or "No summary", 160),
                            "cves": [a for a in aliases if a.startswith("CVE-")][:2]})
        if not entries:
            continue
        entries.sort(key=lambda e: -SEVERITY_ORDER[e["severity"]])
        worst = entries[0]["severity"]
        fixes = [e["fix"] for e in entries if e["fix"]]
        upgrade = max(fixes, key=_version_key) if fixes else None
        count = f"{len(entries)} vulnerabilit{'y' if len(entries) == 1 else 'ies'}"
        title = f"{name} {version}: {count} (worst: {worst.lower()})"
        lines = [f"Upgrade to {upgrade} or later." if upgrade else "No fixed version published yet."]
        if any(not e["fix"] for e in entries) and upgrade:
            lines.append("Some of these have no fixed version yet; check the advisories.")
        for e in entries:
            also = f" ({', '.join(e['cves'])})" if e["cves"] else ""
            fix = f"Fixed in {e['fix']}" if e["fix"] else "No fix yet"
            lines.append(f"{e['severity']}: {e['summary']}{also}. {fix}. [{e['id']}]")
        findings.append(Finding(
            key=f"vuln:{name}:{version}:{','.join(sorted(e['id'] for e in entries))}",
            level=ACTION if SEVERITY_ORDER[worst] >= SEVERITY_ORDER["HIGH"] else PREPARE,
            kind="Vulnerability", title=title, details=lines,
            links=[(e["id"], OSV_PAGE.format(e["id"])) for e in entries]))
    return findings, problems
