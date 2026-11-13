"""The email: one list sorted by urgency, NEW markers against what the last email already showed, problems
at the bottom, and an all-clear when there's nothing. Every value is HTML-escaped and only https links are
rendered, because the text comes from outside (OSV, OpenAI, the web)."""
import html
import json
from datetime import date
from pathlib import Path

from radar.findings import ACTION, PREPARE, SIGNAL, Finding, Problem

SECTIONS = [
    (ACTION, "🔴 ACTION NOW", "Shut down, shutting down within 14 days, or a high/critical vulnerability", "#c62828"),
    (PREPARE, "🟠 PREPARE", "Retiring later or deprecated, or a moderate/low vulnerability", "#ef6c00"),
    (SIGNAL, "🔎 EARLY SIGNALS", "Found by web search, not confirmed by OpenAI yet", "#1565c0"),
]


def mark_new(findings: list[Finding], state_path: Path, save: bool = True) -> None:
    """Sets .new on findings the previous run didn't have, then (if save) remembers this run's keys.
    The state file holds finding keys only: package names, versions, advisory ids and model names."""
    try:
        seen = set(json.loads(state_path.read_text(encoding="utf-8")).get("keys", []))
        first_run = False
    except (OSError, ValueError):
        seen, first_run = set(), True
    for finding in findings:
        finding.new = not first_run and finding.key not in seen
    if not save:
        return
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps({"keys": sorted(f.key for f in findings)}, indent=1), encoding="utf-8")


def subject(findings: list[Finding], problems: list[Problem], today: date) -> str:
    counts = {level: sum(f.level == level for f in findings) for level, *_ in SECTIONS}
    parts = [f"{icon.split()[0]} {counts[level]} {word}" for (level, icon, *_), word in
             zip(SECTIONS, ("action", "prepare", "signal")) if counts[level]]
    new = sum(f.new for f in findings)
    head = ", ".join(parts) if parts else "✅ All clear"
    tail = (f" ({new} new)" if new else "") + (" ⚠️ some checks failed" if problems else "")
    return f"[Deprecation Radar] {head}{tail} – {today.strftime('%a %d %b %Y')}"


def _e(value) -> str:
    return html.escape(str(value), quote=True)


def _link(label: str, url: str) -> str:
    if not url.startswith("https://"):
        return _e(label)
    return f'<a href="{_e(url)}" style="color:#1565c0">{_e(label)}</a>'


def build_html(findings: list[Finding], problems: list[Problem], today: date, watched: str) -> str:
    out = ['<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#1f2933;max-width:760px">',
           f'<p style="margin:0 0 12px">Deprecation Radar check for <b>{_e(today.strftime("%A %d %B %Y"))}</b>. '
           f'Watched: {_e(watched)}.</p>']
    if not findings:
        out.append('<p style="font-size:16px;padding:12px;background:#e8f5e9;border-radius:6px">✅ <b>All clear.</b> '
                   'No vulnerabilities in your pinned packages and no retiring models found.</p>')
    for level, heading, blurb, color in SECTIONS:
        items = sorted((f for f in findings if f.level == level), key=lambda f: (not f.new, f.kind, f.title))
        if not items:
            continue
        out.append(f'<h3 style="color:{color};margin:20px 0 4px">{_e(heading)} ({len(items)})</h3>'
                   f'<div style="color:#52606d;font-size:12px;margin-bottom:8px">{_e(blurb)}</div><ol style="padding-left:20px">')
        for f in items:
            badge = ('<span style="background:#c62828;color:#fff;font-size:11px;padding:1px 6px;border-radius:3px;'
                     'margin-right:6px">NEW</span>') if f.new else ""
            out.append(f'<li style="margin-bottom:12px">{badge}<span style="color:#52606d">{_e(f.kind)}:</span> '
                       f'<b>{_e(f.title)}</b><ul style="margin:4px 0;padding-left:18px">')
            out += [f"<li>{_e(line)}</li>" for line in f.details]
            out.append("</ul>")
            if f.links:
                out.append('<div style="font-size:12px">' + " · ".join(_link(l, u) for l, u in f.links) + "</div>")
            out.append("</li>")
        out.append("</ol>")
    if problems:
        out.append('<h3 style="color:#6b4f00;margin:20px 0 4px">⚠️ Checks that could not finish</h3>'
                   '<div style="color:#52606d;font-size:12px;margin-bottom:8px">The list above may be incomplete '
                   'until these are fixed.</div><ul>')
        out += [f"<li><b>{_e(p.check)}:</b> {_e(p.message)}</li>" for p in problems]
        out.append("</ul>")
    out.append('<p style="color:#9aa5b1;font-size:11px;margin-top:24px">Sent automatically every Tuesday and Thursday '
               'by deprecation-radar. Web-search results are unverified; check the official links before acting.</p></div>')
    return "".join(out)
