"""python -m radar            -> check, then email (MAIL_MODE=graph) or write outbox/report.html (MAIL_MODE=dry_run)
   python -m radar --dry-run  -> check and write outbox/report.html; sends nothing and doesn't update state

Settings come from environment variables (GitHub Actions secrets). For local runs a .env file next to this
folder is read too; it is git-ignored."""
import os
import sys
from pathlib import Path

from radar import models, report, vulns
from radar.findings import Problem, today_pkt
from radar.mailer import EMAIL, GraphSender, write_outbox

ROOT = Path(__file__).resolve().parent.parent
WATCHLIST = ROOT / "watchlist"
STATE = ROOT / "state" / "state.json"
OUTBOX = ROOT / "outbox"
DEFAULT_RESEARCH_MODEL = "gpt-5.6-terra"


def load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            value = value.split(" #", 1)[0].strip().strip('"').strip("'")
            if value:
                os.environ.setdefault(key.strip(), value)


def env(name: str) -> str:
    return (os.environ.get(name) or "").strip()


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8-sig")  # -sig: Notepad/PowerShell may add a byte-order mark
    except OSError:
        return ""


def main(argv: list[str]) -> int:
    load_dotenv(ROOT / ".env")
    global WATCHLIST
    WATCHLIST = Path(env("RADAR_WATCHLIST_DIR")) if env("RADAR_WATCHLIST_DIR") else WATCHLIST
    dry_run = "--dry-run" in argv or env("MAIL_MODE") != "graph"
    today = today_pkt()
    research_model = env("OPENAI_RESEARCH_MODEL") or DEFAULT_RESEARCH_MODEL

    findings, problems = [], []
    for job, run in (("Vulnerabilities", lambda: vulns.check(read(WATCHLIST / "requirements.txt"))),
                     ("Models", lambda: models.check(read(WATCHLIST / "models.txt"), env("OPENAI_API_KEY") or None,
                                                     research_model, today))):
        try:
            found, failed = run()
            findings += found
            problems += failed
        except Exception as exc:  # one broken check must not stop the email
            problems.append(Problem(job, f"crashed: {type(exc).__name__}"))

    pinned = len(vulns.parse_requirements(read(WATCHLIST / "requirements.txt"))[0])
    model_count = len(models.parse_models(read(WATCHLIST / "models.txt"))[0])
    watched = f"{pinned} pinned package{'s' if pinned != 1 else ''}, {model_count} model{'s' if model_count != 1 else ''}"
    report.mark_new(findings, STATE, save=not dry_run)
    subject = report.subject(findings, problems, today)
    body = report.build_html(findings, problems, today, watched)
    print(subject)
    for p in problems:
        print(f"  problem: {p.check}: {p.message}")

    if dry_run:
        print(f"Dry run: wrote {write_outbox(OUTBOX, subject, body)} (nothing sent)")
        return 0
    missing = [n for n in ("GRAPH_TENANT_ID", "GRAPH_CLIENT_ID", "GRAPH_CLIENT_SECRET", "MAIL_FROM", "MAIL_TO") if not env(n)]
    if missing:
        print(f"Cannot send: {', '.join(missing)} not set", file=sys.stderr)
        return 2
    to = [a.strip() for a in env("MAIL_TO").split(",") if a.strip()]
    if not to or not all(EMAIL.fullmatch(a) for a in to):
        print("Cannot send: MAIL_TO must be email addresses separated by commas", file=sys.stderr)
        return 2
    try:
        GraphSender(env("GRAPH_TENANT_ID"), env("GRAPH_CLIENT_ID"), env("GRAPH_CLIENT_SECRET"), env("MAIL_FROM")).send(
            subject, body, to)
    except Exception as exc:  # fail the run so GitHub notifies you; the message never includes secrets
        print(f"Email failed: {exc}", file=sys.stderr)
        return 1
    print(f"Email sent to {len(to)} recipient(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
