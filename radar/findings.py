"""What the checks hand to the email: findings (something you must act on or prepare for) and problems (a check
that could not run, so silence would be misleading)."""
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone

ACTION, PREPARE, SIGNAL = "action", "prepare", "signal"
PKT = timezone(timedelta(hours=5))  # Pakistan has no daylight saving


def today_pkt() -> date:
    return datetime.now(PKT).date()


@dataclass
class Finding:
    key: str            # stable id; when it first appears the email marks it NEW (include dates so a changed date is NEW)
    level: str          # ACTION, PREPARE or SIGNAL
    kind: str           # "Vulnerability" or "Model"
    title: str
    details: list[str] = field(default_factory=list)
    links: list[tuple[str, str]] = field(default_factory=list)  # (label, https url)
    new: bool = False


@dataclass
class Problem:
    check: str
    message: str
