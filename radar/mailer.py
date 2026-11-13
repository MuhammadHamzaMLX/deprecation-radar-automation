"""Sends the report through Microsoft Graph (client credentials, same app setup as the Voice bot), or writes it
to outbox/ in dry-run mode. Errors carry status codes only, never the secret, token or response body."""
import html
import json
import re
import time
from pathlib import Path

from radar import net

EMAIL = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
TENANT = re.compile(r"[0-9a-fA-F-]{36}|[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
DELAYS = (5, 20)
MAX_WAIT = 60


class GraphSender:
    def __init__(self, tenant: str, client_id: str, secret: str, mailbox: str):
        if not TENANT.fullmatch(tenant or ""):
            raise ValueError("GRAPH_TENANT_ID should be a tenant GUID or domain")
        if not EMAIL.fullmatch(mailbox or ""):
            raise ValueError("MAIL_FROM should be one email address")
        self.tenant, self.client_id, self.secret, self.mailbox = tenant, client_id, secret, mailbox

    def _token(self) -> str:
        status, body = net.request("POST", f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token", form={
            "grant_type": "client_credentials", "client_id": self.client_id, "client_secret": self.secret,
            "scope": "https://graph.microsoft.com/.default"})
        if status != 200:
            raise net.NetError(f"Graph sign-in failed ({status})", status)
        return json.loads(body)["access_token"]

    def send(self, subject: str, html_body: str, to: list[str]) -> None:
        payload = {"message": {"subject": subject, "body": {"contentType": "HTML", "content": html_body},
                               "toRecipients": [{"emailAddress": {"address": a}} for a in to]},
                   "saveToSentItems": True}
        error = None
        for attempt in range(len(DELAYS) + 1):
            try:
                token = self._token()
                status, _ = net.request("POST", f"https://graph.microsoft.com/v1.0/users/{self.mailbox}/sendMail",
                                        json_body=payload, headers={"Authorization": f"Bearer {token}"}, retries=0)
                if status == 202:
                    return
                error = net.NetError(f"Graph sendMail failed ({status})", status)
                if status in (400, 401, 403, 404):
                    break  # a settings or permission problem; retrying won't help
            except net.NetError as exc:
                error = exc
                if exc.status in (400, 401):
                    break
            if attempt < len(DELAYS):
                time.sleep(min(getattr(error, "retry_after", None) or DELAYS[attempt], MAX_WAIT))
        raise error or net.NetError("Graph sendMail failed")


def write_outbox(folder: Path, subject: str, html_body: str) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "report.html"
    path.write_text(f"<!doctype html><meta charset='utf-8'><title>{html.escape(subject)}</title>{html_body}",
                    encoding="utf-8")
    return path
