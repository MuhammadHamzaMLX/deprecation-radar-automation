"""The only way the radar talks to the internet: HTTPS to a fixed list of hosts, with timeouts and a size cap.
Redirects are followed only to hosts on the list, and a request carrying a secret header follows none, so a
key can never be sent somewhere unexpected. Errors name the host and status, never headers or bodies."""
import json
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

ALLOWED_HOSTS = {
    "api.osv.dev",                  # vulnerability database (gets package names + versions)
    "platform.openai.com",          # deprecations page (redirects to developers.openai.com)
    "developers.openai.com",
    "api.openai.com",               # model list + web-search research (gets model names only)
    "login.microsoftonline.com",    # Graph sign-in
    "graph.microsoft.com",          # sendMail
}
TIMEOUT = 30
MAX_BYTES = 5_000_000
USER_AGENT = "deprecation-radar/1.0"


class NetError(RuntimeError):
    def __init__(self, message: str, status: int | None = None, retry_after: float | None = None):
        super().__init__(message)
        self.status, self.retry_after = status, retry_after


def _check_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS:
        raise NetError(f"blocked request to {parts.scheme}://{parts.hostname} (not on the allowed list)")
    return parts.hostname


class _AllowListRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if req.has_header("Authorization"):
            raise NetError(f"{urlsplit(req.full_url).hostname} redirected an authenticated request; refused", code)
        _check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_opener = urllib.request.build_opener(_AllowListRedirects)


def request(method: str, url: str, *, json_body=None, form: dict | None = None, headers: dict | None = None,
            retries: int = 2) -> tuple[int, bytes]:
    """Sends one request (retrying network errors, 429 and 5xx a couple of times) and returns (status, body).
    A 4xx other than 429 is returned to the caller, not raised."""
    host = _check_url(url)
    data, sent_headers = None, {"User-Agent": USER_AGENT, **(headers or {})}
    if json_body is not None:
        data, sent_headers["Content-Type"] = json.dumps(json_body).encode(), "application/json"
    elif form is not None:
        from urllib.parse import urlencode
        data, sent_headers["Content-Type"] = urlencode(form).encode(), "application/x-www-form-urlencoded"
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, data=data, headers=sent_headers, method=method)
        try:
            with _opener.open(req, timeout=TIMEOUT) as reply:
                body = reply.read(MAX_BYTES + 1)
                if len(body) > MAX_BYTES:
                    raise NetError(f"{host} sent more than {MAX_BYTES} bytes; refused")
                return reply.status, body
        except urllib.error.HTTPError as exc:
            wait = exc.headers.get("Retry-After", "") if exc.headers else ""
            retry_after = float(wait) if wait.isdigit() else None
            if (exc.code == 429 or exc.code >= 500) and attempt < retries:
                time.sleep(min(retry_after or 2 * (attempt + 1), 30))
                continue
            if exc.code == 429 or exc.code >= 500:
                raise NetError(f"{host} answered {exc.code}", exc.code, retry_after) from None
            return exc.code, exc.read(MAX_BYTES)
        except NetError:
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            if attempt < retries:
                time.sleep(2 * (attempt + 1))
                continue
            reason = getattr(exc, "reason", exc)
            raise NetError(f"could not reach {host} ({type(reason).__name__})") from None
    raise NetError(f"could not reach {host}")


def get_json(url: str, headers: dict | None = None) -> dict:
    status, body = request("GET", url, headers=headers)
    if status != 200:
        raise NetError(f"{urlsplit(url).hostname} answered {status}", status)
    return json.loads(body)


def post_json(url: str, payload: dict, headers: dict | None = None) -> dict:
    status, body = request("POST", url, json_body=payload, headers=headers)
    if status != 200:
        raise NetError(f"{urlsplit(url).hostname} answered {status}", status)
    return json.loads(body)
