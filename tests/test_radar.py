"""Unit tests: no network, no secrets. net.request is replaced by a fake that answers per URL."""
import json
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from radar import mailer, models, net, report, vulns  # noqa: E402
from radar.findings import ACTION, PREPARE, SIGNAL, Finding, Problem  # noqa: E402

TODAY = date(2026, 11, 13)

PAGE = """<html><body><table>
<tr><th>Shutdown date</th><th>Affected model or feature</th><th>Status</th><th>Recommended replacement</th><th>Notice date</th></tr>
<tr><td>Nov 20, 2026</td><td>gpt-soon, gpt-soon-2025-01-01</td><td>Deprecated</td><td>gpt-new</td><td>May 1, 2026</td></tr>
<tr><td>Apr 1, 2027</td><td>gpt-later</td><td>Deprecated</td><td>gpt-6-sol</td><td>Oct 1, 2026</td></tr>
<tr><td>Dec 1, 2026</td><td>a, b, c</td><td>Deprecated</td><td>x</td><td>Jun 1, 2026</td></tr>
</table><table>
<tr><th>Shutdown date</th><th>Affected model or feature</th><th>Listed replacement</th><th>Notice date</th></tr>
<tr><td>Oct 23, 2026</td><td>gpt-old</td><td>gpt-5.6-sol</td><td>Apr 22, 2026</td></tr>
</table></body></html>"""


def research_reply(payload: dict) -> bytes:
    return json.dumps({"output": [{"type": "web_search_call"}, {"type": "message", "content": [
        {"type": "output_text", "text": "Here you go:\n" + json.dumps(payload)}]}]}).encode()


class FakeNet:
    """Replaces net.request; routes maps a URL substring to (status, body) or a callable(method, url, kw)."""

    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def __call__(self, method, url, **kw):
        self.calls.append((method, url, kw))
        for part, answer in self.routes.items():
            if part in url:
                answer = answer(method, url, kw) if callable(answer) else answer
                if isinstance(answer, Exception):
                    raise answer
                status, body = answer
                return status, body if isinstance(body, bytes) else json.dumps(body).encode()
        raise AssertionError(f"unexpected request {url}")


class Patched(unittest.TestCase):
    def fake(self, routes):
        fake = FakeNet(routes)
        original = net.request
        net.request = fake
        self.addCleanup(setattr, net, "request", original)
        return fake


class TestRequirements(unittest.TestCase):
    def test_parsing(self):
        pinned, skipped = vulns.parse_requirements(
            "# comment\nJinja2==2.10  # inline\nrequests[socks]==2.19.0 ; python_version>'3'\n"
            "fastapi>=0.100\n-r other.txt\nNumpy===1.0 \\\n  --hash=sha256:abc\nflask==2.*\n\nJINJA2==2.10\n")
        self.assertEqual(pinned, [("jinja2", "2.10"), ("requests", "2.19.0"), ("numpy", "1.0")])
        self.assertEqual(skipped, ["fastapi>=0.100", "-r other.txt", "flask==2.*"])

    def test_version_order(self):
        key = vulns._version_key
        self.assertTrue(key("2.10.1") > key("2.10") > key("2.9.9"))
        self.assertEqual(key("1.0.0"), key("1"))


class TestVulns(Patched):
    def test_findings_dedupe_severity_and_fix(self):
        ghsa = {"id": "GHSA-aaaa-bbbb-cccc", "summary": "Sandbox <escape>", "aliases": ["CVE-2019-1", "PYSEC-2019-1"],
                "database_specific": {"severity": "HIGH"},
                "affected": [{"package": {"name": "Jinja2", "ecosystem": "PyPI"},
                              "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.10.1"}]}]}]}
        low = {"id": "GHSA-dddd-eeee-ffff", "summary": "Minor", "aliases": [], "database_specific": {"severity": "LOW"},
               "affected": [{"package": {"name": "jinja2", "ecosystem": "PyPI"},
                             "ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.1.5"}]}]}]}
        fake = self.fake({
            "querybatch": (200, {"results": [{"vulns": [{"id": "PYSEC-2019-1"}, {"id": "GHSA-aaaa-bbbb-cccc"},
                                                         {"id": "GHSA-dddd-eeee-ffff"}]}, {}]}),
            "GHSA-aaaa": (200, ghsa), "GHSA-dddd": (200, low),
        })
        findings, problems = vulns.check("jinja2==2.10\nsafe==1.0\n")
        self.assertEqual(problems, [])
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.level, ACTION)
        self.assertIn("2 vulnerabilities", f.title)
        self.assertEqual(f.details[0], "Upgrade to 3.1.5 or later.")
        self.assertTrue(any("CVE-2019-1" in d and "Fixed in 2.10.1" in d for d in f.details))
        self.assertFalse(any("PYSEC" in u for _, u in f.links))  # alias of the GHSA, fetched once only
        self.assertFalse(any("PYSEC" in c[1] for c in fake.calls))
        sent = fake.calls[0][2]["json_body"]["queries"]
        self.assertEqual(sent[0], {"package": {"name": "jinja2", "ecosystem": "PyPI"}, "version": "2.10"})

    def test_low_only_is_prepare_and_bad_ids_ignored(self):
        self.fake({"querybatch": (200, {"results": [{"vulns": [{"id": "../../evil"}, {"id": "GHSA-x"}]}]}),
                   "GHSA-x": (200, {"id": "GHSA-x", "summary": "s", "database_specific": {"severity": "LOW"}})})
        findings, _ = vulns.check("a==1\n")
        self.assertEqual(findings[0].level, PREPARE)
        self.assertEqual(findings[0].details[0], "No fixed version published yet.")

    def test_osv_down_is_a_problem_not_a_crash(self):
        self.fake({"querybatch": net.NetError("could not reach api.osv.dev")})
        findings, problems = vulns.check("a==1\n")
        self.assertEqual(findings, [])
        self.assertIn("api.osv.dev", problems[0].message)

    def test_empty_file_is_reported(self):
        _, problems = vulns.check("# nothing\n")
        self.assertIn("No packages", problems[0].message)


class TestModels(Patched):
    def test_parse_deprecations(self):
        found = models.parse_deprecations(PAGE)
        self.assertEqual(found["gpt-soon-2025-01-01"], {"shutdown": date(2026, 11, 20), "replacement": "gpt-new"})
        self.assertEqual(found["gpt-old"]["shutdown"], date(2026, 10, 23))
        self.assertIn("c", found)

    def test_parse_date(self):
        self.assertEqual(models.parse_date("July 2, 2026"), date(2026, 7, 2))
        self.assertEqual(models.parse_date("Sept 3, 2026"), date(2026, 9, 3))
        self.assertEqual(models.parse_date("2027-01-06"), date(2027, 1, 6))
        self.assertIsNone(models.parse_date("soon"))

    def routes(self, available, research):
        return {"deprecations": (200, PAGE.encode()),
                "/v1/models": (200, {"data": [{"id": m} for m in available]}),
                "/v1/responses": lambda method, url, kw: (200, research_reply(research(kw["json_body"]["input"])))}

    def test_levels(self):
        quiet = {"retiring": "no", "summary": "nothing", "sources": []}
        rumour = {"retiring": "yes", "shutdown_date": "2027-03-01", "replacement": "gpt-7",
                  "summary": "<script>alert(1)</script> retiring", "sources": ["https://openai.com/x", "javascript:alert(1)"]}
        fake = self.fake(self.routes(
            ["gpt-soon", "gpt-later", "gpt-rumour", "gpt-fine", "gpt-5.6-terra"],
            lambda prompt: rumour if "gpt-rumour" in prompt else quiet))
        findings, problems = models.check("gpt-soon\ngpt-later\ngpt-old\ngpt-rumour\ngpt-fine\nbad name!\n", "sk-test",
                                          "gpt-5.6-terra", TODAY)
        by = {f.title.split(" ")[0]: f for f in findings}
        self.assertEqual(by["gpt-soon"].level, ACTION)        # 7 days left
        self.assertEqual(by["gpt-later"].level, PREPARE)
        self.assertEqual(by["gpt-old"].level, ACTION)         # shut down and not in the model list
        self.assertTrue(any("Not available" in d for d in by["gpt-old"].details))
        self.assertEqual(by["gpt-rumour"].level, SIGNAL)
        self.assertEqual(by["gpt-rumour"].links, [("Source 1", "https://openai.com/x")])
        self.assertNotIn("gpt-fine", by)
        self.assertNotIn("gpt-5.6-terra", by)
        self.assertIn("bad name!", problems[0].message)
        searched = [c for c in fake.calls if "/v1/responses" in c[1]]
        self.assertEqual(len(searched), 6)  # 5 listed + the radar's own research model
        body = searched[0][2]["json_body"]
        self.assertFalse(body["store"])
        self.assertEqual(body["tools"], [{"type": "web_search"}])

    def test_rumour_never_reaches_action(self):
        self.fake(self.routes(["gpt-x", "r"], lambda p: {"retiring": "yes", "shutdown_date": "2026-11-14",
                                                         "summary": "tomorrow!", "sources": []}))
        findings, _ = models.check("gpt-x\n", "sk", "r", TODAY)
        self.assertEqual({f.level for f in findings}, {SIGNAL})

    def test_no_key_and_page_down(self):
        self.fake({"deprecations": (503, b"")})
        findings, problems = models.check("gpt-old\n", None, "r", TODAY)
        self.assertEqual(findings, [])
        checks = {p.check for p in problems}
        self.assertIn("OpenAI deprecations page", checks)
        self.assertIn("OpenAI", checks)

    def test_page_layout_change_is_reported(self):
        self.fake({"deprecations": (200, b"<html>new design</html>"), "/v1/models": (200, {"data": []}),
                   "/v1/responses": (500, b"")})
        _, problems = models.check("gpt-a\n", "sk", "r", TODAY)
        self.assertTrue(any("layout changed" in p.message for p in problems))
        self.assertTrue(any(p.check.startswith("Web search") for p in problems))


class TestReport(unittest.TestCase):
    def test_new_markers_and_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state.json"
            first = [Finding("k1", ACTION, "Model", "a")]
            report.mark_new(first, state)
            self.assertFalse(first[0].new)  # first run: nothing is "new", everything is just the baseline
            second = [Finding("k1", ACTION, "Model", "a"), Finding("k2", PREPARE, "Model", "b")]
            report.mark_new(second, state, save=False)
            self.assertEqual([f.new for f in second], [False, True])
            self.assertEqual(json.loads(state.read_text())["keys"], ["k1"])  # dry run didn't save

    def test_escaping_and_links(self):
        f = Finding("k", SIGNAL, "Model", "<b>x</b>", ["<img src=x onerror=alert(1)>"],
                    [("ok", "https://openai.com/a\"onmouseover=\"x"), ("bad", "javascript:alert(1)")])
        body = report.build_html([f], [Problem("<p>", "<script>")], TODAY, "1 model")
        self.assertNotIn("<img", body)
        self.assertNotIn("<script>", body)
        self.assertNotIn("javascript:", body)
        self.assertIn('href="https://openai.com/a&quot;onmouseover=&quot;x"', body)

    def test_subjects(self):
        self.assertIn("✅ All clear", report.subject([], [], TODAY))
        self.assertIn("All clear", report.build_html([], [], TODAY, "x"))
        s = report.subject([Finding("a", ACTION, "Model", "a", new=True), Finding("b", SIGNAL, "Model", "b")],
                           [Problem("x", "y")], TODAY)
        self.assertIn("🔴 1 action", s)
        self.assertIn("🔎 1 signal", s)
        self.assertIn("(1 new)", s)
        self.assertIn("some checks failed", s)


class TestNet(unittest.TestCase):
    def test_only_allowed_https_hosts(self):
        for url in ("http://api.osv.dev/x", "https://evil.example.com/", "https://api.osv.dev.evil.com/",
                    "file:///etc/passwd"):
            with self.assertRaises(net.NetError):
                net.request("GET", url)


class TestMailer(Patched):
    def test_sends_with_token_and_never_leaks_secret(self):
        fake = self.fake({"oauth2": (200, {"access_token": "tok"}), "sendMail": (202, b"")})
        mailer.GraphSender("contoso.onmicrosoft.com", "cid", "hunter2", "radar@contoso.com").send(
            "subj", "<p>hi</p>", ["me@contoso.com"])
        token_call, send_call = fake.calls
        self.assertEqual(token_call[2]["form"]["client_secret"], "hunter2")
        self.assertTrue(send_call[1].endswith("/v1.0/users/radar@contoso.com/sendMail"))
        self.assertEqual(send_call[2]["headers"]["Authorization"], "Bearer tok")
        self.assertEqual(send_call[2]["json_body"]["message"]["toRecipients"],
                         [{"emailAddress": {"address": "me@contoso.com"}}])

    def test_rejected_sign_in(self):
        self.fake({"oauth2": (401, b'{"error":"invalid_client","secret":"hunter2"}')})
        with self.assertRaises(net.NetError) as ctx:
            mailer.GraphSender("t.com", "c", "hunter2", "a@b.com").send("s", "b", ["a@b.com"])
        self.assertIn("401", str(ctx.exception))
        self.assertNotIn("hunter2", str(ctx.exception))

    def test_rejects_bad_settings(self):
        with self.assertRaises(ValueError):
            mailer.GraphSender("../evil", "c", "s", "a@b.com")
        with self.assertRaises(ValueError):
            mailer.GraphSender("t.com", "c", "s", "a@b.com/../../me")


if __name__ == "__main__":
    unittest.main()
