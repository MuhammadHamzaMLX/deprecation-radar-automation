# deprecation-radar

Every **Tuesday and Thursday at 9:00 AM (Pakistan time)** this repo emails you one report covering:

1. **Vulnerable pip packages.** Each package in `watchlist/requirements.txt` is checked against [OSV.dev](https://osv.dev).
2. **Retiring OpenAI models.** Each model in `watchlist/models.txt` is checked against:
   - your API key's model list (a missing model fails in production right now)
   - OpenAI's official [deprecations page](https://developers.openai.com/api/docs/deprecations)
   - an OpenAI web search for early news, replacement models and migration notes

The email has three sections. Anything that wasn't in the previous email is marked **NEW**.

| Section | What goes there |
|---|---|
| 🔴 ACTION NOW | Model shut down, unavailable, or shutting down within 14 days. High or critical vulnerability. |
| 🟠 PREPARE | Model deprecated with a later shutdown date. Moderate, low or unrated vulnerability. |
| 🔎 EARLY SIGNALS | Web search reports a retirement that OpenAI hasn't officially listed. |

- If nothing is found you get **✅ All clear**.
- If a check couldn't run, the email says so under **⚠️ Checks that could not finish**, so the radar never goes quiet by accident.

## Day-to-day use

Edit the two files in `watchlist/` and push. That's all.

- `watchlist/requirements.txt`: paste your production `pip freeze`. Only `name==version` lines can be checked; anything else is listed as "not checked".
- `watchlist/models.txt`: one OpenAI model name per line, spelled exactly as in your API calls.

## One-time setup

1. **Create a private GitHub repo** named `deprecation-radar` and push this folder to it. Keep it private: the watchlist shows which libraries and models your company uses.
2. **Add the secrets** under *Settings → Secrets and variables → Actions → Secrets*:

   | Secret | Value |
   |---|---|
   | `OPENAI_API_KEY` | An OpenAI key for the **same project production uses**, so "not available" means the same thing for both. A restricted key that can only read models and make Responses API calls is enough. |
   | `GRAPH_TENANT_ID` | Azure tenant ID |
   | `GRAPH_CLIENT_ID` | Azure app (client) ID |
   | `GRAPH_CLIENT_SECRET` | A **new** client secret made just for this repo (see below) |
   | `MAIL_FROM` | The mailbox the app sends as |
   | `MAIL_TO` | Your Outlook address |

3. *(Optional)* To change the research model, set the variable `OPENAI_RESEARCH_MODEL` under the *Variables* tab. The default is `gpt-5.6-terra`. The radar also checks its own research model for retirement.
4. **Test it.** Go to *Actions → deprecation-radar → Run workflow*. Check that the email arrives.

If sending fails, the run fails and GitHub emails the repo owner about the failed workflow.

## Run locally

Copy `.env.example` to `.env`, which git ignores, and fill it in. Then run one of these:

```bash
python -m radar --dry-run
```

This writes `outbox/report.html` and sends nothing.

```bash
python -m unittest discover -s tests -v
```

This runs the tests. They use no network and no secrets.

## Security

**What leaves your company**
- **OSV.dev** receives package names and versions only.
- **OpenAI** receives model names and today's date only (`store: false`), plus your API key.
- **Microsoft Graph** receives the report, which goes to `MAIL_TO` only.
- No source code, company name, customer data or other secrets are sent anywhere.

**What can't happen**
- **Nothing from the watchlist is installed or executed.** `requirements.txt` is parsed as plain text.
- **No third-party Python packages.** The radar uses the Python standard library only, so nothing is installed into the run.
- **Network access is allow-listed.** Only six HTTPS hosts can be contacted (see `radar/net.py`). Redirects to any other host are refused, and requests carrying an API key or token don't follow redirects at all.
- **Secrets stay hidden.** They live only in GitHub secrets and are passed to a single workflow step. Error messages contain status codes, never keys, tokens or response bodies.
- **The workflow is locked down.**
  - It runs only on a schedule or a manual button press. It never runs on pull requests, so outside code can't reach your secrets.
  - Its GitHub token is read-only.
  - The actions it uses are pinned to exact commits.
- **Web content is treated as untrusted.**
  - OSV, OpenAI and web-search text is HTML-escaped in the email, and only `https://` links are shown.
  - Web-search results are labelled "verify" and can never put an item in 🔴 ACTION.
  - The research model is told to ignore instructions found on web pages.

**Ask IT for these on the Azure app**
1. **A separate client secret for this repo.** You can then revoke it without breaking the Voice bot. Set a short expiry and a calendar reminder to rotate it.
2. **Restrict `Mail.Send` to the one sending mailbox** with an Exchange Online *Application Access Policy* or *RBAC for Applications*. Without this, the `Mail.Send` application permission lets the app send as **any** mailbox in the company, so a leaked secret would be serious. With it, a leaked secret can only send from that one mailbox.
3. If your company uses **Conditional Access** for workload identities, sign-ins from GitHub's servers may be blocked. The run will then fail with "Graph sign-in failed".

## Files

```
watchlist/requirements.txt   what you edit: pip packages
watchlist/models.txt         what you edit: OpenAI models
radar/net.py                 the only network code (allow-list, timeouts, size limit)
radar/vulns.py               OSV vulnerability check
radar/models.py              OpenAI model checks
radar/report.py              email HTML, NEW markers
radar/mailer.py              Microsoft Graph sender / dry-run outbox
radar/__main__.py            runs it all
.github/workflows/radar.yml  Tue + Thu schedule
.github/workflows/tests.yml  tests on every push
```
