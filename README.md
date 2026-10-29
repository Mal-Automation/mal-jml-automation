# JML Automation — Joiner / Mover / Leaver security workflow

[![CI](../../actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)

A Python tool that automates Mal's employee **onboarding** and **offboarding** security steps across the identity and access stack: **Okta → Google Workspace → 1Password → Jamf → Slack/e-mail**.

```
                 ┌──────── JOINER ────────┐                ┌──────── LEAVER ─────────┐
 HRIS / CLI ───► │ 1 Okta: create+activate │   HRIS / CLI ─►│ 1 Okta: kill sessions + │
 GitHub Action   │   + add to `engineering`│   GitHub Action│   OAuth tokens, deactivate│
                 │ 2 GWS: create account   │                │ 2 GWS: revoke ALL OAuth │
                 │ 3 1Password: invite +   │                │   tokens, sign-out, suspend│
                 │   add to vault group    │                │ 3 1Password: remove from │
                 │ 4 Jamf: e-mail MDM      │                │   every vault group, suspend│
                 │   enrollment invitation │                │ 4 1Password Events: verify│
                 └───────────┬────────────┘                └────────────┬────────────┘
                             └──── JSON audit record + Slack / e-mail alert ◄┘
```

## What it does

| # | Requirement | Joiner | Leaver |
|---|---|---|---|
| 1 | **Okta user lifecycle** | Create & activate user, create group if missing, assign to `engineering` | Clear all sessions and Okta-issued OAuth tokens, then **deactivate** (or `--okta-mode suspend`) |
| 2 | **Google Workspace** | Create user with random 20-char temp password, forced reset at first login (password never logged or returned) | **Revoke every OAuth token** (`tokens.list` → `tokens.delete`), sign out of all sessions, suspend |
| 3 | **1Password vault access** | Provision user via SCIM (sends invite), add to vault group (e.g. `Engineering`) | Remove from **every** group (so every shared vault), then suspend; verify via Events API |
| 4 | **MDM enrollment** | Build a realistic Jamf Pro `computerinvitations` XML payload, send it (mocked), log request and response | – |
| 5 | **Alert** | Summary sent | **Slack Block Kit** message (user, UTC timestamp, every action, failures) and/or SMTP e-mail; console fallback |

How it handles failures:

- **A leaver run never stops early.** If Okta is down, Google tokens and 1Password access are still revoked. Partial revocation beats none. Every failure is listed in the alert under "Needs follow-up".
- **Dependent steps are skipped, not failed.** For example, the Okta group assignment is skipped if the Okta user could not be created.
- **Idempotent.** Re-running a joiner finds existing users instead of erroring.
- **Audit trail.** Every run writes `reports/<event>-<user>-<timestamp>.json`. The exit code is `1` if any step failed, so schedulers and CI can tell.
- **Retries.** 429 and 5xx responses are retried with backoff, and `Retry-After` is respected (Okta rate limits).

## Real vs. mocked API calls

Each integration picks its mode on its own (`JML_MODE=auto`, the default): **live if its credentials are set, mocked if not.** `JML_MODE=mock` forces everything to mock. `JML_MODE=live` makes missing credentials an error.

| System | Real implementation | Free account? | Default without creds |
|---|---|---|---|
| **Okta** | Management API v1 (`/api/v1/users`, `/groups`, `/lifecycle/*`, `/sessions`), `SSWS` token | ✅ [Okta Integrator (developer) org](https://developer.okta.com/signup/) | Mock (`fixtures/okta_*.json`) |
| **Google Workspace** | Admin SDK Directory API (`users.insert/get/update/signOut`, `tokens.list/delete`) via service account + domain-wide delegation | ✅ 14-day Workspace trial | Mock (`fixtures/gws_*.json`) |
| **1Password** | **SCIM Bridge** (SCIM 2.0 Users/Groups PATCH) + **Events API** (`/api/v1/auditevents`) | ✅ 14-day Business trial | Mock (`fixtures/op_*.json`) |
| **Jamf Pro** | `POST /api/v1/auth/token` → `POST /JSSResource/computerinvitations/id/0` → invalidate token | ❌ no self-serve free tier | **Mocked by design.** The real payload is built and logged, and the response comes from a fixture |
| **Slack** | Incoming webhook (Block Kit) | ✅ free workspace | Console output |
| **E-mail** | SMTP + STARTTLS | – | Console output |

> **Why 1Password SCIM and not Connect?** 1Password Connect can only read and write *items* inside vaults. It cannot manage people or vault membership. Membership is managed through the SCIM Bridge. Vault permissions are granted to **groups** (set up once by an admin, e.g. `Engineering` → `Eng-Shared`, `Eng-Prod`), so adding or removing group membership is how vault access is granted and revoked. Suspending the user also removes any direct vault grants. The Events API is read-only, so it is used to **verify** the change in the audit log.

Mocked responses are **realistic fixtures** that mirror each vendor's documented response schema, with the user's email and name filled in. The test suite uses `responses` and `MagicMock` to check the **exact live HTTP requests** (URLs, headers, SCIM PatchOps, Okta query params) without any network access.

## Quick start (runs fully mocked, no accounts needed)

```bash
git clone <this-repo-url> jml-automation && cd jml-automation
python3 -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt

# Onboard a new hire
python -m jml --mock join --first Ada --last Lovelace --email ada@mal.example \
    --title "Senior Engineer" --okta-group engineering --vault-group Engineering

# Offboard a departing employee
python -m jml --mock leave --email bob@mal.example

# Process a batch (e.g. an HRIS export)
python -m jml --mock run --file examples/events.json
```

Example leaver output:

```
JML LEAVER COMPLETED
User:      bob.departing@mal.example
Started:   2026-10-29T10:22:24+00:00
Finished:  2026-10-29T10:22:24+00:00

Actions taken:
  [SUCCESS] Okta: clear sessions + deactivate user [mock] - id=00u8mock… -> DEPROVISIONED
  [SUCCESS] Google Workspace: revoke all OAuth tokens [mock] - 3 revoked: Slack, Zoom, GitHub
  [SUCCESS] Google Workspace: sign out all sessions & suspend [mock] - signed out, suspended
  [SUCCESS] 1Password: remove from all shared vaults & suspend [mock] - removed from: Engineering, On-Call, All Staff
  [SUCCESS] 1Password: verify audit trail (Events API) [mock] - 2 matching audit event(s)
```

## Running against real APIs

```bash
cp .env.example .env      # then fill in whichever systems you have
python -m jml join --first Ada --last Lovelace --email ada@yourdomain.com
python -m jml leave --email ada@yourdomain.com
```

All secrets are read from environment variables (or a local `.env`, which is git-ignored). **No credentials are hardcoded.**

### Okta (free)
1. Sign up at <https://developer.okta.com/signup/>.
2. Go to **Security → API → Tokens → Create token**.
3. Set `OKTA_ORG_URL=https://dev-XXXXX.okta.com` and `OKTA_API_TOKEN=...`.
4. The `engineering` group is created automatically if it doesn't exist.

### Google Workspace (trial)
1. Start a Workspace trial. In Google Cloud, enable the **Admin SDK API**.
2. Create a service account and download its JSON key. Save it as `service-account.json` (git-ignored).
3. In **Admin console → Security → API controls → Domain-wide delegation**, add the service account's client ID with these scopes:
   `https://www.googleapis.com/auth/admin.directory.user,https://www.googleapis.com/auth/admin.directory.user.security`
4. Set `GWS_SERVICE_ACCOUNT_FILE` and `GWS_ADMIN_SUBJECT` (a super-admin to impersonate).

### 1Password (trial)
1. Start a 1Password Business trial. Go to **Integrations → Directory → SCIM bridge**, deploy it, and copy the bearer token.
2. Create a group `Engineering` and grant it access to your shared vaults.
3. Set `OP_SCIM_BRIDGE_URL` and `OP_SCIM_TOKEN`. Optionally, set `OP_EVENTS_TOKEN` from **Integrations → Events Reporting**.

### Slack
Create an app with **Incoming Webhooks**, add it to `#security-alerts`, and set `SLACK_WEBHOOK_URL`.

## Automated runs (GitHub Actions)

| Workflow | Trigger | Purpose |
|---|---|---|
| `.github/workflows/ci.yml` | push / PR | `ruff check`, `black --check`, `pytest`, and a mocked end-to-end smoke run on Python 3.10 and 3.12 |
| `.github/workflows/jml.yml` | **Run workflow** button, or `repository_dispatch` from your HRIS | Runs a real joiner or leaver using repository **secrets**, then uploads the JSON audit record as a build artifact (kept 90 days) |

To trigger an offboarding from an HRIS or webhook:

```bash
curl -X POST -H "Authorization: Bearer $GH_TOKEN" \
  https://api.github.com/repos/<owner>/<repo>/dispatches \
  -d '{"event_type":"jml-leaver","client_payload":{"email":"bob@mal.example"}}'
```

Workflow inputs are passed through `env:` and never interpolated into shell commands, to prevent script injection. The GWS key is written with `umask 077` to the runner's temporary directory.

## Tests and linting

```bash
pytest -q            # 41 tests, no network
ruff check .         # lint (pycodestyle, pyflakes, isort, bugbear, bandit rules)
black --check .      # formatting
```

| Module | Tests |
|---|---|
| `jml/clients/okta.py` | create (with activate), idempotency, group assign / auto-create, offboard deactivate & suspend, 404 handling, error-summary parsing, no HTTP in mock mode |
| `jml/clients/google_workspace.py` | insert without leaking password, idempotency, revoke each OAuth token, partial-failure reporting, sign-out + suspend, password complexity |
| `jml/clients/onepassword.py` | SCIM provision, add-member PatchOp, missing group, remove-from-all + suspend, partial failure still suspends, Events API filtering |
| `jml/clients/mdm.py` | XML payload realism and escaping, mocked response logging, live token → invite → invalidate flow |
| `jml/notify.py` | Slack Block Kit content, webhook POST, Slack failure → console fallback, SMTP e-mail |
| `jml/workflow.py`, `jml/cli.py` | Full joiner, dependent-step skipping, leaver continues after failure and alerts, audit record written, batch CLI, live-mode config error |
| `jml/config.py`, `jml/models.py` | Mode selection, validation, report aggregation |

## Project layout

```
jml/
  cli.py                 # python -m jml join | leave | run
  workflow.py            # orchestration, failure handling, audit records
  config.py              # env-var settings, live/mock selection
  models.py              # Employee, ActionResult, WorkflowReport
  notify.py              # Slack / e-mail / console alerts
  http.py                # retrying requests session
  fixtures.py            # templated mock responses
  clients/
    okta.py  google_workspace.py  onepassword.py  mdm.py
fixtures/                # realistic vendor response fixtures
tests/                   # pytest suite
examples/events.json     # sample HRIS batch
```

## Security notes

- Least privilege: the Okta token should belong to an admin role scoped to user and group management. Google scopes are limited to `directory.user` and `directory.user.security`.
- Secrets are never logged. Generated passwords are never returned or printed.
- Leaver order is chosen to cut access fastest: the IdP session first (stops new SSO logins), then app-level OAuth grants, then the password vault.
- **Mover** (department change) = joiner group assignment for the new team plus a scoped leaver step for the old vault group. The building blocks (`add_user_to_group`, `add_to_vault_group`, SCIM remove PatchOp) are already in place.
