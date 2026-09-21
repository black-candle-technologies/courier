# Optional Black Candle account linking (dashboard)

The dashboard can let users log in with their Black Candle account
(`auth.blackcandletech.com`) in addition to their dashboard
username/password. Linking is **per-user opt-in** and the feature is
**off unless the operator configures it** — no build flags, no separate
versions. One codebase, one release; the difference between the hosted
dashboard and a self-hosted one is two environment variables.

## Enabling it (hosted dashboard)

```sh
export BCT_AUTH_URL="https://auth.blackcandletech.com"
export BCT_AUTH_API_KEY="<authd service API key>"
courier-dashboard --addr :8471 --db courier-relay.db
```

Flags `--bct-auth-url` / `--bct-auth-key` override the environment.
Setting the URL without the key is a startup error. With neither set,
the linking routes are not registered and the UI affordances never
render — self-hosted installs are unaffected.

The dashboard acts as an authd API client (`POST /v1/login` to verify
credentials, then `POST /v1/logout` to destroy the throwaway session).
The API key lives in server config only and is never rendered to the
browser. BCT passwords are passed through transiently — never stored,
never logged. Verification goes through authd itself, so its account
lockout and rate limits apply unchanged. Each verification is a real
authd sign-in, so the account holder gets authd's normal "new sign-in"
notification email.

## User flow

1. Log in to the dashboard with the dashboard username/password.
2. Open **Settings** → enter the Black Candle email + password → **Link account**.
   The BCT email must already be confirmed (authd rejects unverified
   logins).
3. Afterwards, the login page offers **Log in with Black Candle**, and
   Settings shows the linked address with an **Unlink** button.

One BCT account links to at most one dashboard user (unique index;
concurrent double-links are rejected). Unlinking never touches the
dashboard password — it keeps working either way.

## Schema

Additive migration on `dashboard_users`: nullable `bct_user_id`
(authd user id, NULL = not linked) and `bct_email` (display only),
plus a unique index on `bct_user_id` (NULLs are distinct, so unlinked
users are unaffected). Safe to apply to existing databases, including
self-hosted ones where the feature stays dormant.
