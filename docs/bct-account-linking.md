# Optional Black Candle login via OAuth (dashboard)

The dashboard can let users log in with their Black Candle account
(`auth.blackcandletech.com`) in addition to their dashboard
username/password, using OAuth 2.0. Linking is **per-user opt-in** and
the feature is **off unless the operator configures it** — no build
flags, no separate versions. One codebase, one release; the difference
between the hosted dashboard and a self-hosted one is three environment
variables.

The dashboard **never collects Black Candle passwords**. Users
authenticate on the provider's own site (`auth.blackcandletech.com`),
approve the connection, and the provider redirects back with a
single-use authorization code that the dashboard exchanges for an
access token. Only the token's view of the account (id, email,
email-verified) is ever used.

## Enabling it (hosted dashboard)

```sh
export BCT_OAUTH_URL="https://auth.blackcandletech.com"
export BCT_OAUTH_CLIENT_ID="courier-dashboard"
export BCT_OAUTH_CLIENT_SECRET="<oauth client secret>"
# Optional: exact redirect URI registered with the provider. When empty,
# it is derived from each incoming request (https + host + the path
# below). Set it explicitly in production.
export BCT_OAUTH_REDIRECT_URI="https://courier.blackcandletech.com/oauth/bct/callback"
courier-dashboard --addr :8471 --db courier-relay.db
```

Flags `--bct-oauth-url` / `--bct-oauth-client-id` /
`--bct-oauth-client-secret` / `--bct-oauth-redirect-uri` override the
environment. Partial configuration (any of the first three set without
the others) is a startup error. With none set, the OAuth routes are not
registered and the UI affordances never render — self-hosted installs
are unaffected.

The provider side must register the client (`OAUTH_CLIENT_ID`,
`OAUTH_CLIENT_SECRET`, `OAUTH_REDIRECT_URIS` in authd) with the exact
redirect URI above.

## How it works

1. The dashboard redirects the browser to the provider's
   `/oauth/authorize` with `response_type=code`, `scope=identity`, a
   single-use `state`, and a PKCE S256 `code_challenge`.
2. The user logs in on `auth.blackcandletech.com` (if needed) and
   approves the connection. The provider redirects back to
   `/oauth/bct/callback` with the authorization `code` and `state`.
3. The dashboard validates and consumes the state (single-use,
   10-minute expiry, bound to the login/link intent and — for linking —
   the dashboard user), exchanges the code for an access token (HTTP
   Basic client auth + PKCE verifier), and reads `/oauth/userinfo`
   (only `email_verified` accounts are accepted).
4. Login intent: the BCT user id is mapped to the linked dashboard
   user and a dashboard session is issued. Link intent: the BCT
   account is bound to the current dashboard user.

The OAuth `state` values live in a mutex-guarded in-memory map and are
purged lazily. CSRF is bound by single-use state; authorization-code
interception is bound by PKCE. The client secret lives in server config
only and is never rendered to the browser.

## User flow

1. Log in to the dashboard with the dashboard username/password.
2. Open **Settings** → **Link Black Candle account** → sign in on
   `auth.blackcandletech.com` and approve. The BCT email must already
   be confirmed (unverified accounts are rejected at userinfo).
3. Afterwards, the login page offers **Log in with Black Candle**
   (below the regular form), and Settings shows the linked address
   with an **Unlink** button.

One BCT account links to at most one dashboard user (unique index;
concurrent double-links are rejected). Re-linking the same account to
the same user is a no-op success. Unlinking never touches the
dashboard password — it keeps working either way.

## Schema

Additive migration on `dashboard_users`: nullable `bct_user_id`
(authd user id, NULL = not linked) and `bct_email` (display only),
plus a unique index on `bct_user_id` (NULLs are distinct, so unlinked
users are unaffected). Safe to apply to existing databases, including
self-hosted ones where the feature stays dormant.
