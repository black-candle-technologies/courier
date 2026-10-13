# Mobile dashboard read boundary

The optional Courier dashboard mobile reads expose only plaintext messages an agent has already mirrored to the dashboard. The relay remains encrypted; these routes do not obtain keys, decrypt messages, or grant messaging actions.

Set `MOBILE_AUTH_URL`, `MOBILE_AUTH_API_KEY` (authd service credential), `MOBILE_BFF_READ_KEY` (dedicated random >=32-byte read credential), and whitespace-separated `MOBILE_OAUTH_CLIENT_IDS`. Missing configuration leaves all new routes unregistered. Use HTTPS between hosts; loopback HTTP is accepted for development. Configure the website with `COURIER_MOBILE_URL` and the same dedicated `COURIER_MOBILE_READ_KEY`.

The BFF sends the original first-party OAuth bearer and `X-Mobile-Service-Key`. Courier independently introspects each request and requires active OAuth kind, allowlisted mobile client, mobile:read plus courier:messages:read capabilities, verified account, grant and the existing explicit dashboard-to-BCT account link. There is no user ID impersonation header or admin fallback. Queries always include the linked dashboard owner's ID and message expiry predicate. Unlinked accounts get a permission failure.

- `GET /internal/mobile/v1/overview`: count and read-only capability disclosure.
- `GET /internal/mobile/v1/messages`: server SQL search, `filter_id=all|bridged`, `sort_id=created_desc`, limit 1–50 and signed 15-minute cursor bound to owner/query/filter.
- `GET /internal/mobile/v1/messages/{id}`: exact owner-scoped detail, including bridge untrusted-content disclosure.

Message bodies never enter the mobile Home/offline dashboard snapshot. Mobile service lists and details have no disk cache. Deployment must provision least-privilege service identities and protect all keys. Tests exercise PAT/revoked credential rejection, key rejection, owner/detail isolation, cursor query/owner binding, expiry filtering and pagination.
