# Transport setup and upgrades

Courier currently supports direct pinned TLS. A proxy that intercepts TLS presents
its own certificate and fails an existing relay pin. Cloud transport is unavailable;
changing to SPKI pinning, trusting the interception certificate, or repinning to it
cannot provide Courier's intended relay authentication. There is no fallback.

For a new identity, obtain the relay's current full certificate SHA256 through an
independent trusted operator channel, then run:

```
courier init --transport direct-tls --relay https://relay.example --fingerprint VERIFIED_SHA256
```

An interactive setup without `--transport` asks for `direct-tls` or cancellation.
Unattended setup requires that flag. Every new setup and explicit `init --repin`
requires `--fingerprint`; a mismatch fails before saving identity/trust or
publishing keys. `--force` does not waive those requirements. Do not recreate or
move an existing identity merely because its environment cannot use direct TLS.

Existing omitted transport fields keep their URL-based behavior, endpoint and
pin. Existing local/custom non-HTTPS setups remain a legacy compatibility case;
new CLI setup requires HTTPS. Library test fixtures can still use local HTTP.
The config commands expose explicit policy without changing trust:

```
courier config get relay_transport
courier config get dashboard_transport
courier config set relay_transport direct-tls
courier config set dashboard_transport direct-tls
```

Dashboard policy is separate because its server can differ from the relay.
`dashboard setup --fingerprint VERIFIED_SHA256` verifies its own certificate; the
existing shared-host rule can use the already pinned relay fingerprint. Setup
fails when no independent expected pin is available. Pinned HTTPS and bootstrap
requests reject redirects. All ordinary endpoints, attachments and wake retain
existing HTTP request formats and leaf-pin verification.

The first interactive `courier update` asks to keep current transport settings or
cancel. Typing `keep` records only acknowledgement under the config lock; it does
not select a new mode or replace pins. EOF, `yes` and cancel do not acknowledge.
Later interactive upgrades skip that question. Noninteractive upgrades never read
stdin for this choice or write a transport selection. Automatic updates and the
installer preserve transport settings and show guidance. A damaged identity does
not prevent updating the executable; it must be repaired before identity traffic.

Relay operators can explicitly set `courier-relay --transport direct-tls` (also the
default). Any other value fails before database/certificate creation or listening.
No relay deployment or certificate change is required for this scaffold.

Old executables do not understand these fields. No cloud transport is enabled by
this release, and no cross-version downgrade protection is claimed. Keep existing
working installations on their original policy; new cloud functionality needs
verified platform support, a reviewed standard and independent security review.
See [the design and outstanding requirements](transport-policy-design.md).
