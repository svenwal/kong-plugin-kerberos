# kong-plugin-kerberos

Kerberos/SPNEGO authentication for Kong, as a Lua plugin.

`kerberos-auth` terminates HTTP `Negotiate` authentication (RFC 4559) at the gateway: it validates
the caller's Kerberos service ticket against a keytab through the GSS-API and maps the authenticated
principal onto a **Kong consumer**, so ACL, rate limiting, request transformation and logging plugins
behave exactly as they do behind `key-auth` or `ldap-auth`.

It can also authenticate *onwards* to a Kerberos protected upstream, reusing the caller's delegated
credential when one was sent so the backend sees the original user.

```
  browser / curl --negotiate            Kong                     upstream
  ───────────────────────────    ────────────────────    ─────────────────────
   GET /api                 ──►  401 WWW-Authenticate: Negotiate
   GET /api                 ──►  gss_accept_sec_context
   Authorization: Negotiate …     → alice@EXAMPLE.TEST
                                  → consumer "alice"    ──► X-Consumer-Username: alice
                                                            X-Kerberos-Principal: alice@EXAMPLE.TEST
                                  (optional) gss_init_sec_context
                                                        ──► Authorization: Negotiate …
```

## Status

Version 0.1.0. Verified end to end against MIT Kerberos 1.20 with both Kong Gateway 3.14 and Kong
OSS 3.9 on Ubuntu 24.04, with a 24 case suite covering consumer mapping, ACL, rate limiting,
delegation and the failure paths. See [Testing](#testing).

## Requirements

- Kong Gateway 3.x or Kong OSS 3.x. The plugin uses only the public PDK.
- A GSS-API implementation reachable by the dynamic linker:
  - **Kong Gateway (Enterprise) images already ship `libgssapi_krb5.so.2`** — nothing to install.
  - **Kong OSS images ship no Kerberos libraries.** Add one layer:

    ```dockerfile
    FROM kong/kong:3.9
    USER root
    RUN apt-get update \
        && apt-get install -y --no-install-recommends libgssapi-krb5-2 \
        && rm -rf /var/lib/apt/lists/*
    USER kong
    ```

- A keytab holding the service key for the name clients use to reach Kong, and a `krb5.conf`.

## Installation

```bash
luarocks make kong-plugin-kerberos-auth-0.1.0-1.rockspec
```

Or mount the source and point Kong at it:

```yaml
environment:
  KONG_PLUGINS: "bundled,kerberos-auth"
  KONG_LUA_PACKAGE_PATH: "/opt/kong-plugin/?.lua;;"
volumes:
  - ./kong:/opt/kong-plugin/kong:ro
  - ./krb5.conf:/etc/krb5.conf:ro
  - ./kong.keytab:/etc/krb5.keytab:ro
```

The keytab must be readable by the user Kong's workers run as (`kong` in the official images).

### Creating the service principal

MIT KDC:

```bash
kadmin -q "addprinc -randkey HTTP/kong.example.com@EXAMPLE.COM"
kadmin -q "ktadd -k /etc/kong/kong.keytab HTTP/kong.example.com@EXAMPLE.COM"
```

Active Directory:

```powershell
setspn -S HTTP/kong.example.com KONG-SVC
ktpass /princ HTTP/kong.example.com@EXAMPLE.COM /mapuser KONG-SVC@EXAMPLE.COM `
       /crypto AES256-SHA1 /ptype KRB5_NT_PRINCIPAL /pass * /out kong.keytab
```

The instance in the principal must match the hostname clients dial, not Kong's internal hostname.
Behind a load balancer, that is the load balancer's name.

## Quick start

```yaml
plugins:
  - name: kerberos-auth
    config:
      keytab: /etc/krb5.keytab
      service_principal: HTTP@kong.example.com

consumers:
  - username: alice          # matches alice@EXAMPLE.COM with the default strip_realm
```

`alice@EXAMPLE.COM` now proxies as consumer `alice`. Anyone else authenticates but gets a 403,
because provisioning a consumer is what grants access.

## How the identity is derived

| Value | Meaning | Example |
|---|---|---|
| `principal` | The full name GSS-API reports | `alice@EXAMPLE.COM` |
| `user` | Everything before `@` | `alice` |
| `realm` | Everything after `@` | `EXAMPLE.COM` |
| `identity` | `principal` after `strip_realm` and `principal_lowercase` | `alice` |

`config.consumer.template` renders these into the consumer lookup key; the default is `${identity}`.
`X-Kerberos-Principal` always carries the untouched principal regardless of how the key was built.

## Configuration

### Kerberos identity

| Field | Default | Description |
|---|---|---|
| `keytab` | `/etc/krb5.keytab` | Keytab holding the service key. |
| `service_principal` | *(none)* | `HTTP@host` or `HTTP/host@REALM`. Unset accepts **any** principal in the keytab. |
| `krb5_config` | *(system)* | Path to `krb5.conf`. |
| `gssapi_library` | `libgssapi_krb5.so.2` | Shared library to load. The Kong images ship the versioned soname only. |
| `replay_cache` | `none` | `none` disables MIT's per-request replay cache file I/O; `default` keeps it. See [Replay cache](#replay-cache). |

### Request handling

| Field | Default | Description |
|---|---|---|
| `header_name` | `Authorization` | Header carrying the token. |
| `scheme` | `Negotiate` | Expected authentication scheme. |
| `challenge_on_missing` | `true` | Answer a request without a token with `401` + `WWW-Authenticate: Negotiate`, which is what starts the exchange. |
| `hide_credentials` | `false` | Strip the header before proxying. |
| `run_on_preflight` | `true` | Also authenticate CORS `OPTIONS` requests. |

### Principal shaping and authorisation

| Field | Default | Description |
|---|---|---|
| `realm` | *(none)* | Only accept principals from this realm. |
| `allowed_principals` | *(none)* | Allow list. A leading `~` marks a PCRE pattern. When set, everything else is rejected. |
| `denied_principals` | *(none)* | Deny list, evaluated first. |
| `strip_realm` | `true` | Drop `@REALM` when deriving the identity. |
| `principal_lowercase` | `false` | Lowercase the identity. Useful with Active Directory. |

### Consumer mapping

| Field | Default | Description |
|---|---|---|
| `consumer.enabled` | `true` | Map the principal onto a consumer. |
| `consumer.by` | `username` | `username` or `custom_id`. |
| `consumer.template` | `${identity}` | Lookup key template. |
| `consumer.on_missing` | `deny` | `deny` → 403, `allow` → proxy without a consumer, `anonymous` → use `config.anonymous`. |
| `consumer.cache_ttl` | `60` | TTL for negative and `custom_id` lookups, in seconds. |
| `anonymous` | *(none)* | Consumer id or username used for the `anonymous` policy and for auth chaining. |

`username` lookups go through Kong's own entity cache key, so consumer changes invalidate
immediately. `custom_id` is not a cache key on the consumers schema, so those lookups use a plugin
scoped key and pick up changes after at most `consumer.cache_ttl` seconds.

See [The anonymous consumer](#the-anonymous-consumer) for what `config.anonymous` does and
how it interacts with the 401 challenge.

### The anonymous consumer

`config.anonymous` behaves exactly as it does in `key-auth`, `ldap-auth` and the other bundled auth
plugins, and takes the same values — a consumer id or a username:

- A request that **cannot be authenticated** proceeds as that consumer instead of getting a 401,
  with `X-Anonymous-Consumer: true` set.
- If another auth plugin on the route already authenticated the caller, this plugin stands down
  without touching the consumer — but, as in Kong's own plugins, only when `config.anonymous` is
  set. That is what makes several auth plugins OR together on one route.
- A missing anonymous consumer is a `500`, not a silent pass.

What it does **not** cover is authorisation. A principal rejected by `realm`, `denied_principals` or
`allowed_principals`, or one refused by `consumer.on_missing: deny`, gets a `403` even when an
anonymous consumer is configured. Those are decisions about a caller who *did* authenticate, and
quietly downgrading them to a shared anonymous identity would turn a deny list into a no-op. Use
`consumer.on_missing: anonymous` when you do want authenticated-but-unmapped principals to borrow
the anonymous consumer's policy.

#### Chaining with other auth plugins

The trade-off is Kerberos specific and worth stating plainly: setting `config.anonymous` means an
unauthenticated request is answered with `200`, not `401`, so a browser is never invited to
negotiate. The two workable arrangements are:

| Goal | Configuration |
|---|---|
| Any one credential is enough | `anonymous` on **every** auth plugin on the route, pointing at the same consumer. Only clients that send a token unprompted will use Kerberos; deny the anonymous consumer with `acl` or `request-termination` if it should not reach the upstream. |
| Kerberos is always required | Leave `anonymous` unset on `kerberos-auth`. It then never stands down and always challenges, so a caller needs a ticket even if another plugin succeeded. |

Both are covered by the test suite (`23-auth-chaining`, `24-auth-chaining-strict`).

### Upstream headers

| Field | Default | Description |
|---|---|---|
| `principal_header` | `X-Kerberos-Principal` | `null` disables. |
| `realm_header` | `X-Kerberos-Realm` | `null` disables. |
| `set_authenticated_userid` | `true` | Sets `X-Authenticated-Userid` and the authenticated credential, so log plugins record the principal. |

Alongside these the plugin sets the usual Kong headers: `X-Consumer-ID`, `X-Consumer-Username`,
`X-Consumer-Custom-ID`, `X-Credential-Identifier`, and `X-Anonymous-Consumer` when the anonymous
consumer was used.

### Token cache

| Field | Default | Description |
|---|---|---|
| `cache.enabled` | `false` | Memoise successful validations, keyed by the SHA-256 of the token. |
| `cache.ttl` | `60` | Lifetime of a memoised validation, in seconds. |

This trades a security property for throughput: within the TTL, a replay of the same token is
accepted without a handshake. Rejections are never cached. It is ignored when a delegated credential
is in use, because delegation needs the live handshake. Off by default.

### Upstream Kerberos (initiator)

| Field | Default | Description |
|---|---|---|
| `upstream.enabled` | `false` | Send a `Negotiate` header to the upstream. |
| `upstream.service_principal` | `HTTP@<upstream host>` | Upstream service principal. |
| `upstream.client_principal` | *(none)* | Identity Kong uses when nothing was delegated. |
| `upstream.keytab` | `config.keytab` | Keytab holding `client_principal`. |
| `upstream.use_delegated_credential` | `true` | Reuse the caller's delegated credential so the upstream sees the original user. |
| `upstream.mechanism` | `auto` | `auto`, `spnego` or `krb5`. See below. |
| `upstream.header_name` | `Authorization` | Header used for the upstream token. |
| `upstream.mutual` | `false` | Request mutual authentication from the upstream. |

**Mechanism selection is not cosmetic.** A credential delegated by a client carries a krb5 element
only. MIT's mechglue hands SPNEGO `GSS_C_NO_CREDENTIAL` when it cannot find a SPNEGO element, and
SPNEGO then quietly falls back to the process default identity — the upstream sees *Kong* instead of
the caller, with no error anywhere. `auto` therefore uses raw Kerberos for delegated credentials and
SPNEGO for credentials Kong acquires itself. Override only if a specific upstream demands it.

For delegation to happen at all, the client has to forward its TGT: `curl --delegation always`, or a
browser configured to trust the SPN (which follows the `ok-as-delegate` flag on the service
principal).

## Replay cache

MIT's acceptor keeps a replay cache, writing a file per request under `/var/tmp`. In a container
that is both a hot spot and a frequent source of permission failures. The default
`replay_cache: none` disables it: Kong sits in front of the real application, and a gateway that
re-validates every ticket against the KDC's clock skew window is not the layer where replay
protection belongs. Set `replay_cache: default` if your threat model says otherwise.

## Performance notes

The GSS-API calls are synchronous C calls on the nginx event loop.

- **Acceptor side** is CPU only. The acceptor credential (and its keytab file I/O) is acquired once
  per worker at configuration time, so a request costs one ticket decryption — tens of microseconds.
- **Initiator side** talks to the KDC. The TGT is acquired at configuration time into a private
  in-process ccache, and service tickets are cached by the krb5 library, so only the first request
  per worker per upstream pays for a round trip. This is why `upstream.enabled` is off by default.

## Testing

Everything runs in Docker — a real MIT KDC, Kong, a header-echo upstream, an Apache
`mod_auth_gssapi` upstream for the delegation cases, and a Kerberos client that drives `kinit` and
`curl --negotiate`.

```bash
make test          # bring the stack up and run the suite
make test-clean    # rebuild everything from scratch first
make shell         # a shell in the client container for manual kinit/curl
make gss-check     # exercise the FFI layer alone, without Kong
make logs          # follow Kong's logs
make down          # tear down, including the realm database
ONLY=17-acl make test                      # one case
KONG_IMAGE=kong/kong:3.9 make test-clean   # against Kong OSS instead
```

The suite covers the happy path, missing/malformed/garbage tokens, unknown consumers under all three
`on_missing` policies, `custom_id` mapping, realm and allow/deny filtering, `hide_credentials`,
mutual authentication, the token cache, ACL group authorisation, per-consumer rate limiting,
destroyed ticket caches, and both upstream identities.

`make gss-check` is the tool to reach for when a Kerberos problem needs to be isolated from routing
and plugin configuration: it initiates and accepts a token in one process against the real keytab.

## Troubleshooting

Kerberos failures are opaque by default, so the plugin renders both halves of every GSS status pair
into the log. Raise `KONG_LOG_LEVEL=debug` to also see the negotiated flags and which credential the
upstream leg used.

| Message | Cause |
|---|---|
| `Keytab FILE:… is nonexistent or empty` | Wrong path, or the keytab is not readable by the `kong` user. |
| `No key table entry found for HTTP/…` | The keytab has no entry for the name clients dial. Check with `klist -k`. |
| `Server HTTP/… not found in Kerberos database` | The SPN does not exist in the realm, or `service_principal` names a host the KDC does not know. |
| `Request ticket server … kvno mismatch` | The keytab is stale; re-export it after a password change. |
| `Clock skew too great` | More than five minutes between Kong, the client and the KDC. |
| `multi-leg SPNEGO negotiation is not supported` | The client fell back to NTLM. See [Limitations](#limitations). |
| `authenticated '…' but no consumer matches '…'` | Authentication worked; provision the consumer or change `consumer.on_missing`. |

Useful `krb5.conf` settings in containers, where reverse DNS rarely matches:

```ini
[libdefaults]
    dns_lookup_kdc = false
    dns_canonicalize_hostname = false
    rdns = false
```

## Limitations

- **Single-leg SPNEGO only.** If `gss_accept_sec_context` asks to continue — NTLM over SPNEGO, and
  some multi-hop cases — the exchange cannot complete: MIT cannot export a SPNEGO context, so the
  context handle cannot survive to the next request or reach another worker. The plugin says so
  explicitly instead of looping.
- **No TLS channel binding** (RFC 5929) and **no S4U2Proxy constrained delegation** in 0.1.0. The
  delegation that is supported is classic TGT forwarding by the client.
- `custom_id` consumer mapping has weaker cache invalidation than `username`, as described above.
- The upstream leg performs blocking KDC I/O on cache misses.

## Licence

Apache-2.0.
