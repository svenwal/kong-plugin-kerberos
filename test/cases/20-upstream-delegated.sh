# Kong re-authenticates to a Kerberos protected upstream using the credential
# the caller delegated, so the upstream sees the original user.
kinit_as alice || return
negotiate_request /upstream-delegated --delegation always

assert_status 200 "delegated credential accepted by mod_auth_gssapi"
assert_body_contains "Remote-User: alice@EXAMPLE.TEST"
assert_body_contains "Auth-Type: Negotiate"

# A second caller must reach the upstream as themselves, not as the first
# caller whose credential a worker happened to cache.
kinit_as dave || return
negotiate_request /upstream-delegated --delegation always

assert_status 200 "second delegating caller"
assert_body_contains "Remote-User: dave@EXAMPLE.TEST"

# Without delegation Kong has nothing to forward and falls back to its own
# identity rather than failing.
kinit_as alice || return
negotiate_request /upstream-delegated
assert_status 200 "caller did not delegate"
assert_body_lacks "Remote-User: alice@EXAMPLE.TEST"
