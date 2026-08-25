# Repeated calls with cache.enabled must keep returning the same identity.
kinit_as alice || return

negotiate_request /token-cache
assert_status 200 "first call populates the cache"
assert_body_contains "X-Consumer-Username: alice"

negotiate_request /token-cache
assert_status 200 "second call served with the cache warm"
assert_body_contains "X-Consumer-Username: alice"
assert_body_contains "X-Kerberos-Principal: alice@EXAMPLE.TEST"
