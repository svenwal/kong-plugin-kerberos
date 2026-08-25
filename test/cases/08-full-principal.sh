# With strip_realm off the lookup key keeps the realm.
kinit_as alice || return
negotiate_request /full-principal

assert_status 200 "strip_realm=false"
assert_body_contains "X-Consumer-Username: alice@EXAMPLE.TEST"
