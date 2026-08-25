# A principal with a matching consumer is authenticated and fully identified
# to the upstream and to downstream plugins.
kinit_as alice || return
negotiate_request /default

assert_status 200 "alice on the default route"
assert_body_contains "X-Kerberos-Principal: alice@EXAMPLE.TEST"
assert_body_contains "X-Kerberos-Realm: EXAMPLE.TEST"
assert_body_contains "X-Consumer-Username: alice"
assert_body_contains "X-Consumer-Id:"
assert_body_contains "X-Credential-Identifier: alice@EXAMPLE.TEST"
assert_body_contains "X-Authenticated-Userid: alice@EXAMPLE.TEST"
assert_body_lacks "X-Anonymous-Consumer"
