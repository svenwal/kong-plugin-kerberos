# The same principal passes on a route configured to proxy without a consumer.
kinit_as bob || return
negotiate_request /allow-unmapped

assert_status 200 "on_missing=allow"
assert_body_contains "X-Kerberos-Principal: bob@EXAMPLE.TEST"
assert_body_contains "X-Authenticated-Userid: bob@EXAMPLE.TEST"
assert_body_lacks "X-Consumer-Username"
