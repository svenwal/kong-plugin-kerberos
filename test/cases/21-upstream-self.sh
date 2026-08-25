# Without delegation Kong authenticates upstream as its own principal.
kinit_as alice || return
negotiate_request /upstream-self

assert_status 200 "keytab derived initiator credential accepted"
assert_body_contains "Remote-User: kong-client@EXAMPLE.TEST"

# A different caller still reaches the upstream as Kong.
kinit_as dave || return
negotiate_request /upstream-self
assert_status 200 "second caller"
assert_body_contains "Remote-User: kong-client@EXAMPLE.TEST"
