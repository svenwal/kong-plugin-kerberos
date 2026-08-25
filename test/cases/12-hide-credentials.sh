# The Negotiate header must not leak to the upstream.
kinit_as alice || return
negotiate_request /hide-credentials

assert_status 200 "hide_credentials=true"
assert_body_contains "X-Consumer-Username: alice"
assert_body_lacks "Authorization: Negotiate"
