# kerberos-auth without an anonymous consumer of its own never stands down, so
# a Kerberos ticket is required even when another auth plugin succeeded.

# An API key alone is not enough: key-auth authenticates, kerberos-auth still
# challenges.
drop_tickets
export KRB5CCNAME="/tmp/ccache-none-$$"
request /chained-strict -H "apikey: alice-api-key"

assert_status 401 "API key alone does not satisfy kerberos-auth"
assert_header_matches "^WWW-Authenticate: *Negotiate"

# With a ticket the caller gets through, and kerberos-auth's consumer replaces
# the anonymous one key-auth fell back to.
kinit_as alice || return
negotiate_request /chained-strict

assert_status 200 "Kerberos ticket satisfies the route"
assert_body_contains "X-Consumer-Username: alice"
assert_body_contains "X-Kerberos-Principal: alice@EXAMPLE.TEST"
assert_body_lacks "X-Anonymous-Consumer"
