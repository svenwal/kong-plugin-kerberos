# The canonical Kong multi-auth recipe: key-auth (priority 1250) and
# kerberos-auth (1000) on one route, both pointing at the same anonymous
# consumer, OR'd together.

# An API key satisfies key-auth, so kerberos-auth stands down rather than
# challenging a caller who is already authenticated.
drop_tickets
export KRB5CCNAME="/tmp/ccache-none-$$"
request /chained-auth -H "apikey: alice-api-key"

assert_status 200 "key-auth wins, kerberos-auth stands down"
assert_body_contains "X-Consumer-Username: alice"
assert_body_lacks "X-Kerberos-Principal"
assert_body_lacks "X-Anonymous-Consumer"

# Neither credential: both plugins fall back to the shared anonymous consumer.
request /chained-auth

assert_status 200 "no credentials falls through as the anonymous consumer"
assert_body_contains "X-Consumer-Username: guest"
assert_body_contains "X-Anonymous-Consumer: true"

# The Kerberos trade-off of that recipe, asserted rather than assumed: with an
# anonymous consumer configured there is no 401, so a browser is never invited
# to negotiate. Use the /chained-strict arrangement when the challenge matters.
assert_header_not_matches "^WWW-Authenticate:"
