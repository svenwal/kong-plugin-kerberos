# Unmatched principals borrow the anonymous consumer, so downstream policy
# still has something to attach to.
kinit_as bob || return
negotiate_request /anonymous-fallback

assert_status 200 "on_missing=anonymous"
assert_body_contains "X-Consumer-Username: guest"
assert_body_contains "X-Anonymous-Consumer: true"

# A principal that is explicitly denied must stay denied. Authorisation
# decisions are never downgraded to the anonymous consumer, even on a route
# whose whole purpose is the anonymous fallback.
kinit_as mallory || return
negotiate_request /anonymous-fallback

assert_status 403 "deny list beats the anonymous fallback"
assert_body_lacks "X-Consumer-Username: guest"
