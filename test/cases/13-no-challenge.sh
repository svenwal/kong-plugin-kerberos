# With challenge_on_missing off the plugin refuses without inviting a retry.
request /no-challenge

assert_status 401 "challenge_on_missing=false"
assert_header_not_matches "^WWW-Authenticate:"
