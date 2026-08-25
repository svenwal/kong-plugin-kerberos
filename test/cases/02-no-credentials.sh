# Without a token the plugin must start the exchange, not just refuse.
request /default

assert_status 401 "no Authorization header"
assert_header_matches "^WWW-Authenticate: *Negotiate"
