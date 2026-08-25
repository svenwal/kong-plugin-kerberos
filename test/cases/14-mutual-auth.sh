# curl requests mutual authentication, so the successful response must carry
# the acceptor's token back.
kinit_as alice || return
negotiate_request /default

assert_status 200 "mutual authentication"
assert_final_header_matches "^WWW-Authenticate: *Negotiate [A-Za-z0-9+/=]+"
