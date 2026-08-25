# bob authenticates against the KDC but has no Kong consumer, so the default
# policy rejects the request.
kinit_as bob || return
negotiate_request /default

assert_status 403 "authenticated principal without a consumer"
assert_body_contains "not a known consumer"
