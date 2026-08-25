# A valid ticket from a realm the route does not accept is refused.
kinit_as alice || return
negotiate_request /wrong-realm

assert_status 403 "realm mismatch"
