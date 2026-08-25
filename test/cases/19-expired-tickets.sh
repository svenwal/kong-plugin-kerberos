# Destroying the ticket cache must produce a challenge, not a server error.
kinit_as alice || return
negotiate_request /default
assert_status 200 "authenticated before kdestroy"

drop_tickets
export KRB5CCNAME="/tmp/ccache-empty-$$"
negotiate_request /default
assert_status 401 "no ticket cache"
