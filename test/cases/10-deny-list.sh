kinit_as mallory || return
negotiate_request /deny-list
assert_status 403 "denied principal"

kinit_as dave || return
negotiate_request /deny-list
assert_status 200 "principal not on the deny list"
