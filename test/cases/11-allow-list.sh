kinit_as alice || return
negotiate_request /allow-list
assert_status 200 "principal matches the allow list pattern"

kinit_as carol || return
negotiate_request /allow-list
assert_status 403 "principal outside the allow list"
