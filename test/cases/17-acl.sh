# The consumer the plugin resolves is the one the ACL plugin authorises.
kinit_as alice || return
negotiate_request /acl
assert_status 200 "alice is in the admins group"

kinit_as dave || return
negotiate_request /acl
assert_status 403 "dave is a consumer but not in admins"
