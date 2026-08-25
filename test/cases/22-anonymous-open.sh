# config.anonymous on its own: a caller who cannot authenticate proceeds as the
# anonymous consumer rather than being challenged. This is the same semantic
# config.anonymous has in key-auth and ldap-auth.
drop_tickets
export KRB5CCNAME="/tmp/ccache-none-$$"
request /anonymous-open

assert_status 200 "no credentials with an anonymous consumer configured"
assert_body_contains "X-Consumer-Username: guest"
assert_body_contains "X-Anonymous-Consumer: true"
assert_body_lacks "X-Kerberos-Principal"

# A caller who does authenticate is still identified as themselves, and the
# anonymous marker must be cleared.
kinit_as alice || return
negotiate_request /anonymous-open

assert_status 200 "authenticated caller on the same route"
assert_body_contains "X-Consumer-Username: alice"
assert_body_contains "X-Kerberos-Principal: alice@EXAMPLE.TEST"
assert_body_lacks "X-Anonymous-Consumer"
