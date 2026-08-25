# With no service_principal pinned, any principal in the keytab is accepted.
kinit_as alice || return
negotiate_request /any-service-principal

assert_status 200 "service_principal unset"
assert_body_contains "X-Consumer-Username: alice"
