# carol maps to consumer krb-carol through custom_id rather than username.
kinit_as carol || return
negotiate_request /custom-id

assert_status 200 "consumer.by=custom_id"
assert_body_contains "X-Consumer-Username: krb-carol"
assert_body_contains "X-Consumer-Custom-Id: carol"
assert_body_contains "X-Kerberos-Principal: carol@EXAMPLE.TEST"
