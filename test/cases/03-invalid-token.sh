# Malformed input must be rejected cleanly: 401, never a 500.
request /default -H "Authorization: Negotiate bm90LWEtdmFsaWQtdG9rZW4="
assert_status 401 "well formed base64 that is not a GSS token"

request /default -H "Authorization: Negotiate !!!not-base64!!!"
assert_status 401 "malformed base64"

request /default -H "Authorization: Negotiate"
assert_status 401 "scheme without a token"

request /default -H "Authorization: Basic YWxpY2U6c2VjcmV0"
assert_status 401 "wrong authentication scheme"

request /default -H "Authorization: Negotiate $(head -c 4000 /dev/urandom | base64 -w0)"
assert_status 401 "large random token"
