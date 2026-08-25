# Rate limiting counts per consumer, which only works if the plugin set one.
kinit_as alice || return

for i in 1 2 3; do
  negotiate_request /rate-limited
  assert_status 200 "alice request ${i} of 3"
done

negotiate_request /rate-limited
assert_status 429 "alice exceeds her per-consumer limit"

# A different consumer has its own counter.
kinit_as dave || return
negotiate_request /rate-limited
assert_status 200 "dave is counted separately"
