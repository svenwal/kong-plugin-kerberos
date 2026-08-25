# Shared helpers for the kerberos-auth end to end cases.
# Every case runs in its own subshell with this file sourced.

KONG_PROXY="${KONG_PROXY:-http://kong.example.test:8000}"
REALM="${REALM:-EXAMPLE.TEST}"
USER_PASSWORD="${USER_PASSWORD:-kerberos123}"

RESP_STATUS=""
RESP_BODY=""
RESP_HEADERS=""

if [[ -t 1 ]]; then
  C_OK=$'\033[32m'; C_BAD=$'\033[31m'; C_OFF=$'\033[0m'
else
  C_OK=""; C_BAD=""; C_OFF=""
fi

pass() { printf '    %sok%s   %s\n' "$C_OK" "$C_OFF" "$*"; }

failed() {
  printf '    %sFAIL%s %s\n' "$C_BAD" "$C_OFF" "$*"
  touch "$CASE_FAIL_MARKER"
}

note() { printf '         %s\n' "$*"; }

# Obtains a TGT for the given user into a ccache private to this case.
kinit_as() {
  local user="$1"
  export KRB5CCNAME="/tmp/ccache-${user}-$$"
  if ! printf '%s\n' "$USER_PASSWORD" | kinit "${user}@${REALM}" >/dev/null 2>&1; then
    failed "kinit ${user}@${REALM} failed"
    return 1
  fi
  return 0
}

drop_tickets() {
  kdestroy -A >/dev/null 2>&1 || true
  unset KRB5CCNAME
}

# request <path> [curl args...]
request() {
  local path="$1"; shift
  local hdr body
  hdr="$(mktemp)"; body="$(mktemp)"

  RESP_STATUS="$(curl -sS -o "$body" -D "$hdr" -w '%{http_code}' \
                      --max-time 20 "$@" "${KONG_PROXY}${path}" 2>/dev/null || echo 000)"
  RESP_BODY="$(cat "$body")"
  RESP_HEADERS="$(cat "$hdr")"
  rm -f "$hdr" "$body"
}

# Same, but let curl run the SPNEGO exchange with the current ticket cache.
negotiate_request() {
  local path="$1"; shift
  request "$path" --negotiate -u : "$@"
}

assert_status() {
  if [[ "$RESP_STATUS" == "$1" ]]; then
    pass "status $1${2:+ ($2)}"
  else
    failed "expected status $1, got ${RESP_STATUS}${2:+ ($2)}"
    note "body: $(printf '%s' "$RESP_BODY" | head -c 200)"
  fi
}

assert_body_contains() {
  if printf '%s' "$RESP_BODY" | grep -qiF -- "$1"; then
    pass "body contains '$1'"
  else
    failed "body does not contain '$1'"
    note "body: $(printf '%s' "$RESP_BODY" | head -c 300)"
  fi
}

assert_body_lacks() {
  if printf '%s' "$RESP_BODY" | grep -qiF -- "$1"; then
    failed "body unexpectedly contains '$1'"
  else
    pass "body does not contain '$1'"
  fi
}

assert_header_matches() {
  if printf '%s' "$RESP_HEADERS" | grep -qiE -- "$1"; then
    pass "response headers match /$1/"
  else
    failed "response headers do not match /$1/"
    note "headers: $(printf '%s' "$RESP_HEADERS" | tr '\r' ' ' | head -c 300)"
  fi
}

# Matches only within the final response block, which is what the client sees
# after curl has finished the 401 -> 200 Negotiate exchange.
assert_final_header_matches() {
  local final
  final="$(printf '%s' "$RESP_HEADERS" | tr -d '\r' | awk '
    /^HTTP\// { block = "" }
    { block = block $0 "\n" }
    END { printf "%s", block }')"

  if printf '%s' "$final" | grep -qiE -- "$1"; then
    pass "final response headers match /$1/"
  else
    failed "final response headers do not match /$1/"
    note "final block: $(printf '%s' "$final" | head -c 300)"
  fi
}

assert_header_not_matches() {
  if printf '%s' "$RESP_HEADERS" | grep -qiE -- "$1"; then
    failed "response headers unexpectedly match /$1/"
    note "headers: $(printf '%s' "$RESP_HEADERS" | tr '\r' ' ' | head -c 300)"
  else
    pass "response headers do not match /$1/"
  fi
}
