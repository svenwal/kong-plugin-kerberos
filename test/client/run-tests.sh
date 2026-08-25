#!/usr/bin/env bash
# Runs every case in $CASES_DIR against the running Kong.
set -uo pipefail

CASES_DIR="${CASES_DIR:-/suite-cases}"
ONLY="${ONLY:-}"

export KRB5_CONFIG=/etc/krb5.conf

total=0
failed_cases=0

echo "kerberos-auth end to end suite"
echo "  proxy: ${KONG_PROXY:-http://kong.example.test:8000}"
echo "  cases: ${CASES_DIR}"
echo

for case_file in "${CASES_DIR}"/*.sh; do
  [[ -e "$case_file" ]] || continue

  name="$(basename "$case_file" .sh)"
  if [[ -n "$ONLY" && "$name" != *"$ONLY"* ]]; then
    continue
  fi

  total=$((total + 1))
  echo "  ${name}"

  marker="$(mktemp)"
  rm -f "$marker"

  (
    export CASE_FAIL_MARKER="$marker"
    # shellcheck source=/dev/null
    . /suite/lib.sh
    # shellcheck source=/dev/null
    . "$case_file"
  )

  if [[ -e "$marker" ]]; then
    failed_cases=$((failed_cases + 1))
    rm -f "$marker"
  fi
  echo
done

echo "------------------------------------------------------------"
if [[ "$failed_cases" -gt 0 ]]; then
  echo "${failed_cases} of ${total} case(s) failed"
  exit 1
fi
echo "all ${total} case(s) passed"
