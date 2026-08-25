#!/usr/bin/env bash
# Boots a single-realm MIT KDC for the kerberos-auth plugin test suite and
# publishes the service keytabs into the shared /keytabs volume.
#
# Principal and keytab creation is idempotent, so the realm database can be
# kept across restarts while new principals are still picked up.
set -euo pipefail

REALM="${REALM:-EXAMPLE.TEST}"
MASTER_PASSWORD="${MASTER_PASSWORD:-masterkey}"
USER_PASSWORD="${USER_PASSWORD:-kerberos123}"
KEYTAB_DIR="${KEYTAB_DIR:-/keytabs}"

log() { echo "[kdc] $*"; }

kadm() { kadmin.local -q "$*" >/dev/null; }

principal_exists() {
  kadmin.local -q "getprinc $1" 2>/dev/null | grep -q "^Principal:"
}

ensure_service_principal() {
  local principal="$1"
  if ! principal_exists "$principal"; then
    log "creating service principal ${principal}"
    # ok_as_delegate lets clients following the Kerberos policy forward their
    # TGT to Kong, which is what the delegation test exercises.
    kadm "addprinc -randkey +ok_as_delegate ${principal}"
  fi
}

ensure_user_principal() {
  local principal="$1"
  if ! principal_exists "$principal"; then
    log "creating user principal ${principal}"
    kadm "addprinc -pw ${USER_PASSWORD} ${principal}"
  fi
}

rm -f "${KEYTAB_DIR}/.ready"
mkdir -p "${KEYTAB_DIR}"

if [[ ! -f /var/lib/krb5kdc/principal ]]; then
  log "creating realm ${REALM}"
  kdb5_util create -s -r "${REALM}" -P "${MASTER_PASSWORD}"
fi

# Service principals. The instance names must match the hostnames clients dial,
# which the docker-compose network aliases provide.
ensure_service_principal "HTTP/kong.example.test@${REALM}"
ensure_service_principal "HTTP/secure.example.test@${REALM}"
# Identity Kong authenticates as upstream when no credential was delegated.
ensure_service_principal "kong-client@${REALM}"

# End users. alice/carol/dave map to consumers, bob deliberately does not,
# mallory exists to exercise the deny list.
for user in alice bob carol dave mallory; do
  ensure_user_principal "${user}@${REALM}"
done

if [[ ! -f "${KEYTAB_DIR}/kong.keytab" ]]; then
  log "exporting kong keytab"
  kadm "ktadd -k ${KEYTAB_DIR}/kong.keytab HTTP/kong.example.test@${REALM} kong-client@${REALM}"
fi

if [[ ! -f "${KEYTAB_DIR}/secure.keytab" ]]; then
  log "exporting secure upstream keytab"
  kadm "ktadd -k ${KEYTAB_DIR}/secure.keytab HTTP/secure.example.test@${REALM}"
fi

# World readable: this is a throwaway test realm, and the kong and apache
# containers run as unprivileged users that must read these.
chmod 644 "${KEYTAB_DIR}"/*.keytab

log "starting krb5kdc"
krb5kdc
log "starting kadmind"
kadmind -nofork &

# Wait for the KDC to answer before advertising readiness.
for _ in $(seq 1 30); do
  if kinit -k -t "${KEYTAB_DIR}/kong.keytab" "HTTP/kong.example.test@${REALM}" 2>/dev/null; then
    kdestroy 2>/dev/null || true
    break
  fi
  sleep 1
done

touch "${KEYTAB_DIR}/.ready"
log "ready"

wait -n
