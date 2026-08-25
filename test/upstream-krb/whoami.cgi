#!/bin/sh
echo "Content-Type: text/plain"
echo ""
echo "Upstream: secure.example.test"
echo "Remote-User: ${REMOTE_USER}"
echo "Auth-Type: ${AUTH_TYPE}"
