#!/bin/bash
# Verifies: exploits work on :5000 (vulnerable) and fail on :5001 (secure),
# while legitimate functionality survives on :5001.
# Usage: bash tests/verify.sh
set -u
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "PASS: $1"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL: $1"; }
need() { command -v "$1" >/dev/null || { echo "need $1"; exit 2; }; }
need curl; need python3

V=http://localhost:5000; S=http://localhost:5001
curl -s -m 5 $V/api/health | grep -q '"secure":false' || { bad "vuln health"; }
curl -s -m 5 $S/api/health | grep -q '"secure":true'  || { bad "secure health"; }

rm -f /tmp/vcj.txt /tmp/scj.txt
curl -s -m 5 -c /tmp/vcj.txt -d 'username=alice&password=alice123' $V/login -o /dev/null
curl -s -m 5 -c /tmp/scj.txt -d 'username=alice&password=alice123' $S/login -o /dev/null

# 1. IDOR: vuln leaks, secure 403s
curl -s -m 5 -b /tmp/vcj.txt $V/api/tickets/2 | grep -q 'Medical accommodation' \
  && ok "vuln IDOR leaks ticket 2" || bad "vuln IDOR leaks ticket 2"
curl -s -m 5 -b /tmp/vcj.txt $V/api/users/2 | grep -q 'private_note' \
  && ok "vuln IDOR leaks user 2" || bad "vuln IDOR leaks user 2"
curl -s -m 5 -b /tmp/scj.txt $S/api/tickets/2 | grep -q 'forbidden' \
  && ok "secure IDOR ticket 403" || bad "secure IDOR ticket 403"
curl -s -m 5 -b /tmp/scj.txt $S/api/users/2 | grep -q 'forbidden' \
  && ok "secure IDOR user 403" || bad "secure IDOR user 403"

# 2. SQLi: vuln UNION dumps, secure returns []
PAYLOAD="q='%20UNION%20SELECT%20id,username,password%20FROM%20users--%20"
curl -s -m 5 -b /tmp/vcj.txt "$V/api/search?$PAYLOAD" \
  | grep -q 'admin123' && ok "vuln SQLi dumps creds" || bad "vuln SQLi dumps creds"
[ "$(curl -s -m 5 -b /tmp/scj.txt "$S/api/search?$PAYLOAD")" = "[]" ] \
  && ok "secure SQLi neutralized" || bad "secure SQLi neutralized"
[ "$(curl -s -m 5 -d "username=admin'-- &password=x" $S/login -o /dev/null -w '%{http_code}')" = "401" ] \
  && ok "secure login bypass blocked" || bad "secure login bypass blocked"

# 3. XSS: vuln renders raw, secure escapes
MARK="verify-$(date +%s)"
curl -s -m 5 -b /tmp/vcj.txt -H 'Content-Type: application/json' \
  -d "{\"body\":\"<script>alert('$MARK')</script>\"}" $V/api/tickets/4/comments -o /dev/null
curl -s -m 5 -b /tmp/vcj.txt $V/ticket/4 | grep -q "<script>alert('$MARK')" \
  && ok "vuln XSS renders raw" || bad "vuln XSS renders raw"
curl -s -m 5 -b /tmp/scj.txt -H 'Content-Type: application/json' \
  -d "{\"body\":\"<script>alert('$MARK')-secure</script>\"}" $S/api/tickets/4/comments -o /dev/null
curl -s -m 5 -b /tmp/scj.txt $S/ticket/4 | grep -q '&lt;script&gt;' \
  && ok "secure XSS escaped" || bad "secure XSS escaped"

# 4. SSRF: vuln returns flag, secure blocks
curl -s -m 5 -b /tmp/vcj.txt -H 'Content-Type: application/json' \
  -d '{"url":"http://127.0.0.1:5000/internal/secret"}' $V/api/avatar/fetch \
  | grep -q 'flag{ssrf-reached-internal-admin}' \
  && ok "vuln SSRF reaches internal" || bad "vuln SSRF reaches internal"
curl -s -m 5 -b /tmp/scj.txt -H 'Content-Type: application/json' \
  -d '{"url":"http://127.0.0.1:5000/internal/secret"}' $S/api/avatar/fetch \
  | grep -q 'blocked' \
  && ok "secure SSRF blocked" || bad "secure SSRF blocked"

# 5. Secure functionality intact
curl -s -m 5 -b /tmp/scj.txt "$S/api/search?q=wifi" | grep -q 'Office wifi' \
  && ok "secure search works" || bad "secure search works"
[ "$(curl -s -m 5 -o /dev/null -w '%{http_code}' $S/api/debug)" = "404" ] \
  && ok "secure debug disabled" || bad "secure debug disabled"

echo "--- $PASS passed, $FAIL failed ---"
[ "$FAIL" = "0" ]
