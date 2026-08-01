#!/usr/bin/env bash
#
# verify_unix_socket_auth.sh
# Manual verification of the AF_UNIX + SO_PEERCRED control-port auth on
# branch security/control-unix-socket.
#
#   ./verify_unix_socket_auth.sh
#
# The cross-UID checks need sudo (it will prompt once) and an unprivileged
# user such as 'nobody'. They are reported as SKIP if either is unavailable.
#
set -u

# ---- locate the repo root (this script may sit at root or in tests/) -------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR"
while [ "$ROOT" != "/" ] && [ ! -f "$ROOT/src/hypervisor.c" ]; do
   ROOT="$(dirname "$ROOT")"
done
[ -f "$ROOT/src/hypervisor.c" ] || { echo "cannot find repo root (src/hypervisor.c)"; exit 2; }
cd "$ROOT"

BIN="$ROOT/ubridge"
SOCK="/tmp/ubridge-verify-$$.sock"
PROBE="/tmp/ubridge-probe-$$.py"
UBPID=""
HPID=""

PASS=0; FAIL=0; SKIP=0
ok(){   printf '  [PASS] %s\n' "$1"; PASS=$((PASS+1)); }
bad(){  printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL+1)); }
skip(){ printf '  [SKIP] %s\n' "$1"; SKIP=$((SKIP+1)); }

cleanup(){
   [ -n "${UBPID:-}" ] && kill "$UBPID" 2>/dev/null
   [ -n "${HPID:-}" ] && kill "$HPID" 2>/dev/null
   wait 2>/dev/null
   rm -f "$SOCK" "$PROBE"
}
trap cleanup EXIT

# ---- probe helper (python; callable by any user) --------------------------
# Connects to an AF_UNIX socket, sends one command, prints a verdict token:
#   CONNECT_ERROR:<Exception>   could not connect (e.g. permission denied)
#   CLOSED                      connected, then socket closed (rejection)
#   EMPTY                       connected, no data before EOF (rejection)
#   TIMEOUT                     connected, no reply within 3s
#   REPLY:<first-line>          got a reply line
cat > "$PROBE" <<'PY'
import socket, sys
sock, cmd = sys.argv[1], sys.argv[2]
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(3)
    s.connect(sock)
except Exception as e:
    print("CONNECT_ERROR:" + type(e).__name__); sys.exit(0)
try:
    s.sendall((cmd + "\n").encode())
    data = s.recv(100)
except socket.timeout:
    print("TIMEOUT"); sys.exit(0)
except Exception:
    print("CLOSED"); sys.exit(0)
print("EMPTY" if not data else "REPLY:" + data.decode(errors="replace").split("\r")[0])
PY
chmod 644 "$PROBE"   # readable so 'nobody' can run it via sudo

probe(){          python3 "$PROBE" "$1" "$2"; }              # as current user
probe_as(){ sudo -u "$1" python3 "$PROBE" "$2" "$3"; }       # as another user

echo "== build =="
if make >/tmp/ubridge-verify-make.log 2>&1; then
   ok "make"
else
   bad "make failed (see /tmp/ubridge-verify-make.log)"; exit 1
fi

echo "== start ubridge on an AF_UNIX control socket =="
rm -f "$SOCK"
"$BIN" -U "$SOCK" >/tmp/ubridge-verify-ub.log 2>&1 &
UBPID=$!
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
if [ ! -S "$SOCK" ]; then bad "ubridge did not create $SOCK"; exit 1; fi

echo "== same-UID acceptance (baseline) =="
out=$(probe "$SOCK" "hypervisor version")
case "$out" in
   REPLY:100-*) ok "same-UID gets a reply ($out)" ;;
   *)           bad "same-UID expected a reply, got '$out'" ;;
esac

echo "== cross-UID rejection =="
ALTUID=""
for u in nobody ftp mail daemon; do
   if id "$u" >/dev/null 2>&1; then ALTUID="$u"; break; fi
done

if [ -z "$ALTUID" ]; then
   skip "cross-UID checks (no unprivileged user like 'nobody' found)"
elif ! sudo -v 2>/dev/null; then
   skip "cross-UID checks (no sudo rights; re-run with a sudo-capable account)"
else
   # (a) file-permission layer: 0600 socket -> cross-UID cannot even connect.
   out=$(probe_as "$ALTUID" "$SOCK" "hypervisor version")
   case "$out" in
      CONNECT_ERROR:*) ok "cross-UID blocked at connect by 0600 file perms ($out)" ;;
      *)              bad "cross-UID reached the 0600 socket ('$out')" ;;
   esac

   # (b) SO_PEERCRED in isolation: open the socket so cross-UID can connect,
   #     then ubridge must close it with no reply.
   chmod 666 "$SOCK"
   out=$(probe_as "$ALTUID" "$SOCK" "hypervisor version")
   case "$out" in
      EMPTY|CLOSED) ok "cross-UID rejected by SO_PEERCRED ($out)" ;;
      REPLY:*)      bad "SECURITY: cross-UID received a command reply ($out)" ;;
      *)            bad "cross-UID unexpected result ('$out')" ;;
   esac
fi

echo "== transport checks (the AF_UNIX -U instance) =="
if ss -ltnp 2>/dev/null | grep -q '"ubridge"'; then
   bad "AF_UNIX (-U) instance unexpectedly has a TCP listener"
else
   ok "AF_UNIX (-U) instance exposes no TCP listener"
fi

if ss -lx 2>/dev/null | grep -q "$(basename "$SOCK")"; then
   ok "AF_UNIX control socket is listening"
else
   bad "AF_UNIX control socket not seen in 'ss -lx'"
fi

echo "== TCP -H works and defaults to loopback (127.0.0.1, not 0.0.0.0) =="
HPORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
"$BIN" -H "$HPORT" >/tmp/ubridge-verify-tcp.log 2>&1 &
HPID=$!
for _ in $(seq 1 50); do ss -ltn 2>/dev/null | grep -qE ":$HPORT([^0-9]|$)" && break; sleep 0.1; done
bound=$(ss -ltn 2>/dev/null | grep -E ":$HPORT([^0-9]|$)" | head -1)
case "$bound" in
   *127.0.0.1:$HPORT*) ok "TCP -H binds loopback 127.0.0.1:$HPORT" ;;
   "")                 bad "TCP -H did not listen ($bound)" ;;
   *)                  bad "TCP -H not on loopback ($bound)" ;;
esac
case "$bound" in
   *0.0.0.0:$HPORT*|*\*:$HPORT*|*:::$HPORT*)
      bad "TCP -H bound to all interfaces (should be loopback only)" ;;
   *) ok "TCP -H not bound to 0.0.0.0/*" ;;
esac
trep=$(python3 - "$HPORT" <<'PY'
import socket, sys
p = int(sys.argv[1]); s = socket.create_connection(("127.0.0.1", p), timeout=3)
s.sendall(b"hypervisor version\n")
print(s.recv(100).decode(errors="replace").split("\r")[0])
PY
)
case "$trep" in
   100-*) ok "TCP -H local connect gets reply ($trep)" ;;
   *)      bad "TCP -H local connect no reply ('$trep')" ;;
esac
kill "$HPID" 2>/dev/null; wait "$HPID" 2>/dev/null; HPID=""

echo "== TCP -H 0.0.0.0:<port> (opt-in) binds all interfaces =="
WPORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("0.0.0.0",0)); print(s.getsockname()[1]); s.close()')
"$BIN" -H "0.0.0.0:$WPORT" >/tmp/ubridge-verify-tcp2.log 2>&1 &
HPID=$!
for _ in $(seq 1 50); do ss -ltn 2>/dev/null | grep -qE ":$WPORT([^0-9]|$)" && break; sleep 0.1; done
wbound=$(ss -ltn 2>/dev/null | grep -E ":$WPORT([^0-9]|$)" | head -1)
case "$wbound" in
   *0.0.0.0:$WPORT*|*\*:$WPORT*|*:::$WPORT*)
      ok "TCP -H 0.0.0.0:$WPORT binds all interfaces (opt-in works)" ;;
   *127.0.0.1:$WPORT*)
      bad "TCP -H 0.0.0.0:$WPORT ignored the explicit IP (bound loopback only)" ;;
   "") bad "TCP -H 0.0.0.0:$WPORT did not listen ($wbound)" ;;
   *)  bad "TCP -H 0.0.0.0:$WPORT unexpected bind ($wbound)" ;;
esac
kill "$HPID" 2>/dev/null; wait "$HPID" 2>/dev/null; HPID=""

echo
echo "Result: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
