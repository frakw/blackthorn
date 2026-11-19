#!/bin/bash
# End-to-end test of blackthorn in throwaway Docker containers:
#   hub    Debian + systemd + sshd, runs thorn with a fake claude
#   t1,t2  sshd targets (managed machines)
#   admin  your laptop: SSH client, curl as the browser, oathtool as the phone
# Everything runs in its own Docker network and is removed afterwards.
#
#   cargo build && tests/e2e/run.sh [path/to/thorn]
#
# Needs Docker and permission to run a privileged container (for systemd and
# nftables inside the hub; they act on the container's own namespaces).
# No pipefail: checks below pipe into `grep -q`, which may stop reading early.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
THORN=${1:-$HERE/../../target/debug/thorn}
P=bt-e2e-$$
NET=$P-net
pass=0
WEB_SECRET=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP
SSH_SECRET=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
PASSWORD='correct horse battery staple'

cleanup() {
  if [ -n "${KEEP:-}" ] && [ "${pass_all:-}" != 1 ]; then
    echo "KEEP set: containers $P-* left running; remove with: docker rm -f \$(docker ps -aq -f name=$P)"
    return
  fi
  docker rm -f "$P-hub" "$P-t1" "$P-t2" "$P-admin" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

say() { printf '\n== %s\n' "$*"; }
ok() { pass=$((pass + 1)); printf '   ok: %s\n' "$*"; }
fail() { printf '   FAIL: %s\n' "$*"; exit 1; }
hub() { docker exec "$P-hub" "$@"; }
admin() { docker exec "$P-admin" "$@"; }
thorn() { hub /usr/local/bin/thorn "$@"; }
# The same, passing standard input through.
hubi() { docker exec -i "$P-hub" "$@"; }
thorni() { hubi /usr/local/bin/thorn "$@"; }
key_of() { hub awk -v n="[spaces.$1]" '$0==n{f=1;next} f&&/^key/{gsub(/"/,"",$3);print $3;exit}' /var/lib/blackthorn/state.toml; }
# Sleeps into a fresh 30-second TOTP window (each code is accepted once).
fresh_code() { sleep $((31 - $(date +%s) % 30)); admin oathtool --totp -b "$1"; }

# Waits up to $1 seconds for a space's latest reach.log line for host $3 to
# read $4.
expect_reach() {
  local secs=$1 space=$2 host=$3 want=$4 key got=""
  key=$(key_of "$space")
  for _ in $(seq "$secs"); do
    got=$(hub sh -c "grep ' $host ' /var/lib/blackthorn/spaces/$key/reach.log 2>/dev/null | tail -1 | cut -d' ' -f3")
    [ "$got" = "$want" ] && { ok "$space -> $host: $want"; return; }
    sleep 1
  done
  fail "$space -> $host: wanted $want, last saw '${got:-nothing}'"
}

tcp_open() { docker exec "$1" timeout 4 bash -c "exec 3<>/dev/tcp/$2/$3" 2>/dev/null; }

# Web: curl from the admin container with a cookie jar.
web_get() { admin curl -s -b /tmp/jar -c /tmp/jar "http://$HUB:7180$1"; }
web_post() { local path=$1; shift; admin curl -s -S -o /dev/null -w "%{redirect_url}" -b /tmp/jar -c /tmp/jar "$@" "http://$HUB:7180$path" || echo "curl-failed"; }
csrf() { web_get / | grep -o 'name="csrf" value="[0-9a-f]*"' | head -1 | cut -d'"' -f4; }

say "build images"
for i in hub target admin; do
  docker build -q -t "blackthorn-e2e-$i" -f "$HERE/Dockerfile.$i" "$HERE" >/dev/null
done

say "start containers"
docker network create "$NET" >/dev/null
for t in t1 t2; do
  docker run -d --name "$P-$t" --hostname "$t" --network "$NET" blackthorn-e2e-target >/dev/null
done
docker run -d --name "$P-admin" --hostname admin --network "$NET" blackthorn-e2e-admin >/dev/null
docker run -d --name "$P-hub" --hostname blackthorn --network "$NET" \
  --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock blackthorn-e2e-hub >/dev/null
for _ in $(seq 30); do
  hub systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && break
  sleep 1
done
ip_of() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$P-$1"; }
T1=$(ip_of t1) T2=$(ip_of t2) HUB=$(ip_of hub) ADMIN=$(ip_of admin)
echo "   hub=$HUB t1=$T1 t2=$T2 admin=$ADMIN"

say "one-line install, from a release directory"
# A stand-in for a GitHub release: the binary and its SHA256SUMS.
hub mkdir -p /opt/release /opt/bad
docker cp "$THORN" "$P-hub:/opt/release/thorn-x86_64-linux"
docker cp "$HERE/../../install.sh" "$P-hub:/root/install.sh"
docker cp "$HERE/fake-claude" "$P-hub:/root/fake-claude"
hub sh -c 'cd /opt/release && sha256sum thorn-x86_64-linux > SHA256SUMS'
hub sh -c 'cp /opt/release/thorn-x86_64-linux /opt/bad/ && echo junk >> /opt/bad/thorn-x86_64-linux && cp /opt/release/SHA256SUMS /opt/bad/'
install_from() { hub env BLACKTHORN_DOWNLOAD="file://$1" sh /root/install.sh --no-claude 2>&1; }
out=$(install_from /opt/bad || true)
if echo "$out" | grep -q "checksum mismatch" && ! hub test -e /usr/local/bin/thorn; then
  ok "a binary that does not match SHA256SUMS is refused"
else
  fail "tampered binary: $out"
fi
out=$(install_from /opt/release) || fail "install: $out"
[ "$(hub systemctl is-active blackthorn-web.service)" = active ] && ok "the web UI is on right after install" || fail "web UI on after install"
hub grep -q '0.0.0.0:7180' /etc/blackthorn/config.toml && ok "without Tailscale it listens on every address" || fail "default listen address"
echo "$out" | grep -q "web UI: http://$HUB:7180/" && ok "install prints the web address" || fail "install prints the web address: $out"
echo "$out" | grep -q "sudo thorn web user add" && ok "and how to create the first login" || fail "first login hint"
thorn web disable >/dev/null
install_from /opt/release >/dev/null || fail "upgrade install"
[ "$(hub systemctl is-active blackthorn-web.service)" != active ] && ok "running it again upgrades without turning the web UI back on" || fail "upgrade kept web off"
hub /usr/local/bin/thorn init --claude-from /root/fake-claude >/dev/null

say "configure the web UI and inbound limits"
hubi sh -c "cat > /etc/blackthorn/config.toml" <<EOF
claude_bin = "/usr/local/bin/claude"
never_manage = ["192.0.2.99"]

[inbound]
admin_from = ["$ADMIN"]

[web]
listen = ["$HUB:7180"]
EOF
thorn apply >/dev/null
[ "$(hub systemctl is-active blackthorn-firewall.service)" = active ] && ok "firewall unit active" || fail "firewall unit active"
[ "$(hub systemctl is-active blackthorn-tick.timer)" = active ] && ok "tick timer active" || fail "tick timer active"

say "machines"
for t in t1 t2; do
  ip=$(ip_of $t)
  thorn host add "$t" "alice@$ip" --yes >/dev/null
  line=$(thorn host pubkey "$t")
  case "$line" in "from=\"$HUB\",restrict ssh-ed25519 "*) ok "$t key line is limited to the hub: from=\"$HUB\",restrict";; *) fail "key line: $line";; esac
  echo "$line" | docker exec -i "$P-$t" sh -c 'cat >> /home/alice/.ssh/authorized_keys; chown alice /home/alice/.ssh/authorized_keys; chmod 600 /home/alice/.ssh/authorized_keys'
  thorn host check "$t" | grep -q "(linux)" && ok "host check $t learns its OS" || fail "host check $t learns its OS"
done
# Same machine, re-registered at its address (here unchanged): spaces stay.
thorn host set-address t2 "alice@$T2" --yes | grep -q "replace its blackthorn line" && ok "host set-address" || fail "host set-address"
thorn host check t2 | grep -q "(linux)" && ok "t2 still logs in after set-address" || fail "t2 after set-address"
thorn host set-address t2 "alice@$T1" --yes 2>&1 | grep -q "already registered as t1" && ok "set-address refuses another machine's address" || fail "set-address to t1's address"
thorn host add laptop "me@$ADMIN" --yes 2>&1 | grep -q "device you administer" && ok "refuses to manage an admin device" || fail "refuses to manage an admin device"
thorn host add hs "me@192.0.2.99" --yes 2>&1 | grep -q "never_manage" && ok "refuses a never_manage address" || fail "refuses a never_manage address"

say "the hub refuses connections from managed machines"
tcp_open "$P-admin" "$HUB" 22 && ok "admin device reaches hub ssh" || fail "admin device reaches hub ssh"
if tcp_open "$P-t1" "$HUB" 22; then fail "t1 opened a connection to the hub"; else ok "t1 cannot connect to the hub"; fi
if tcp_open "$P-t1" "$HUB" 7180; then fail "t1 reached the web port"; else ok "t1 cannot reach the web port"; fi

say "spaces"
thorn new t1 | grep -q "created space t1-claude" && ok "thorn new t1 creates t1-claude" || fail "thorn new t1 creates t1-claude"
thorn new t2 --single --rc-name t2-hub >/dev/null
thorn ls | grep -q "needs login" && ok "new Claude spaces wait for sign-in" || fail "new Claude spaces wait for sign-in"
echo good-code | thorni login t2-claude >/dev/null && ok "t2-claude signed in from the command line" || fail "t2-claude signed in from the command line"

say "web UI"
printf '%s\n%s\n' "$PASSWORD" "$(hub /usr/local/bin/thorn _totp $WEB_SECRET)" \
  | thorni web user add frakw --totp-secret "$WEB_SECRET" | grep -q "account frakw added" && ok "web account with TOTP" || fail "web account with TOTP"
thorn web enable >/dev/null
for _ in $(seq 20); do tcp_open "$P-admin" "$HUB" 7180 && break; sleep 0.5; done
[ "$(hub systemctl show -p User --value blackthorn-web)" = blackthorn-web ] && ok "web UI runs as the unprivileged blackthorn-web user" || fail "web UI runs as the unprivileged blackthorn-web user"
[ "$(admin curl -s -o /dev/null -w '%{redirect_url}' "http://$HUB:7180/")" = "http://$HUB:7180/login" ] && ok "pages need a login" || fail "pages need a login"
admin curl -sI "http://$HUB:7180/login" | grep -qi "content-security-policy: default-src 'none'" && ok "strict CSP header" || fail "strict CSP header"
r=$(web_post /login --data-urlencode "user=frakw" --data-urlencode "password=$PASSWORD" --data-urlencode "code=000000")
case "$r" in *"/login?err="*) ok "wrong code refused";; *) fail "login with a wrong code: $r";; esac
code=$(fresh_code $WEB_SECRET)
r=$(web_post /login --data-urlencode "user=frakw" --data-urlencode "password=$PASSWORD" --data-urlencode "code=$code")
[ "$r" = "http://$HUB:7180/" ] && ok "login with password + TOTP" || fail "login with password + TOTP"
web_get / | grep -q '<svg class="map"' && ok "map page draws the SVG map" || fail "map page draws the SVG map"
web_get /map.svg | grep -q 't1-claude' && ok "map shows t1-claude" || fail "map shows t1-claude"
C=$(csrf)
[ -n "$C" ] && ok "got a CSRF value" || fail "got a CSRF value"
r=$(web_post /space/t1-claude/login --data-urlencode "csrf=wrong")
case "$r" in *"stale"*) ok "a form without the right CSRF value is refused";; *) fail "csrf: $r";; esac
page=$(admin curl -s -b /tmp/jar -c /tmp/jar --data-urlencode "csrf=$C" "http://$HUB:7180/space/t1-claude/login")
echo "$page" | grep -q 'https://claude.example/oauth/authorize' && ok "web sign-in shows Claude's sign-in link" || fail "web sign-in shows Claude's sign-in link"
r=$(web_post /space/t1-claude/login-finish --data-urlencode "csrf=$C" --data-urlencode "code=good-code")
case "$r" in *"ok=signed"*) ok "web sign-in finished with the pasted code";; *) fail "sign-in: $r";; esac

say "each space reaches only its own machine"
expect_reach 30 t1-claude t1 ok
expect_reach 10 t1-claude t2 FAIL
expect_reach 20 t2-claude t2 ok
expect_reach 10 t2-claude t1 FAIL
k1=$(key_of t1-claude)
if hub runuser -u "bt-$k1" -- timeout 5 bash -c "exec 3<>/dev/tcp/$T2/22" 2>/dev/null; then
  fail "t1-claude opened a TCP connection to t2"
else
  ok "t1-claude cannot open TCP to t2 even by IP"
fi
if hub runuser -u "bt-$k1" -- timeout 5 bash -c "exec 3<>/dev/tcp/$T1/80" 2>/dev/null; then
  fail "t1-claude reached t1 on a port other than ssh"
else
  ok "t1-claude cannot reach t1 on other ports"
fi
n=$(hub env SSH_AUTH_SOCK="/run/blackthorn-agent/$k1/agent.sock" ssh-add -L | wc -l)
[ "$n" = 1 ] && ok "t1-claude's agent holds 1 key" || fail "t1-claude's agent holds 1 key"
if hub runuser -u "bt-$k1" -- test -r /etc/blackthorn/keys/t1; then
  fail "space user can read the private key file"
else
  ok "space user cannot read private key files"
fi

say "agents were started the right way"
a1=$(hub tail -1 "/var/lib/blackthorn/spaces/$k1/fake-claude.args")
echo "$a1" | grep -q -- '^remote-control --name t1-claude --spawn same-dir --capacity 8' && ok "t1-claude: server mode" || fail "t1-claude: server mode"
k2=$(key_of t2-claude)
a2=$(hub tail -1 "/var/lib/blackthorn/spaces/$k2/fake-claude.args")
echo "$a2" | grep -q -- '--session-id .* --remote-control t2-hub' && ok "t2-claude: single mode, Remote Control name t2-hub" || fail "t2-claude: single mode, Remote Control name t2-hub"
hub test -f "/var/lib/blackthorn/spaces/$k1/work/CLAUDE.md" && ok "instructions written to CLAUDE.md" || fail "instructions written to CLAUDE.md"

say "bridges are one-way and end at once"
thorn bridge add t1-claude t2-claude --for 1h >/dev/null
expect_reach 15 t1-claude t2 ok
expect_reach 5 t2-claude t1 FAIL
hub grep -q 'temporary bridge' "/var/lib/blackthorn/spaces/$k1/work/CLAUDE.md" && ok "CLAUDE.md lists the bridged machine" || fail "CLAUDE.md lists the bridged machine"
thorn bridge rm t1-claude t2-claude >/dev/null
expect_reach 10 t1-claude t2 FAIL

say "web: block and unblock a machine; harmful actions need a fresh code"
r=$(web_post /host/t2/block --data-urlencode "csrf=$C" --data-urlencode "duration=15m" --data-urlencode "reason=from the web")
case "$r" in *"ok=blocked"*) ok "blocked t2 from the web";; *) fail "web block: $r";; esac
expect_reach 10 t2-claude t2 FAIL
web_post /host/t2/unblock --data-urlencode "csrf=$C" >/dev/null
expect_reach 15 t2-claude t2 ok
r=$(web_post /host/t2/rm --data-urlencode "csrf=$C" --data-urlencode "code=123456")
case "$r" in *"fresh%20code"*) ok "removing a machine without a fresh code is refused";; *) fail "step-up: $r";; esac
thorn host ls | grep -q '^t2 ' && ok "t2 is still there" || fail "t2 is still there"

say "settings, from the web and the command line"
web_get /settings | grep -q 'name="inbound.admin_from"' && ok "the settings page lists admin_from" || fail "settings page"
web_get / | grep -q "v$(thorn --version | cut -d' ' -f2)<" && ok "the web UI shows its version" || fail "version in the web UI"
admin curl -s "http://$HUB:7180/static/logo.svg" | grep -q "<svg" && ok "the logo is served" || fail "logo"
code=$(fresh_code $WEB_SECRET)
r=$(web_post /settings --data-urlencode "csrf=$C" --data-urlencode "inbound.admin_from=192.0.2.77" --data-urlencode "code=$code")
case "$r" in *"lock%20you%20out"*) ok "a setting that would lock you out is refused";; *) fail "lock-out guard: $r";; esac
code=$(fresh_code $WEB_SECRET)
r=$(web_post /settings --data-urlencode "csrf=$C" --data-urlencode "inbound.deny_from=192.0.2.50" --data-urlencode "code=$code")
case "$r" in *"ok=saved"*) ok "a setting saved from the web";; *) fail "web settings: $r";; esac
thorn firewall show | grep -q "192.0.2.50" && ok "and applied to the firewall at once" || fail "setting applied"
thorn config set inbound.deny_from "" >/dev/null && ! hub grep -q "192.0.2.50" /etc/blackthorn/config.toml && ok "thorn config set empties a list" || fail "config set"
hub env SSH_CONNECTION="192.0.2.9 50000 $HUB 22" /usr/local/bin/thorn config set inbound.admin_from 192.0.2.77 2>&1 | grep -q "lock you out" && ok "the command line refuses to lock out its SSH user too" || fail "CLI lock-out guard"

say "block cuts a machine off now, and lifts itself"
thorn host block t1 --for 70s --reason test >/dev/null
expect_reach 10 t1-claude t1 FAIL
n=$(hub env SSH_AUTH_SOCK="/run/blackthorn-agent/$k1/agent.sock" ssh-add -L 2>/dev/null | grep -c ssh- || true)
[ "$n" = 0 ] && ok "key taken out of t1-claude's agent while blocked" || fail "key taken out of t1-claude's agent while blocked"
echo "   waiting for the block to expire (tick runs every minute)..."
expect_reach 150 t1-claude t1 ok

say "rename keeps the space and restarts with the new Remote Control name"
thorn rename t1-claude t1-main >/dev/null
sleep 3
hub tail -1 "/var/lib/blackthorn/spaces/$k1/fake-claude.args" | grep -q -- '--name t1-main' && ok "t1-main restarted with the new name" || fail "t1-main restarted with the new name"
expect_reach 15 t1-main t1 ok

say "SSH two-factor: undone automatically unless confirmed"
admin cat /root/.ssh/id_ed25519.pub | hubi sh -c 'cat > /home/admin/.ssh/authorized_keys; chown admin:admin /home/admin/.ssh/authorized_keys; chmod 600 /home/admin/.ssh/authorized_keys'
SSHO="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
admin ssh $SSHO -o BatchMode=yes "admin@$HUB" true && ok "admin logs in with a key before" || fail "admin logs in with a key before"
hub /usr/local/bin/thorn _totp $SSH_SECRET | thorni harden ssh --totp --user admin --rollback-after 20s --totp-secret $SSH_SECRET >/dev/null
if admin ssh $SSHO -o BatchMode=yes "admin@$HUB" true 2>/dev/null; then fail "key alone still works"; else ok "a key alone is no longer enough"; fi
admin sh -c "printf '#!/bin/sh\noathtool --totp -b $SSH_SECRET\n' > /tmp/askpass; chmod +x /tmp/askpass"
admin env SSH_ASKPASS=/tmp/askpass SSH_ASKPASS_REQUIRE=force DISPLAY=x ssh $SSHO "admin@$HUB" true </dev/null && ok "key + TOTP code logs in" || fail "key + TOTP code logs in"
echo "   not confirming; waiting for the automatic undo..."
sleep 25
admin ssh $SSHO -o BatchMode=yes "admin@$HUB" true && ok "unconfirmed change was undone: key alone works again" || fail "unconfirmed change was undone: key alone works again"
hub /usr/local/bin/thorn _totp $SSH_SECRET | thorni harden ssh --totp --user admin --totp-secret $SSH_SECRET >/dev/null
thorn harden confirm >/dev/null
sleep 2
hub test -f /etc/ssh/sshd_config.d/10-blackthorn.conf && ok "confirmed change stays" || fail "confirmed change stays"
thorn harden undo >/dev/null

say "reboot: everything comes back by itself"
docker restart "$P-hub" >/dev/null
for _ in $(seq 40); do
  hub systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && break
  sleep 1
done
hub nft list table inet blackthorn >/dev/null && ok "firewall loaded after reboot" || fail "firewall loaded after reboot"
hub sh -c ": > /var/lib/blackthorn/spaces/$k1/reach.log"
expect_reach 30 t1-main t1 ok
expect_reach 10 t1-main t2 FAIL
expect_reach 20 t2-claude t2 ok
for _ in $(seq 20); do tcp_open "$P-admin" "$HUB" 7180 && break; sleep 1; done
admin curl -s -o /dev/null -w '%{http_code}' "http://$HUB:7180/login" | grep -q 200 && ok "web UI back after reboot" || fail "web UI back after reboot"

say "remove a space"
thorn rm t2-claude >/dev/null
hub id "bt-$k2" >/dev/null 2>&1 && fail "user bt-$k2 still exists" || ok "t2-claude's user removed"
hub test -d "/var/lib/blackthorn/archive/t2-claude-$k2" && ok "t2-claude's files archived" || fail "t2-claude's files archived"
thorn status

pass_all=1
printf '\nall %d checks passed\n' "$pass"
