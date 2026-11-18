#!/bin/bash
# End-to-end test of blackthorn in throwaway Docker containers:
#   hub   Debian + systemd, runs thorn with a fake claude
#   t1,t2 sshd targets
# Everything runs in its own Docker network and is removed afterwards.
#
#   cargo build && tests/e2e/run.sh [path/to/thorn]
#
# Needs Docker and permission to run a privileged container (for systemd and
# nftables inside the hub; they act on the container's own namespaces).
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
THORN=${1:-$HERE/../../target/debug/thorn}
P=bt-e2e-$$
NET=$P-net
pass=0

cleanup() {
  docker rm -f "$P-hub" "$P-t1" "$P-t2" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

say() { printf '\n== %s\n' "$*"; }
ok() { pass=$((pass + 1)); printf '   ok: %s\n' "$*"; }
fail() { printf '   FAIL: %s\n' "$*"; exit 1; }
hub() { docker exec "$P-hub" "$@"; }
thorn() { hub /usr/local/bin/thorn "$@"; }

# Waits up to $1 seconds for a session's latest reach.log line for host $3
# to read $4.
expect_reach() {
  local secs=$1 sess=$2 host=$3 want=$4 key got=""
  key=$(hub awk -v n="[sessions.$sess]" '$0==n{f=1;next} f&&/^key/{gsub(/"/,"",$3);print $3;exit}' /var/lib/blackthorn/state.toml)
  for _ in $(seq "$secs"); do
    got=$(hub sh -c "grep ' $host ' /var/lib/blackthorn/sessions/$key/reach.log 2>/dev/null | tail -1 | cut -d' ' -f3")
    [ "$got" = "$want" ] && { ok "$sess -> $host: $want"; return; }
    sleep 1
  done
  fail "$sess -> $host: wanted $want, last saw '${got:-nothing}'"
}

say "build images"
docker build -q -t blackthorn-e2e-hub -f "$HERE/Dockerfile.hub" "$HERE" >/dev/null
docker build -q -t blackthorn-e2e-target -f "$HERE/Dockerfile.target" "$HERE" >/dev/null

say "start containers"
docker network create "$NET" >/dev/null
for t in t1 t2; do
  docker run -d --name "$P-$t" --hostname "$t" --network "$NET" blackthorn-e2e-target >/dev/null
done
docker run -d --name "$P-hub" --hostname blackthorn --network "$NET" \
  --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock blackthorn-e2e-hub >/dev/null
for _ in $(seq 30); do
  hub systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && break
  sleep 1
done
T1=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$P-t1")
T2=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$P-t2")
echo "   t1=$T1 t2=$T2"

say "init"
docker cp "$THORN" "$P-hub:/root/thorn"
docker cp "$HERE/fake-claude" "$P-hub:/root/fake-claude"
hub /root/thorn init --claude-from /root/fake-claude
[ "$(hub systemctl is-active blackthorn-firewall.service)" = active ] && ok "firewall unit active"
[ "$(hub systemctl is-active blackthorn-tick.timer)" = active ] && ok "tick timer active"

say "hosts"
thorn host add t1 "alice@$T1" --yes
thorn host add t2 "alice@$T2" --yes
for t in t1 t2; do
  thorn host pubkey "$t" | docker exec -i "$P-$t" sh -c 'cat >> /home/alice/.ssh/authorized_keys; chown alice /home/alice/.ssh/authorized_keys; chmod 600 /home/alice/.ssh/authorized_keys'
  thorn host check "$t" && ok "host check $t"
done

say "sessions"
thorn new alpha --host t1
thorn new beta --host t2 --rc-name beta-hub
for s in alpha beta; do
  key=$(hub awk -v n="[sessions.$s]" '$0==n{f=1;next} f&&/^key/{gsub(/"/,"",$3);print $3;exit}' /var/lib/blackthorn/state.toml)
  # Stand-in for `thorn login`: the fake claude does not need credentials.
  hub install -d -o "bt-$key" -g "bt-$key" "/var/lib/blackthorn/sessions/$key/.claude"
  hub install -o "bt-$key" -g "bt-$key" -m 600 /dev/null "/var/lib/blackthorn/sessions/$key/.claude/.credentials.json"
done
thorn start alpha beta
thorn ls

say "each session reaches only its own hosts"
expect_reach 20 alpha t1 ok
expect_reach 10 alpha t2 FAIL
expect_reach 10 beta t2 ok
expect_reach 10 beta t1 FAIL

say "a session cannot get around ssh_config by connecting directly"
akey=$(hub awk '/^\[sessions.alpha\]/{f=1;next} f&&/^key/{gsub(/"/,"",$3);print $3;exit}' /var/lib/blackthorn/state.toml)
if hub runuser -u "bt-$akey" -- timeout 5 bash -c "exec 3<>/dev/tcp/$T2/22" 2>/dev/null; then
  fail "alpha opened a TCP connection to t2"
else
  ok "alpha cannot open TCP to t2 even by IP"
fi
if hub runuser -u "bt-$akey" -- timeout 5 bash -c "exec 3<>/dev/tcp/$T1/80" 2>/dev/null; then
  fail "alpha reached t1 on a port other than ssh"
else
  ok "alpha cannot reach t1 on other ports"
fi
hub timeout 5 bash -c "exec 3<>/dev/tcp/$T2/22" && ok "root on the hub is not restricted"

say "the agent holds only the session's keys"
n=$(hub env SSH_AUTH_SOCK="/run/blackthorn-agent/$akey/agent.sock" ssh-add -L | wc -l)
[ "$n" = 1 ] && ok "alpha's agent has 1 key"
if hub test -r /etc/blackthorn/keys/t1 && hub runuser -u "bt-$akey" -- test -r /etc/blackthorn/keys/t1; then
  fail "session user can read the private key file"
else
  ok "session user cannot read private key files"
fi

say "Claude Code was started with the right arguments"
args=$(hub cat "/var/lib/blackthorn/sessions/$akey/fake-claude.args")
echo "   $args"
echo "$args" | grep -q -- '--session-id .* --remote-control alpha' && ok "alpha: --session-id and --remote-control alpha"

say "block cuts a host off now, and lifts itself"
thorn host block t1 --for 70s --reason test
expect_reach 10 alpha t1 FAIL
thorn host ls
n=$(hub env SSH_AUTH_SOCK="/run/blackthorn-agent/$akey/agent.sock" ssh-add -L 2>/dev/null | grep -c ssh- || true)
[ "$n" = 0 ] && ok "key taken out of alpha's agent while blocked"
echo "   waiting for the block to expire (tick runs every minute)..."
expect_reach 150 alpha t1 ok

say "grant and revoke"
thorn grant alpha t2
expect_reach 10 alpha t2 ok
thorn revoke alpha t2
expect_reach 10 alpha t2 FAIL

say "rename keeps the conversation and restarts with the new Remote Control name"
thorn rename alpha gamma
sleep 3
args=$(hub tail -1 "/var/lib/blackthorn/sessions/$akey/fake-claude.args")
echo "   $args"
echo "$args" | grep -q -- '--remote-control gamma' && ok "gamma restarted with the new name"
expect_reach 15 gamma t1 ok

say "reboot: everything comes back by itself"
docker restart "$P-hub" >/dev/null
for _ in $(seq 40); do
  hub systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && break
  sleep 1
done
hub nft list table inet blackthorn >/dev/null && ok "firewall loaded after reboot"
hub sh -c ": > /var/lib/blackthorn/sessions/$akey/reach.log"
expect_reach 30 gamma t1 ok
expect_reach 10 gamma t2 FAIL
expect_reach 10 beta t2 ok

say "remove a session"
bkey=$(hub awk '/^\[sessions.beta\]/{f=1;next} f&&/^key/{gsub(/"/,"",$3);print $3;exit}' /var/lib/blackthorn/state.toml)
thorn rm beta
hub id "bt-$bkey" >/dev/null 2>&1 && fail "user bt-$bkey still exists" || ok "beta's user removed"
hub test -d "/var/lib/blackthorn/archive/beta-$bkey" && ok "beta's files archived"
thorn status

printf '\nall %d checks passed\n' "$pass"
