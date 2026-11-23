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
hub nft list set inet blackthorn tried4 | grep -q "$T1" && ok "and the hub noted that t1 tried (for notifications)" || fail "tried4 set has t1"

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
web_get / | grep -q '<svg class="map' && ok "map page draws the SVG map" || fail "map page draws the SVG map: $(web_get / | sed 's/<svg class="logo".*<\/svg>//' | head -c 1500)"
web_get /map.svg | grep -q 't1-claude' && ok "map shows t1-claude" || fail "map shows t1-claude"
web_get /map.svg | grep -q 'class="frame kind-machine"' && ok "the map frames what runs on the hub" || fail "map frame"
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
echo "$a1" | grep -q -- '^remote-control --no-create-session-in-dir --spawn same-dir --capacity 8 --remote-control-session-name-prefix t1-claude' && ok "t1-claude: server mode, no empty chat at start" || fail "t1-claude: server mode"
k2=$(key_of t2-claude)
a2=$(hub tail -1 "/var/lib/blackthorn/spaces/$k2/fake-claude.args")
echo "$a2" | grep -q -- '--session-id .* --remote-control --remote-control-session-name-prefix t2-hub' && ok "t2-claude: single mode, its chat named on its own, t2-hub only as a prefix" || fail "t2-claude: single mode: $a2"
hub test -f "/var/lib/blackthorn/spaces/$k1/t1-claude/CLAUDE.md" && ok "instructions in CLAUDE.md, in a folder named for the Claude app" || fail "instructions written to CLAUDE.md"
hub grep -q "\"/var/lib/blackthorn/spaces/$k1/t1-claude\"" "/var/lib/blackthorn/spaces/$k1/.claude.json" && ok "that folder is trusted" || fail "folder trust"
hub runuser -u "bt-$k1" -- ln -s /etc/shadow "/var/lib/blackthorn/spaces/$k1/t1-claude/.CLAUDE.md.thorn-tmp"
thorn apply >/dev/null
hub sh -c 'head -1 /etc/shadow | grep -q "^root:"' && [ "$(hub stat -c %U /etc/shadow)" = root ] && ok "a link planted where root writes CLAUDE.md is not followed" || fail "/etc/shadow was touched through a planted link"

say "bridges are one-way and end at once"
thorn bridge add t1-claude t2-claude --for 1h >/dev/null
expect_reach 15 t1-claude t2 ok
expect_reach 5 t2-claude t1 FAIL
hub grep -q 'temporary bridge' "/var/lib/blackthorn/spaces/$k1/t1-claude/CLAUDE.md" && ok "CLAUDE.md lists the bridged machine" || fail "CLAUDE.md lists the bridged machine"
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

say "chats of a space: list, name, delete"
dir="/var/lib/blackthorn/spaces/$k1/.claude/projects/-var-lib-blackthorn-spaces-$k1-work"
cid=4a1f0c2e-1111-4222-8333-444455556666
hub runuser -u "bt-$k1" -- sh -c "mkdir -p '$dir' && echo '{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"check the disks\"}}' > '$dir/$cid.jsonl'"
hub runuser -u "bt-$k1" -- ln -s /etc/shadow "$dir/5b2e1d3f-1111-4222-8333-444455556666.jsonl"
thorn chat ls t1-claude | grep -q "check the disks" && ok "thorn chat ls names a chat by its first message" || fail "chat ls"
thorn chat ls t1-claude | grep -q "5b2e1d3f" && fail "chat ls followed a planted link" || ok "chat ls skips links the space user planted"
thorn chat rm t1-claude 5b2e1d3f 2>&1 | grep -q "no chat" && ok "and will not delete through one" || fail "rm through a link"
thorn chat rm t1-claude 4a1f 2>&1 | grep -q "running" && ok "a chat in use is not deleted" || fail "chat rm while in use"
hub touch -h -d '2 hours ago' "$dir/$cid.jsonl"
# Claude Code's list of its live processes names the chat: running, however old.
pid=$(hub pgrep -o -u "bt-$k1")
hub runuser -u "bt-$k1" -- sh -c "mkdir -p /var/lib/blackthorn/spaces/$k1/.claude/sessions && echo '{\"pid\":$pid,\"sessionId\":\"$cid\",\"kind\":\"bg\"}' > /var/lib/blackthorn/spaces/$k1/.claude/sessions/$pid.json"
thorn chat ls t1-claude | grep -q "check the disks  (running)" && ok "a chat Claude Code lists as live is running" || fail "live chat in ls: $(thorn chat ls t1-claude)"
hub rm -f "/var/lib/blackthorn/spaces/$k1/.claude/sessions/$pid.json"
web_get /space/t1-claude | grep -q "check the disks" && ok "the space page lists the chat" || fail "chats on the space page"
web_get /space/t1-claude | grep -q "chat-rename" && fail "the space page still offers to rename chats" || ok "and offers no hub-only rename"
hub touch -h -d '2 hours ago' "$dir/$cid.jsonl"
r=$(web_post /space/t1-claude/chat-rm --data-urlencode "csrf=$C" --data-urlencode "id=$cid")
case "$r" in *"ok=chat%20deleted"*) ok "an old chat deleted from the web";; *) fail "chat rm: $r";; esac
hub test -e "$dir/$cid.jsonl" && fail "the transcript is still there" || ok "its transcript is gone"
hub test -e /etc/shadow && ok "and nothing else was touched" || fail "/etc/shadow is gone"
hub rm -f "$dir/5b2e1d3f-1111-4222-8333-444455556666.jsonl"

say "new chats: in a one-conversation space, and not with Remote Control"
thorn chat new t1-claude | grep -q "window of its own" && ok "with Remote Control, a new chat runs in a window of its own" || fail "chat new in server mode"
sleep 2
hub tmux -S "/run/blackthorn/$k1/tmux.sock" list-windows -F '#{window_name}' | grep -q '^chat-' && ok "next to the Remote Control server" || fail "chat window"
hub grep -q -- "^--session-id [0-9a-f-]* --remote-control --remote-control-session-name-prefix t1-claude" "/var/lib/blackthorn/spaces/$k1/fake-claude.args" && ok "on Remote Control too, so it shows in the Claude app (under its own name)" || fail "chat window args: $(hub tail -3 "/var/lib/blackthorn/spaces/$k1/fake-claude.args")"
old=$(hub tail -1 "/var/lib/blackthorn/spaces/$k2/fake-claude.args" | grep -o -- '--session-id [0-9a-f-]*' | cut -d' ' -f2)
[ -n "$old" ] || old=$(hub tail -1 "/var/lib/blackthorn/spaces/$k2/fake-claude.args" | grep -o -- '--resume [0-9a-f-]*' | cut -d' ' -f2)
dir2="/var/lib/blackthorn/spaces/$k2/.claude/projects/-var-lib-blackthorn-spaces-$k2-work"
hub runuser -u "bt-$k2" -- sh -c "mkdir -p '$dir2' && echo '{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"the first chat\"}}' > '$dir2/$old.jsonl'"
thorn chat new t2-claude | grep -q "new chat" && ok "thorn chat new" || fail "thorn chat new"
thorn chat new t1-claude --name "web check" >/dev/null
sleep 2
hub grep -Eq -- "^--session-id [0-9a-f-]+ --name [0-9a-f]{8} web check --remote-control --remote-control-session-name-prefix t1-claude" "/var/lib/blackthorn/spaces/$k1/fake-claude.args" && ok "a named chat window: Claude gets the id's start and the name" || fail "named chat window: $(hub tail -2 "/var/lib/blackthorn/spaces/$k1/fake-claude.args")"
wid=$(hub grep -- " web check --remote-control" "/var/lib/blackthorn/spaces/$k1/fake-claude.args" | tail -1 | cut -d' ' -f2)
hub grep -q -- "--name ${wid%%-*} web check" "/var/lib/blackthorn/spaces/$k1/fake-claude.args" && ok "the start of its own id" || fail "id in the name"
hub runuser -u "bt-$k1" -- sh -c "echo '{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"web\"}}' > '$dir/$wid.jsonl'"
thorn chat ls t1-claude | grep -q "running, started from the hub" && ok "a chat started from the hub is listed as running" || fail "window chat in ls: $(thorn chat ls t1-claude)"
web_get /space/t1-claude | grep -q "/space/t1-claude/chat-stop" && ok "the space page offers to stop it" || fail "no Stop on the space page"
thorn chat stop t1-claude "${wid%%-*}" | grep -q "stopped chat" && ok "thorn chat stop" || fail "chat stop"
hub tmux -S "/run/blackthorn/$k1/tmux.sock" list-windows -F '#{window_name}' | grep -q "^chat-${wid%%-*}" && fail "its window is still there" || ok "its window is closed"
thorn chat open t1-claude "${wid%%-*}" >/dev/null && ok "and continued at once" || fail "continue after stop"
sleep 2
thorn chat rm t1-claude "${wid%%-*}" | grep -q "deleted chat" && ok "a running chat from the hub is stopped and deleted" || fail "rm of a window chat"
hub tmux -S "/run/blackthorn/$k1/tmux.sock" list-windows -F '#{window_name}' | grep -q "^chat-${wid%%-*}" && fail "its window survived the delete" || ok "its window closed with it"
hub test -e "$dir/$wid.jsonl" && fail "the window chat's transcript is still there" || ok "and its transcript is gone"

say "a chat on the web: read along, unlock, type, answer, files"
r=$(web_post /space/t1-claude/chat-new --data-urlencode "csrf=$C" --data-urlencode "title=web chat")
case "$r" in *"/space/t1-claude/chat/"*"?ok=new%20chat"*) ok "a new chat opens its own page";; *) fail "chat-new redirect: $r";; esac
nid=$(echo "$r" | sed 's#.*/chat/\([0-9a-f-]*\).*#\1#')
sleep 2
web_get "/space/t1-claude/chat/$nid" | grep -q "Type into chats from this browser" && ok "typing needs an unlock first" || fail "no unlock form: $(web_get "/space/t1-claude/chat/$nid" | head -c 800)"
chat_post() { local a=$1; shift; admin curl -s -b /tmp/jar -c /tmp/jar --data-urlencode "csrf=$C" --data-urlencode "js=1" "$@" "http://$HUB:7180/space/t1-claude/chat/$nid/$a"; }
chat_post send --data-urlencode "text=hi" | grep -q "may not type" && ok "a message is refused before the unlock" || fail "send without unlock"
r=$(web_post "/space/t1-claude/chat/$nid/unlock" --data-urlencode "csrf=$C" --data-urlencode "password=$PASSWORD" --data-urlencode "code=000000")
case "$r" in *"err="*) ok "a wrong code does not unlock";; *) fail "unlock with a wrong code: $r";; esac
r=$(web_post "/space/t1-claude/chat/$nid/unlock" --data-urlencode "csrf=$C" --data-urlencode "password=$PASSWORD" --data-urlencode "code=$(fresh_code $WEB_SECRET)")
case "$r" in *"ok=unlocked"*) ok "password and code unlock this browser";; *) fail "unlock: $r";; esac
admin grep -q bt_chat /tmp/jar && ok "kept in a cookie of its own" || fail "no chat cookie"
web_get "/space/t1-claude/chat/$nid" | grep -q 'id="composer"' && ok "then the page offers a message box" || fail "no composer"
chat_post send --data-urlencode "text=check the \"disks\" & more" | grep -q '"ok":"sent"' && ok "a message sent from the web" || fail "send: $(chat_post send --data-urlencode 'text=x')"
sleep 2
feed=$(web_get "/space/t1-claude/chat/$nid/feed")
echo "$feed" | grep -q 'check the &quot;disks&quot; &amp; more' && ok "it reached the chat, as typed" || fail "feed: $feed"
echo "$feed" | grep -q '<strong>heard</strong>' && ok "and Claude's answer reads as Markdown" || fail "answer in feed: $feed"
thorn chat send t1-claude "${nid%%-*}" ask | grep -q sent && ok "thorn chat send" || fail "thorn chat send"
sleep 2
feed=$(web_get "/space/t1-claude/chat/$nid/feed")
echo "$feed" | grep -q '"state":"asking"' && ok "a question is seen" || fail "asking: $feed"
echo "$feed" | grep -q 'Do you want to proceed?' && ok "with its text" || fail "question text: $feed"
chat_post send --data-urlencode "text=yes" | grep -q "answer it first" && ok "nothing is typed while Claude asks" || fail "send while asking"
chat_post key --data-urlencode "key=7" | grep -q "not asking that" && ok "a choice it does not offer is refused" || fail "key 7"
chat_post key --data-urlencode "key=C-c" | grep -q "does not press" && ok "and so is any other key" || fail "key C-c"
chat_post key --data-urlencode "key=1" | grep -q '"ok":"pressed"' && ok "a choice pressed from the web" || fail "key 1"
sleep 2
web_get "/space/t1-claude/chat/$nid/feed" | grep -q '"state":"idle"' && ok "and the question is gone" || fail "after the answer: $(web_get "/space/t1-claude/chat/$nid/feed")"
web_get "/space/t1-claude/chat/$nid/feed" | grep -q 'answered 1' && ok "Claude got that answer" || fail "answer not given"
r=$(chat_post chat-upload --data-urlencode "filename=../../evil name.txt" --data-urlencode "data=$(printf 'hello file' | base64)")
up=$(echo "$r" | sed -n 's/.*"data":"\([^"]*\)".*/\1/p')
case "$up" in .uploads/*-evil-name.txt) ok "a file saved for the chat, its name made safe";; *) fail "upload: $r";; esac
w="/var/lib/blackthorn/spaces/$k1/t1-claude"
[ "$(hub cat "$w/$up")" = "hello file" ] && ok "in the chat's folder" || fail "uploaded file: $(hub ls -la "$w/.uploads")"
[ "$(hub stat -c '%U %a' "$w/$up")" = "bt-$k1 600" ] && ok "owned by the space, private" || fail "upload owner: $(hub stat -c '%U %a' "$w/$up")"
web_get "/space/t1-claude/chat/$nid" | grep -q 'data-cmd="/compact"' && ok "slash commands offered" || fail "no slash commands"
web_get /account | grep -q "may type into chats" && ok "the unlock is listed with the logins" || fail "unlock not on the account page"
web_get "/space/t1-claude/chat/0000aaaa/feed" | grep -q '"error"' && ok "an unknown chat is an error" || fail "unknown chat feed"
thorn chat stop t1-claude "${nid%%-*}" >/dev/null
sleep 3
a=$(hub tail -1 "/var/lib/blackthorn/spaces/$k2/fake-claude.args")
case "$a" in "--session-id $old"*) fail "still the old chat: $a";; --session-id*) ok "restarted into a new conversation";; *) fail "chat new: $a";; esac
r=$(web_post /space/t2-claude/chat-open --data-urlencode "csrf=$C" --data-urlencode "id=$old")
case "$r" in *"ok=back%20in%20that%20chat"*) ok "continued the earlier chat from the web";; *) fail "chat open: $r";; esac
sleep 3
hub tail -1 "/var/lib/blackthorn/spaces/$k2/fake-claude.args" | grep -q -- "^--resume $old" && ok "resumed it" || fail "resume: $(hub tail -1 "/var/lib/blackthorn/spaces/$k2/fake-claude.args")"
expect_reach 20 t2-claude t2 ok

say "renames ask for a code: machine and account"
r=$(web_post /host/t2/rename --data-urlencode "csrf=$C" --data-urlencode "new=t2b" --data-urlencode "code=$(fresh_code $WEB_SECRET)")
case "$r" in *"/host/t2b?ok="*) ok "machine renamed from the web";; *) fail "host rename: $r";; esac
hub grep -q "^Host t2b" "/var/lib/blackthorn/spaces/$k2/.ssh/config" && ok "its space reaches it by the new name" || fail "ssh config after host rename"
hub test -f /etc/blackthorn/keys/t2b && ok "its key moved along" || fail "key after host rename"
thorn host rename t2b t2 | grep -q "is now t2" && ok "thorn host rename" || fail "thorn host rename"
expect_reach 20 t2-claude t2 ok
r=$(web_post /account/rename --data-urlencode "csrf=$C" --data-urlencode "new=frakw-2" --data-urlencode "code=$(fresh_code $WEB_SECRET)")
case "$r" in *"ok=you%20are%20now%20frakw-2"*) ok "account renamed from the web";; *) fail "account rename: $r";; esac
web_get /account | grep -q "Account frakw-2" && ok "and still logged in under the new name" || fail "session after account rename"
thorn web user rename frakw-2 frakw | grep -q "is now frakw" && ok "thorn web user rename" || fail "thorn web user rename"
admin rm -f /tmp/jar
r=$(web_post /login --data-urlencode "user=frakw" --data-urlencode "password=$PASSWORD" --data-urlencode "code=$(fresh_code $WEB_SECRET)")
[ "$r" = "http://$HUB:7180/" ] && ok "log in again under the old name" || fail "login after rename: $r"
C=$(csrf)

say "logins: listed, kept across restarts, ended from the account page"
exp=$(admin awk '$6 == "bt_session" { print $5 }' /tmp/jar)
[ "${exp:-0}" -gt $(( $(date +%s) + 20 * 3600 )) ] && ok "the login cookie lasts a day" || fail "cookie expiry: $exp"
tok=$(admin awk '$6 == "bt_session" { print $7 }' /tmp/jar)
hub stat -c %a /var/lib/blackthorn/web-sessions.json | grep -q 600 && ok "logins are kept root-only" || fail "web-sessions.json mode"
hub grep -q "$tok" /var/lib/blackthorn/web-sessions.json && fail "the file holds a token" || ok "without their tokens"
web_get /account | grep -q "this browser" && ok "the account page lists this login" || fail "logins card: $(web_get /account | grep -o 'id="sessions".*' | head -c 600)"
admin rm -f /tmp/jar2
admin curl -s -o /dev/null -c /tmp/jar2 -A "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1" --data-urlencode "user=frakw" --data-urlencode "password=$PASSWORD" --data-urlencode "code=$(fresh_code $WEB_SECRET)" "http://$HUB:7180/login"
web_get /account | grep -q "Safari 18 on iOS" && ok "and another, by its browser and system" || fail "phone login not listed"
hub systemctl restart blackthorn-api
sleep 1
web_get /account | grep -q "Account frakw" && ok "logins survive a restart of the API" || fail "logged out by a restart"
r=$(web_post /account/session-end-others --data-urlencode "csrf=$C")
case "$r" in *"ok=every%20other"*) ok "every other login ended";; *) fail "end others: $r";; esac
[ "$(admin curl -s -o /dev/null -w '%{redirect_url}' -b /tmp/jar2 "http://$HUB:7180/")" = "http://$HUB:7180/login" ] && ok "that browser is logged out" || fail "other login still works"
web_get /account | grep -q "Account frakw" && ok "this one is not" || fail "ended our own login"
thorn config set web.session_hours 0 2>&1 | grep -q "1 to 720" && ok "a login lifetime out of range is refused" || fail "session_hours 0"
thorn config set web.session_hours 48 >/dev/null && thorn config show | grep -q "web.session_hours.*48" && ok "the login lifetime is a setting" || fail "session_hours: $(thorn config show | grep session)"
thorn config set web.session_hours 24 >/dev/null

say "notifications to an ntfy server"
docker exec -d "$P-admin" sh -c "while true; do printf 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' | nc -N -l 8099 >> /tmp/ntfy.req; done"
sleep 1
thorn notify set "http://$ADMIN:8099/bt-e2e-topic" | grep -q "notifications go to" && ok "thorn notify set" || fail "notify set"
hub stat -c %a /etc/blackthorn/notify.toml | grep -q 600 && ok "the topic is kept root-only" || fail "notify.toml mode"
web_get /settings | grep -q "bt-e2e-topic" && ok "the settings page shows where they go" || fail "notify card"
r=$(web_post /notify/test --data-urlencode "csrf=$C")
case "$r" in *"ok=test%20sent"*) ok "a test sent from the web";; *) fail "notify test: $r";; esac
got=""
for _ in $(seq 10); do admin grep -q "Notifications work." /tmp/ntfy.req && { got=1; break; }; sleep 0.5; done
[ -n "$got" ] && ok "the ntfy server got it" || fail "ntfy request: $(admin cat /tmp/ntfy.req)"
tcp_open "$P-t1" "$HUB" 22 || true
got=""
for _ in $(seq 75); do admin grep -q "machine t1 ($T1) tried to connect to the hub" /tmp/ntfy.req && { got=1; break; }; sleep 1; done
[ -n "$got" ] && ok "a managed machine trying to connect back is reported" || fail "connect-back notification: $(admin cat /tmp/ntfy.req)"
thorn notify off | grep -q off && ok "thorn notify off" || fail "notify off"

say "Remote Control off and on again"
thorn remote t1-claude off | grep -q "Remote Control off" && ok "thorn remote off" || fail "thorn remote off"
sleep 3
a=$(hub tail -1 "/var/lib/blackthorn/spaces/$k1/fake-claude.args")
case "$a" in --session-id*|--resume*) case "$a" in *remote-control*) fail "still Remote Control: $a";; *) ok "off: one local conversation, no Remote Control";; esac;; *) fail "remote off: $a";; esac
web_get /space/t1-claude | grep -q "local only" && ok "the space page says local only" || fail "local only badge"
r=$(web_post /space/t1-claude/remote --data-urlencode "csrf=$C" --data-urlencode "on=on")
case "$r" in *"ok=Remote%20Control%20on"*) ok "turned on again from the web";; *) fail "remote on: $r";; esac
sleep 3
hub tail -1 "/var/lib/blackthorn/spaces/$k1/fake-claude.args" | grep -q -- '^remote-control --no-create-session-in-dir' && ok "back in server mode" || fail "server mode again"
expect_reach 20 t1-claude t1 ok

say "account: password and authenticator from the web"
web_get /account | grep -q "Change password" && ok "the account page" || fail "account page"
NEWPW='a different horse battery'
code=$(fresh_code $WEB_SECRET)
r=$(web_post /account/password --data-urlencode "csrf=$C" --data-urlencode "current=$PASSWORD" --data-urlencode "new=$NEWPW" --data-urlencode "again=$NEWPW" --data-urlencode "code=$code")
case "$r" in *"ok=password%20changed"*) ok "password changed from the web"; PASSWORD=$NEWPW;; *) fail "password change: $r";; esac
code=$(fresh_code $WEB_SECRET)
page=$(admin curl -s -b /tmp/jar -c /tmp/jar --data-urlencode "csrf=$C" --data-urlencode "code=$code" "http://$HUB:7180/account/totp-begin")
NEW=$(echo "$page" | grep -o 'id="totpkey">[A-Z2-7]*' | cut -d'>' -f2)
echo "$page" | grep -q 'class="qr"><svg' && [ -n "$NEW" ] && ok "a new authenticator, as a QR code and a key" || fail "totp begin: $(echo "$page" | head -c 300)"
page=$(admin curl -s -b /tmp/jar -c /tmp/jar --data-urlencode "csrf=$C" --data-urlencode "code=000000" "http://$HUB:7180/account/totp-finish")
echo "$page" | grep -q "does not match" && ok "a wrong code does not switch it" || fail "totp finish with a wrong code"
page=$(admin curl -s -b /tmp/jar -c /tmp/jar --data-urlencode "csrf=$C" --data-urlencode "code=$(admin oathtool --totp -b "$NEW")" "http://$HUB:7180/account/totp-finish")
echo "$page" | grep -q "New authenticator confirmed" && ok "switched once a code from the new one matched" || fail "totp finish"
WEB_SECRET=$NEW
admin rm -f /tmp/jar2
r=$(admin curl -s -o /dev/null -w "%{redirect_url}" -c /tmp/jar2 --data-urlencode "user=frakw" --data-urlencode "password=$PASSWORD" --data-urlencode "code=$(fresh_code $WEB_SECRET)" "http://$HUB:7180/login")
[ "$r" = "http://$HUB:7180/" ] && ok "log in with the new password and authenticator" || fail "login after changes: $r"
web_get /settings | grep -q 'id="update"' && ok "the settings page has the update card" || fail "update card"

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
hub tail -1 "/var/lib/blackthorn/spaces/$k1/fake-claude.args" | grep -q -- '--remote-control-session-name-prefix t1-main' && ok "t1-main restarted with the new name" || fail "t1-main restarted with the new name"
hub test -f "/var/lib/blackthorn/spaces/$k1/t1-main/CLAUDE.md" && ! hub test -e "/var/lib/blackthorn/spaces/$k1/t1-claude" && ok "its folder moved along (the Claude app lists it by that name)" || fail "folder after rename"
thorn rename t1-main t1-main --rc-name ops-box >/dev/null
sleep 3
hub test -d "/var/lib/blackthorn/spaces/$k1/ops-box" && hub tail -1 "/var/lib/blackthorn/spaces/$k1/fake-claude.args" | grep -q -- '--remote-control-session-name-prefix ops-box' && ok "a Remote Control name of its own" || fail "rc-name rename"
expect_reach 20 t1-main t1 ok
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

say "HTTPS with your own certificate"
hub sh -c 'cd /root && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=hub.test -addext subjectAltName=DNS:hub.test -keyout key.pem -out cert.pem 2>/dev/null'
thorn web https --cert /root/cert.pem --key /root/key.pem --name hub.test | grep -q "https://hub.test:7180/" && ok "thorn web https" || fail "web https"
for _ in $(seq 20); do admin curl -sk --resolve "hub.test:7180:$HUB" -o /dev/null "https://hub.test:7180/login" && break; sleep 0.5; done
admin curl -sk --resolve "hub.test:7180:$HUB" "https://hub.test:7180/login" | grep -q "Log in with a passkey" && ok "the web UI speaks HTTPS and offers passkeys" || fail "https login page"
r=$(admin curl -sk --resolve "hub.test:7180:$HUB" -D - -o /dev/null --data-urlencode "user=frakw" --data-urlencode "password=$PASSWORD" --data-urlencode "code=$(fresh_code $WEB_SECRET)" "https://hub.test:7180/login")
echo "$r" | grep -qi "set-cookie: bt_session=.*; Secure" && ok "the session cookie is Secure" || fail "secure cookie: $r"
r=$(admin curl -sk --resolve "hub.test:7180:$HUB" --data-urlencode "purpose=login" "https://hub.test:7180/passkey/begin")
echo "$r" | grep -q '"rp_id":"hub.test"' && ok "a passkey challenge for hub.test" || fail "passkey begin: $r"
admin curl -s -m 5 "http://$HUB:7180/login" >/dev/null 2>&1 && fail "plain HTTP still answers" || ok "no plain HTTP any more"
thorn web https --off | grep -q "plain HTTP" && ok "thorn web https --off" || fail "https off"
for _ in $(seq 20); do admin curl -s -o /dev/null "http://$HUB:7180/login" && break; sleep 0.5; done

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

say "a read-only login on t1; admin spaces run for a time"
out=$(thorn host readonly t1 --print 2>/dev/null | docker exec -i "$P-t1" sh 2>&1)
echo "$out" | grep -q "bt: done" && ok "the printed setup script ran on t1" || fail "setup script: $out"
thorn host readonly t1 --verify | grep -q "has a read-only login: blackthorn" && ok "thorn host readonly --verify" || fail "readonly verify"
thorn host ls | grep -q "blackthorn" && ok "host ls shows the read-only login" || fail "host ls"
docker exec "$P-t1" grep -q 'command="/usr/local/libexec/blackthorn-ssh"' /home/alice/.ssh/authorized_keys && ok "the admin key logs its commands on t1 too" || fail "admin key line"
[ "$(docker exec "$P-t1" stat -c %U /home/blackthorn/.ssh/authorized_keys)" = root ] && ok "the read-only user cannot change its own key line" || fail "ro key file owner"
[ "$(hub systemctl is-enabled "blackthorn-space@$k1.service")" = disabled ] && ok "t1-main (admin) no longer starts at boot" || fail "admin space still enabled"
thorn new t1 --name t1-ro | grep -q "read-only" && ok "new spaces on t1 are read-only" || fail "new read-only space"
echo good-code | thorni login t1-ro >/dev/null
kr=$(key_of t1-ro)
hub grep -q "User blackthorn" "/var/lib/blackthorn/spaces/$kr/.ssh/config" && ok "t1-ro logs in as blackthorn" || fail "ro ssh config"
hub grep -q "read-only" "/var/lib/blackthorn/spaces/$kr/t1-ro/CLAUDE.md" && ok "and its instructions say so" || fail "ro CLAUDE.md"
expect_reach 30 t1-ro t1 ok
want=$(hub cut -d' ' -f2 /etc/blackthorn/keys/t1.ro.pub)
got=$(hub env SSH_AUTH_SOCK="/run/blackthorn-agent/$kr/agent.sock" ssh-add -L | cut -d' ' -f2)
[ "$got" = "$want" ] && ok "its agent holds only the read-only key" || fail "ro agent keys: $got"
[ "$(hub runuser -u "bt-$kr" -- ssh t1 id -un 2>/dev/null)" = blackthorn ] && ok "ssh t1 is the read-only user" || fail "ro login"
if hub runuser -u "bt-$kr" -- ssh t1 'touch /root/x' 2>/dev/null; then fail "the read-only space wrote as root"; else ok "it cannot write where root can"; fi
thorn stop t1-main >/dev/null
thorn start t1-main --for 1m | grep -q "as admin until" && ok "an admin space starts for a time" || fail "start --for"
thorn new t1 --access admin --name t1-adm2 >/dev/null
echo good-code | thorni login t1-adm2 | grep -q "start it when you need it" && ok "a new admin space waits to be started" || fail "admin login"
thorn start t1-adm2 --for 1h 2>&1 | grep -q "already working on t1 as admin" && ok "one admin space per machine at a time" || fail "second admin space started"
# The reboot ended the web session: log in again.
web_post /login --data-urlencode "user=frakw" --data-urlencode "password=$PASSWORD" --data-urlencode "code=$(fresh_code $WEB_SECRET)" >/dev/null
C=$(csrf)
r=$(web_post /space/t1-adm2/start --data-urlencode "csrf=$C")
case "$r" in *"limited"*) ok "the web's plain Start will not start an admin space";; *) fail "web start: $r";; esac
thorn access t1-adm2 readonly | grep -q "now read-only" && ok "thorn access" || fail "access change"
thorn rm t1-adm2 --purge >/dev/null
web_get /host/t1 | grep -q "Read-only login" && ok "the machine page shows the read-only login" || fail "host page"
web_get /map.svg | grep -q 'class="wire ro"' && ok "the map draws read-only logins" || fail "map ro wire"

say "what a space did: its commands, recorded by root"
d="/var/lib/blackthorn/spaces/$kr/.claude/projects/-var-lib-blackthorn-spaces-$kr-t1-ro"
cid=6c3d2e1f-1111-4222-8333-444455556666
hubi runuser -u "bt-$kr" -- sh -c "mkdir -p '$d' && cat > '$d/$cid.jsonl'" <<'JSONL'
{"type":"user","message":{"role":"user","content":"how full is the disk?"}}
{"type":"assistant","timestamp":"2026-11-20T08:00:05.120Z","message":{"content":[{"type":"tool_use","id":"x1","name":"Bash","input":{"command":"ssh t1 'df -h /'"}}]}}
JSONL
thorn _tick >/dev/null 2>&1
thorn log t1-ro | grep -q "ssh t1 'df -h /'" && ok "thorn log lists the command" || fail "thorn log: $(thorn log t1-ro)"
[ "$(hub stat -c %U "/var/log/blackthorn/$kr.log")" = root ] && ok "kept in a root-owned log" || fail "log owner"
web_get /space/t1-ro | grep -q "df -h /" && ok "the space page shows it under Activity" || fail "activity card"
hubi runuser -u "bt-$kr" -- sh -c "echo '{}' > '$d/$cid.jsonl'"
thorn _tick >/dev/null 2>&1
thorn log t1-ro | grep -q "NOTE: transcript got shorter" && ok "a transcript that shrinks is noted" || fail "shrink note"
thorn log t1-ro | grep -q "df -h" && ok "and what it held stays in the log" || fail "log kept"

say "a new chat with a name"
thorn chat new t2-claude --name "disk check" >/dev/null
sleep 3
hub tail -1 "/var/lib/blackthorn/spaces/$k2/fake-claude.args" | grep -Eq -- "--name [0-9a-f]{8} disk check" && ok "the new chat starts with the id's start and its name" || fail "chat name: $(hub tail -1 "/var/lib/blackthorn/spaces/$k2/fake-claude.args")"

echo "   waiting for t1-main's admin time to run out (tick runs every minute)..."
for _ in $(seq 75); do [ "$(hub systemctl is-active "blackthorn-space@$k1.service")" != active ] && break; sleep 2; done
[ "$(hub systemctl is-active "blackthorn-space@$k1.service")" != active ] && ok "the admin space stopped by itself when its time was up" || fail "admin time limit"

say "remove a space"
thorn rm t2-claude >/dev/null
hub id "bt-$k2" >/dev/null 2>&1 && fail "user bt-$k2 still exists" || ok "t2-claude's user removed"
hub test -d "/var/lib/blackthorn/archive/t2-claude-$k2" && ok "t2-claude's files archived" || fail "t2-claude's files archived"

say "tailscale on the hub"
if hub sh -c 'command -v tailscale' >/dev/null; then
  ok "tailscale is installed here; skipping the not-installed checks"
else
  thorn tailscale status | grep -q "not installed" && ok "thorn tailscale status: not installed" || fail "tailscale status: $(thorn tailscale status 2>&1)"
  thorn tailscale web on 2>&1 | grep -q "not installed" && ok "its web interface needs it installed" || fail "tailscale web without tailscale"
  web_get /settings | grep -q 'action="/tailscale/install"' && ok "the Settings page offers to install it" || fail "no install on the Settings page"
  r=$(web_post /tailscale/install --data-urlencode "csrf=$C" --data-urlencode "code=000000")
  case "$r" in *"fresh%20code"*) ok "installing it needs a fresh code";; *) fail "tailscale install without a code: $r";; esac
fi

say "export and import: everything in one file, the same version only"
kr=$(key_of t1-ro)
hub runuser -u "bt-$kr" -- sh -c "echo mine > /var/lib/blackthorn/spaces/$kr/marker"
was=$(hub systemctl is-active "blackthorn-space@$kr.service" || true)
thorn export /root/bt.tar.gz | grep -q "exported blackthorn" && ok "thorn export" || fail "thorn export"
[ "$(hub stat -c %a:%U /root/bt.tar.gz)" = 600:root ] && ok "the file is root's alone" || fail "export mode: $(hub stat -c %a:%U /root/bt.tar.gz)"
thorn export /root/bt.tar.gz >/dev/null 2>&1 && fail "export overwrote a file" || ok "an existing file is not overwritten"
thorn import /root/bt.tar.gz 2>&1 | grep -q -- "--replace" && ok "a hub with spaces is not replaced without --replace" || fail "import without --replace"
hub sh -c 'rm -rf /tmp/v && mkdir /tmp/v && cd /tmp/v && tar -xzf /root/bt.tar.gz && sed -i "s/^version = .*/version = \"0.0.1\"/" blackthorn-export.toml && tar -czf /root/old.tar.gz blackthorn-export.toml etc var'
thorn import /root/old.tar.gz --replace 2>&1 | grep -q "from blackthorn 0.0.1" && ok "an export from another version is refused" || fail "version check"
thorn rm t1-main --purge >/dev/null
hub rm -f "/var/lib/blackthorn/spaces/$kr/marker"
out=$(thorn import /root/bt.tar.gz --replace 2>&1) || fail "import: $out"
echo "$out" | grep -q "imported blackthorn" && ok "thorn import --replace" || fail "import: $out"
thorn ls | grep -q "^t1-main " && ok "a space removed after the export is back" || fail "t1-main after import: $(thorn ls)"
[ "$(hub cat "/var/lib/blackthorn/spaces/$kr/marker")" = mine ] && ok "with the spaces' files" || fail "marker after import"
[ "$(hub stat -c %U "/var/lib/blackthorn/spaces/$kr/marker")" = "bt-$kr" ] && ok "owned by the space's user again" || fail "owner after import: $(hub stat -c %U "/var/lib/blackthorn/spaces/$kr/marker")"
[ "$(hub stat -c %U "/var/lib/blackthorn/spaces/$kr/.ssh")" = root ] && ok "and its ~/.ssh still root's" || fail ".ssh owner after import"
[ "$(hub systemctl is-active "blackthorn-space@$kr.service" || true)" = "$was" ] && ok "t1-ro is $was again" || fail "t1-ro state after import"
hub sh -c 'ls -d /var/lib/blackthorn.before-import-*' >/dev/null && ok "what was here before is kept aside" || fail "nothing set aside"
[ "$(hub stat -c %a "$(hub sh -c 'ls -d /var/lib/blackthorn.before-import-* | head -1')")" = 700 ] && ok "readable by root only" || fail "aside mode"
hub nft list ruleset | grep -q "bt-$kr\|$(hub id -u "bt-$kr")" && ok "the firewall knows the space's new user" || fail "firewall after import"

say "an export with a password"
printf 'short\n' | thorni export /root/x.bt --password 2>&1 | grep -q "at least 8" && ok "a short password is refused" || fail "short export password"
printf 'pw-secret-1\n' | thorni export /root/sealed.bt --password | grep -q "with a password" && ok "thorn export --password" || fail "sealed export"
[ "$(hub head -c 19 /root/sealed.bt)" = blackthorn-sealed-1 ] && ok "the file is sealed" || fail "sealed header"
hub sh -c 'gzip -t < /root/sealed.bt' 2>/dev/null && fail "the sealed file reads as plain gzip" || ok "nothing in it reads without the password"
[ "$(hub stat -c %a:%U /root/sealed.bt)" = 600:root ] && ok "and it is root's alone too" || fail "sealed export mode"
printf 'wrong-password\n' | thorni import /root/sealed.bt --replace 2>&1 | grep -q "wrong password" && ok "a wrong password is refused, before anything changes" || fail "wrong password import"
thorn ls | grep -q "^t1-main " && ok "the spaces are untouched" || fail "spaces after a refused import"
out=$(printf 'pw-secret-1\n' | thorni import /root/sealed.bt --replace 2>&1) || fail "sealed import: $out"
echo "$out" | grep -q "imported blackthorn" && ok "imported with the password" || fail "sealed import: $out"
[ "$(hub cat "/var/lib/blackthorn/spaces/$kr/marker")" = mine ] && ok "with the spaces' files" || fail "marker after sealed import"
thorn status

pass_all=1
printf '\nall %d checks passed\n' "$pass"
