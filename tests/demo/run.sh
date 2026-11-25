#!/bin/bash
# Screenshots of the web UI for the website, from a demo hub in throwaway
# Docker containers (the same images as the end-to-end test): four
# machines, five spaces with believable chats, a bridge, root given in
# each way, one command waiting for approval.
#
#   tests/demo/run.sh path/to/thorn OUTDIR
#
# Needs Docker (a privileged container, for systemd in the hub) and Python
# with Playwright (pip install playwright && playwright install chromium).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
E2E=$HERE/../e2e
THORN=$1
OUT=$2
P=bt-demo-$$
NET=$P-net
MACHINES="web-01 db-01 nas ci-runner"
SECRET=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP
PASSWORD='demo password, not a real one'

cleanup() {
  for m in hub $MACHINES; do docker rm -f "$P-$m" >/dev/null 2>&1 || true; done
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

say() { printf '== %s\n' "$*"; }
hub() { docker exec "$P-hub" "$@"; }
hubi() { docker exec -i "$P-hub" "$@"; }
thorn() { hub /usr/local/bin/thorn "$@"; }
thorni() { hubi /usr/local/bin/thorn "$@"; }
key_of() { hub awk -v n="[spaces.$1]" '$0==n{f=1;next} f&&/^key/{gsub(/"/,"",$3);print $3;exit}' /var/lib/blackthorn/state.toml; }
ip_of() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$P-$1"; }

say "images and containers"
for i in hub target; do
  docker build -q -t "blackthorn-e2e-$i" -f "$E2E/Dockerfile.$i" "$E2E" >/dev/null
done
docker network create "$NET" >/dev/null
for m in $MACHINES; do
  docker run -d --name "$P-$m" --hostname "$m" --network "$NET" blackthorn-e2e-target >/dev/null
done
docker run -d --name "$P-hub" --hostname blackthorn --network "$NET" \
  --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock blackthorn-e2e-hub >/dev/null
for _ in $(seq 30); do
  hub systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && break
  sleep 1
done
HUB=$(ip_of hub)

say "install"
docker cp "$THORN" "$P-hub:/usr/local/bin/thorn"
hub chmod 755 /usr/local/bin/thorn
docker cp "$E2E/fake-claude" "$P-hub:/root/fake-claude"
docker cp "$E2E/fake-codex" "$P-hub:/usr/local/bin/codex"
hub chmod 755 /usr/local/bin/codex
thorn init --claude-from /root/fake-claude --no-web >/dev/null
hubi sh -c "cat > /etc/blackthorn/config.toml" <<EOF
claude_bin = "/usr/local/bin/claude"

[web]
listen = ["$HUB:7180"]
EOF
thorn apply >/dev/null

say "machines"
for m in $MACHINES; do
  thorn host add "$m" "alice@$(ip_of "$m")" --yes >/dev/null
  thorn host pubkey "$m" | docker exec -i "$P-$m" sh -c \
    'cat >> /home/alice/.ssh/authorized_keys; chown alice /home/alice/.ssh/authorized_keys; chmod 600 /home/alice/.ssh/authorized_keys'
  thorn host setup "$m" --print 2>/dev/null | docker exec -i "$P-$m" sh >/dev/null
  thorn host setup "$m" --verify >/dev/null
done

say "spaces"
thorn new web-01 --name web-claude --root 8h >/dev/null
thorn new db-01 --name db-claude --access read-only --root no >/dev/null
thorn new nas --name nas-claude --root ask >/dev/null
thorn new ci-runner --name ci-codex --agent codex --root no >/dev/null
thorn new web-01 --name web-staging --access user --root no >/dev/null
for s in web-claude db-claude nas-claude web-staging; do
  echo good-code | thorni login "$s" >/dev/null
done
echo "sk-demo-0123456789abcdefghijklmnop" | thorni login ci-codex --api-key >/dev/null
thorn bridge add web-claude db-claude --for 2h >/dev/null

say "chats"
T=$(mktemp -d)
python3 "$HERE/transcripts.py" "$T/chats" > "$T/ids"
while read -r space id; do
  key=$(key_of "$space")
  dir=$(hub sh -c "ls -d /var/lib/blackthorn/spaces/$key/*/ | grep -v '/\.' | head -1")
  proj="/var/lib/blackthorn/spaces/$key/.claude/projects/$(echo "${dir%/}" | sed 's#[^A-Za-z0-9]#-#g')"
  hub runuser -u "bt-$key" -- mkdir -p "$proj"
  docker cp "$T/chats/$space/$id.jsonl" "$P-hub:$proj/$id.jsonl"
  hub chown "bt-$key:bt-$key" "$proj/$id.jsonl"
  hub touch -d "@$(stat -c %Y "$T/chats/$space/$id.jsonl")" "$proj/$id.jsonl"
done < "$T/ids"
thorn _tick >/dev/null 2>&1 || true

say "a root command waiting for approval"
kn=$(key_of nas-claude)
docker exec -d "$P-hub" sh -c "runuser -u bt-$kn -- ssh nas \"sudo -n blackthorn-ask 'sed -i s/vaild/valid/ /etc/samba/smb.conf && systemctl restart smbd'\" >/dev/null 2>&1"
for _ in $(seq 40); do thorn approvals | grep -q smb.conf && break; sleep 1; done

say "web account"
printf '%s\n%s\n' "$PASSWORD" "$(thorn _totp $SECRET)" | thorni web user add alex --totp-secret "$SECRET" >/dev/null
thorn web enable >/dev/null
for _ in $(seq 30); do curl -s -o /dev/null "http://$HUB:7180/login" && break; sleep 1; done
thorn _tick >/dev/null 2>&1 || true

say "screenshots"
web_chat=$(awk '$1 == "web-claude" {print $2; exit}' "$T/ids")
nas_chat=$(awk '$1 == "nas-claude" {print $2; exit}' "$T/ids")
mkdir -p "$OUT"
python3 "$HERE/shoot.py" "http://$HUB:7180" alex "$PASSWORD" "$OUT" "$web_chat" "$nas_chat" \
  -- docker exec "$P-hub" /usr/local/bin/thorn _totp "$SECRET"
ls -la "$OUT"
