#!/usr/bin/env python3
"""Writes believable Claude Code transcripts for the screenshot demo.

    transcripts.py OUTDIR

Each chat becomes OUTDIR/<space>/<chat id>.jsonl, timed in the last few
hours, in the shape Claude Code writes them (user and assistant messages,
Bash calls and their results, an AI title).
"""
import json
import os
import sys
import time
import uuid

MODEL = "claude-opus-5-5"


def chat(space, title, minutes_ago, turns):
    """turns: ("user", text) | ("say", text) | ("bash", command, output)."""
    t = time.time() - minutes_ago * 60
    sid = str(uuid.uuid4())
    lines = []

    def stamp():
        nonlocal t
        t += 7
        return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(t))

    for turn in turns:
        kind = turn[0]
        if kind == "user":
            lines.append({"type": "user", "sessionId": sid, "timestamp": stamp(),
                          "message": {"role": "user", "content": turn[1]}})
        elif kind == "say":
            lines.append({"type": "assistant", "sessionId": sid, "timestamp": stamp(),
                          "message": {"role": "assistant", "model": MODEL,
                                      "content": [{"type": "text", "text": turn[1]}]}})
        elif kind == "bash":
            tid = "toolu_" + uuid.uuid4().hex[:20]
            lines.append({"type": "assistant", "sessionId": sid, "timestamp": stamp(),
                          "message": {"role": "assistant", "model": MODEL,
                                      "content": [{"type": "tool_use", "id": tid, "name": "Bash",
                                                   "input": {"command": turn[1],
                                                             "description": turn[3] if len(turn) > 3 else ""}}]}})
            if turn[2] is not None:  # None: still running
                lines.append({"type": "user", "sessionId": sid, "timestamp": stamp(),
                              "message": {"role": "user",
                                          "content": [{"type": "tool_result", "tool_use_id": tid,
                                                       "content": turn[2]}]}})
    lines.append({"type": "ai-title", "sessionId": sid, "aiTitle": title})
    return space, sid, lines, t


CHATS = [
    chat("web-claude", "Fix 502s on /api after this morning's deploy", 95, [
        ("user", "Since this morning's deploy about 1 in 20 requests to /api get a 502. Can you find out why?"),
        ("say", "I'll start with nginx's error log on web-01, then look at the API service behind it."),
        ("bash", "ssh web-01 'sudo tail -n 4 /var/log/nginx/error.log'",
         "2026/11/25 07:41:12 [error] 812#812: *48211 upstream prematurely closed connection while reading response header from upstream, client: 10.0.4.17, server: shop.example.com, request: \"POST /api/cart HTTP/2.0\", upstream: \"http://127.0.0.1:8081/api/cart\"\n"
         "2026/11/25 07:43:55 [error] 812#812: *48650 upstream prematurely closed connection while reading response header from upstream, client: 10.0.9.3, server: shop.example.com, request: \"GET /api/orders?page=2 HTTP/2.0\", upstream: \"http://127.0.0.1:8081/api/orders?page=2\"\n"
         "2026/11/25 07:47:02 [error] 812#812: *49107 upstream prematurely closed connection while reading response header from upstream, client: 10.0.4.17, server: shop.example.com, request: \"POST /api/checkout HTTP/2.0\", upstream: \"http://127.0.0.1:8081/api/checkout\"",
         "Recent nginx errors"),
        ("say", "The API itself is closing connections mid-request. Checking whether its workers are being killed:"),
        ("bash", "ssh web-01 'journalctl -u shop-api --since today | grep -iE \"oom|killed\" | tail -3'",
         "Nov 25 07:41:12 web-01 systemd[1]: shop-api.service: A process of this unit has been killed by the OOM killer.\n"
         "Nov 25 07:43:55 web-01 systemd[1]: shop-api.service: A process of this unit has been killed by the OOM killer.\n"
         "Nov 25 07:47:02 web-01 systemd[1]: shop-api.service: A process of this unit has been killed by the OOM killer.",
         "Look for OOM kills"),
        ("bash", "ssh web-01 'systemctl show shop-api -p MemoryMax -p MemoryCurrent; grep -o \"\\-\\-workers [0-9]*\" /etc/systemd/system/shop-api.service'",
         "MemoryMax=2147483648\nMemoryCurrent=2104012800\n--workers 8",
         "Memory limit and worker count"),
        ("say", "**Found it.** Every 502 lines up with a worker being killed by the OOM killer.\n\n"
                "| | Before the deploy | Now |\n|---|---|---|\n| Memory per worker | ~180 MB | ~250 MB |\n| Workers | 8 | 8 |\n| Total | ~1.4 GB | ~2.0 GB |\n\n"
                "The unit is capped at `MemoryMax=2G`, so the new image classifier pushed it over. Two ways out:\n\n"
                "1. **Run 5 workers** instead of 8: about 1.25 GB, plenty for current traffic (peak is ~40 req/s).\n"
                "2. **Raise `MemoryMax` to 3G**: web-01 has 4 GB, so this leaves little for nginx and Redis.\n\n"
                "I'd go with 1."),
        ("user", "Go with option 1."),
        ("bash", "ssh web-01 \"sudo sed -i 's/--workers 8/--workers 5/' /etc/systemd/system/shop-api.service && sudo systemctl daemon-reload && sudo systemctl restart shop-api && systemctl is-active shop-api\"",
         "active", "Lower workers to 5 and restart"),
        ("bash", "ssh web-01 \"sudo tail -n 5000 /var/log/nginx/access.log | awk '\\$9 == 502' | wc -l\"",
         "0", "502s since the restart"),
        ("say", "Done: `shop-api` now runs 5 workers, using about **1.3 GB of its 2 GB**. No 502s in the 10 minutes since the restart (there were 31 in the 10 minutes before).\n\n"
                "I'd also add a memory alert at 80% of `MemoryMax`, so this shows up before users see it. Want me to?"),
    ]),
    chat("web-claude", "Renew the TLS certificate for shop.example.com", 400, [
        ("user", "The certificate for shop.example.com expires next week, can you check why it did not renew?"),
        ("bash", "ssh web-01 'sudo certbot certificates 2>/dev/null | grep -A3 shop.example.com'",
         "  Certificate Name: shop.example.com\n    Serial Number: 4a1f...\n    Key Type: ECDSA\n    Expiry Date: 2026-12-02 06:12:40+00:00 (VALID: 6 days)",
         "Certificate status"),
        ("bash", "ssh web-01 'systemctl list-timers certbot.timer --no-pager'",
         "NEXT LEFT LAST PASSED UNIT ACTIVATES\n-    -    -    -      certbot.timer certbot.service\n\n1 timers listed.",
         "Renewal timer"),
        ("say", "The renewal timer is **disabled** (no next run), probably since the server was rebuilt in October. I re-enabled it and renewed now:"),
        ("bash", "ssh web-01 'sudo systemctl enable --now certbot.timer && sudo certbot renew --quiet && sudo systemctl reload nginx'",
         "Created symlink /etc/systemd/system/timers.target.wants/certbot.timer → /usr/lib/systemd/system/certbot.timer.",
         "Enable the timer and renew"),
        ("say", "Renewed: valid until **2027-02-23**, and the timer runs twice a day again."),
    ]),
    chat("db-claude", "Why is the monthly orders report slow?", 30, [
        ("user", "The monthly orders report takes almost a minute now. It used to be a few seconds. What changed?"),
        ("bash", "ssh db-01 \"psql -d shop -c 'SELECT left(query, 60) AS query, calls, round(mean_exec_time) AS ms FROM pg_stat_statements ORDER BY mean_exec_time DESC LIMIT 3;'\"",
         "                            query                             | calls |  ms\n"
         "--------------------------------------------------------------+-------+-------\n"
         " SELECT o.id, o.created_at, c.email, sum(i.price * i.qty) FR |    41 | 52310\n"
         " SELECT * FROM products WHERE tsv @@ plainto_tsquery($1)     |  9822 |    38\n"
         " UPDATE carts SET updated_at = now() WHERE id = $1           | 60211 |     2\n(3 rows)",
         "Slowest queries"),
        ("bash", "ssh db-01 \"psql -d shop -c 'EXPLAIN SELECT * FROM order_items WHERE order_id = 1;' | head -3\"",
         "                            QUERY PLAN\n-------------------------------------------------------------------\n Seq Scan on order_items  (cost=0.00..412881.20 rows=4 width=48)",
         "Check the plan"),
        ("say", "The report scans all of `order_items` (14 million rows) once per order: the index on `order_items.order_id` is gone. It was dropped by migration `2026_11_18_rebuild_items`, which recreated the table without it.\n\n"
                "This space only has a **read-only** login on db-01, so I can't add it myself. The fix, as a migration:\n\n"
                "```sql\nCREATE INDEX CONCURRENTLY order_items_order_id_idx\n    ON order_items (order_id);\n```\n\n"
                "`CONCURRENTLY` keeps the table writable while it builds (about 2 minutes at this size)."),
    ]),
    chat("nas-claude", "Samba share not reachable from the office", 6, [
        ("user", "Nobody in the office can open \\\\nas\\projects since about an hour ago. Can you look?"),
        ("bash", "ssh nas 'systemctl is-active smbd; journalctl -u smbd --since -2h --no-pager | tail -3'",
         "failed\nNov 25 09:02:11 nas smbd[1180]: Unable to load configuration file /etc/samba/smb.conf\n"
         "Nov 25 09:02:11 nas systemd[1]: smbd.service: Main process exited, code=exited, status=1/FAILURE\n"
         "Nov 25 09:02:11 nas systemd[1]: smbd.service: Failed with result 'exit-code'.",
         "Samba's state"),
        ("bash", "ssh nas 'testparm -s 2>&1 | head -3'",
         "Load smb config files from /etc/samba/smb.conf\nError loading services: line 48: Unknown parameter encountered: \"vaild users\"",
         "Check the config"),
        ("say", "Line 48 of `smb.conf` has a typo, `vaild users` instead of `valid users`, from this morning's edit. Fixing it and restarting Samba needs root; I'll ask for it."),
        ("bash", "ssh nas \"sudo -n blackthorn-ask 'sed -i s/vaild/valid/ /etc/samba/smb.conf && systemctl restart smbd'\"",
         None, "Fix the typo and restart smbd (needs approval)"),
    ]),
]


def main():
    out = sys.argv[1]
    for space, sid, lines, t in CHATS:
        d = os.path.join(out, space)
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, sid + ".jsonl")
        with open(p, "w") as f:
            for line in lines:
                f.write(json.dumps(line) + "\n")
        os.utime(p, (t, t))
        print(space, sid)


if __name__ == "__main__":
    main()
