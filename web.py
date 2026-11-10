# ==========================================
# web.py
# Local web dashboard (standard library only)
#   python web.py            -> http://127.0.0.1:8000
# ==========================================

import argparse
import json
import sys
import webbrowser
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import db
from common import BASE_DIR, format_endpoint

PAGE = BASE_DIR / "dashboard.html"
MAX_ITEMS = 500
TIMELINE_ROW_CAP = 800

# Order follows the life of a connection (used for stacking and legends)
STATE_ORDER = ["LISTEN", "SYN_SENT", "SYN_RECEIVED", "ESTABLISHED", "FIN_WAIT_1", "FIN_WAIT_2",
               "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT", "CLOSED", "DELETE_TCB", "UNKNOWN"]


def take_snapshot(conn):
    from collector import collect_all     # Windows only, imported lazily

    _, tcp, udp = collect_all()
    return db.save_snapshot(conn, tcp + udp)


def build_payload(conn, snapshot_id=None):

    if snapshot_id is None:
        row = conn.execute("SELECT MAX(id) FROM snapshots").fetchone()
        snapshot_id = row[0]
    if snapshot_id is None:
        return {"empty": True}

    ts = conn.execute("SELECT timestamp FROM snapshots WHERE id=?", (snapshot_id,)).fetchone()[0]
    prev = conn.execute(
        "SELECT id, timestamp FROM snapshots WHERE id < ? ORDER BY id DESC LIMIT 1",
        (snapshot_id,),
    ).fetchone()

    rows = conn.execute(
        """SELECT protocol, local_address, local_port, remote_address,
                  remote_port, state, pid, process_name
           FROM connections WHERE snapshot_id=?""",
        (snapshot_id,),
    ).fetchall()

    keys = ["protocol", "local_address", "local_port", "remote_address",
            "remote_port", "state", "pid", "process_name"]
    connections = [dict(zip(keys, r)) for r in rows]
    for c in connections:
        c["local"] = format_endpoint(c["local_address"], c["local_port"])
        c["remote"] = format_endpoint(c["remote_address"], c["remote_port"])

    # Per-process breakdown
    procs = {}
    for c in connections:
        p = procs.setdefault(c["process_name"], {"name": c["process_name"],
                             "tcp": 0, "listen": 0, "udp": 0, "pids": set()})
        p["pids"].add(c["pid"])
        if c["protocol"] == "UDP":
            p["udp"] += 1
        elif c["state"] == "LISTEN":
            p["listen"] += 1
        else:
            p["tcp"] += 1
    processes = sorted(procs.values(), key=lambda p: -(p["tcp"] + p["listen"] + p["udp"]))[:10]
    for p in processes:
        p["pids"] = len(p["pids"])

    states = Counter(c["state"] for c in connections if c["protocol"] == "TCP")

    diff = None
    if prev:
        old = db._read_connections(conn, prev[0])
        new = db._read_connections(conn, snapshot_id)

        def item(key, table, extra=None):
            d = {"protocol": key[0], "local": format_endpoint(key[1], key[2]),
                 "remote": format_endpoint(key[3], key[4]), "pid": key[5],
                 "process": table[key]["process_name"]}
            if extra:
                d.update(extra)
            return d

        added = [k for k in new if k not in old]
        removed = [k for k in old if k not in new]
        changed = [k for k in new if k in old and new[k]["state"] != old[k]["state"]]
        diff = {
            "added_total": len(added), "removed_total": len(removed),
            "changed_total": len(changed),
            "added": [item(k, new, {"state": new[k]["state"]}) for k in sorted(added, key=str)[:MAX_ITEMS]],
            "removed": [item(k, old, {"state": old[k]["state"]}) for k in sorted(removed, key=str)[:MAX_ITEMS]],
            "changed": [item(k, new, {"from": old[k]["state"], "to": new[k]["state"]})
                        for k in sorted(changed, key=str)[:MAX_ITEMS]],
        }

    return {
        "empty": False,
        "snapshot": {"id": snapshot_id, "timestamp": ts},
        "previous": {"id": prev[0], "timestamp": prev[1]} if prev else None,
        "counts": {
            "total": len(connections),
            "tcp": sum(c["protocol"] == "TCP" for c in connections),
            "udp": sum(c["protocol"] == "UDP" for c in connections),
            "pids": len({c["pid"] for c in connections}),
        },
        "states": dict(states),
        "processes": processes,
        "diff": diff,
        "connections": connections,
    }


def build_timeline(conn, last=40):
    """
    TCP connections across the last `last` snapshots.

    rows[i].cells[j] = index into `states` for connection i in snapshot j, or -1 if the
    connection was not in that snapshot. That matrix is what the dashboard draws as a
    per-connection life line (SYN_SENT -> ESTABLISHED -> CLOSE_WAIT -> TIME_WAIT -> gone).
    """
    last = max(2, min(int(last), 200))
    snaps = conn.execute(
        "SELECT id, timestamp, COALESCE(label, '') FROM snapshots ORDER BY id DESC LIMIT ?",
        (last,)).fetchall()[::-1]
    if not snaps:
        return {"empty": True}

    ids = [s[0] for s in snaps]
    marks = ",".join("?" * len(ids))
    per = {i: [] for i in ids}
    for r in conn.execute(
            f"""SELECT snapshot_id, protocol, local_address, local_port, remote_address,
                       remote_port, state, pid, process_name
                FROM connections WHERE snapshot_id IN ({marks}) AND protocol = 'TCP'
                ORDER BY id""", ids):
        per[r[0]].append(r[1:])
    indexes = [db.index_rows(per[i]) for i in ids]

    seen_states = {v["state"] for idx in indexes for v in idx.values()}
    states = [s for s in STATE_ORDER if s in seen_states] + sorted(seen_states - set(STATE_ORDER))
    sidx = {s: i for i, s in enumerate(states)}
    listen_i = sidx.get("LISTEN", -99)

    summaries = []
    for n, (sid, ts, label) in enumerate(snaps):
        idx = indexes[n]
        item = {"id": sid, "timestamp": ts, "label": label, "total": len(idx),
                "counts": dict(Counter(v["state"] for v in idx.values())),
                "added": None, "removed": None, "changed": None}
        if n:
            d = db.diff_indexes(indexes[n - 1], idx)
            item.update(added=len(d["added"]), removed=len(d["removed"]), changed=len(d["changed"]))
        summaries.append(item)

    all_keys = {}
    for idx in indexes:
        for k in idx:
            all_keys.setdefault(k, None)

    rows = []
    for key in all_keys:
        cells = [sidx[idx[key]["state"]] if key in idx else -1 for idx in indexes]
        latest = next(idx[key] for idx in reversed(indexes) if key in idx)
        changes = sum(1 for a, b in zip(cells, cells[1:]) if a >= 0 and b >= 0 and a != b)
        rows.append({
            "process": latest["process_name"], "pid": key[5],
            "local": format_endpoint(key[1], key[2]), "remote": format_endpoint(key[3], key[4]),
            "cells": cells, "changes": changes,
            "present_all": all(c >= 0 for c in cells),
            "listener": all(c in (-1, listen_i) for c in cells),
        })

    # interesting rows (changed / appeared / disappeared) first, listeners last
    rows.sort(key=lambda r: (not (r["changes"] or not r["present_all"]), r["listener"],
                             r["process"].lower(), r["local"]))
    total_rows = len(rows)
    return {"empty": False, "states": states, "snapshots": summaries,
            "rows": rows[:TIMELINE_ROW_CAP], "total_rows": total_rows,
            "truncated": total_rows > TIMELINE_ROW_CAP}


class Handler(BaseHTTPRequestHandler):

    def _send(self, code, body, ctype):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        url = urlparse(self.path)
        qs = parse_qs(url.query)

        if url.path == "/":
            return self._send(200, PAGE.read_text(encoding="utf-8"), "text/html; charset=utf-8")

        if url.path == "/api/data":
            conn = db.connect()
            try:
                db.create_database(conn)
                sid = None
                if qs.get("take", ["0"])[0] == "1":
                    sid = take_snapshot(conn)
                elif "id" in qs:
                    sid = int(qs["id"][0])
                payload = build_payload(conn, sid)
                return self._send(200, json.dumps(payload), "application/json")
            except Exception as e:  # report API failures to the page
                return self._send(500, json.dumps({"error": str(e)}), "application/json")
            finally:
                conn.close()

        if url.path == "/api/timeline":
            conn = db.connect()
            try:
                db.create_database(conn)
                last = int(qs.get("last", ["40"])[0])
                return self._send(200, json.dumps(build_timeline(conn, last)), "application/json")
            except Exception as e:
                return self._send(500, json.dumps({"error": str(e)}), "application/json")
            finally:
                conn.close()

        self._send(404, "Not found", "text/plain")

    def log_message(self, *args):
        pass  # keep the console quiet


def main():
    p = argparse.ArgumentParser(description="Network monitor web dashboard")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--no-browser", action="store_true")
    args = p.parse_args()

    if sys.platform != "win32":
        print("Note: not Windows, so 'Take snapshot' will fail; stored data can still be viewed.")

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    url = f"http://127.0.0.1:{args.port}"
    print(f"Dashboard running at {url}  (Ctrl+C to stop)")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
