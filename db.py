# ==========================================
# db.py
# SQLite persistence, snapshot diffing, CSV export
# ==========================================

import csv
import sqlite3
from collections import Counter
from datetime import datetime

from common import DB_PATH, format_endpoint

ROW_COLS = ("protocol, local_address, local_port, remote_address, "
            "remote_port, state, pid, process_name")


def connect(path=None):
    return sqlite3.connect(path or DB_PATH)


def create_database(conn):
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS snapshots(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        label TEXT
    );
    CREATE TABLE IF NOT EXISTS connections(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        snapshot_id INTEGER,
        protocol TEXT,
        local_address TEXT,
        local_port INTEGER,
        remote_address TEXT,
        remote_port INTEGER,
        state TEXT,
        pid INTEGER,
        process_name TEXT,
        ip_version INTEGER DEFAULT 4
    );
    CREATE INDEX IF NOT EXISTS idx_connections_snapshot ON connections(snapshot_id);
    CREATE TABLE IF NOT EXISTS dns_cache(
        ip TEXT PRIMARY KEY,
        hostname TEXT,
        resolved_at TEXT
    );
    """)
    # migrate databases created by older versions of this project
    snap_cols = {r[1] for r in conn.execute("PRAGMA table_info(snapshots)")}
    if "label" not in snap_cols:
        conn.execute("ALTER TABLE snapshots ADD COLUMN label TEXT")
    conn_cols = {r[1] for r in conn.execute("PRAGMA table_info(connections)")}
    if "ip_version" not in conn_cols:
        conn.execute("ALTER TABLE connections ADD COLUMN ip_version INTEGER DEFAULT 4")
    conn.commit()


def save_snapshot(conn, connections, label=None):
    """Snapshot row + all connection rows in ONE transaction (all or nothing)."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with conn:
        cur = conn.execute("INSERT INTO snapshots(timestamp, label) VALUES(?, ?)",
                           (timestamp, label))
        snapshot_id = cur.lastrowid
        conn.executemany(
            """INSERT INTO connections(snapshot_id, protocol, local_address, local_port,
                   remote_address, remote_port, state, pid, process_name, ip_version)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            [(snapshot_id, c.protocol, c.local_address, c.local_port, c.remote_address,
              c.remote_port, c.state, c.pid, c.process_name, c.ip_version)
             for c in connections])
    return snapshot_id


def list_snapshots(conn):
    return conn.execute(
        """SELECT s.id, s.timestamp, COALESCE(s.label, ''), COUNT(c.id)
           FROM snapshots s LEFT JOIN connections c ON c.snapshot_id = s.id
           GROUP BY s.id ORDER BY s.id""").fetchall()


def prune(conn, keep):
    """Keep only the newest `keep` snapshots (stops --watch growing the DB forever)."""
    with conn:
        conn.execute("""DELETE FROM connections WHERE snapshot_id NOT IN
                        (SELECT id FROM snapshots ORDER BY id DESC LIMIT ?)""", (keep,))
        cur = conn.execute("""DELETE FROM snapshots WHERE id NOT IN
                        (SELECT id FROM snapshots ORDER BY id DESC LIMIT ?)""", (keep,))
    return cur.rowcount


# --------------------------------------------------------------------------
# Diffing
# --------------------------------------------------------------------------

def index_rows(rows):
    """
    rows: iterable of (protocol, laddr, lport, raddr, rport, state, pid, name).

    Identity key = everything EXCEPT state (so a state change is detectable).
    Duplicates (e.g. several identical UDP rows) get an occurrence number so
    they are not silently collapsed.
    """
    seen, result = Counter(), {}
    for proto, lip, lport, rip, rport, state, pid, pname in rows:
        base = (proto, lip, lport, rip, rport, pid)
        seen[base] += 1
        result[base + (seen[base],)] = {"state": state, "process_name": pname}
    return result


def index_connections(connections):
    return index_rows((c.protocol, c.local_address, c.local_port, c.remote_address,
                       c.remote_port, c.state, c.pid, c.process_name) for c in connections)


def _read_connections(conn, snapshot_id):
    rows = conn.execute(f"SELECT {ROW_COLS} FROM connections WHERE snapshot_id = ? ORDER BY id",
                        (snapshot_id,)).fetchall()
    return index_rows(rows)


def diff_indexes(old, new):
    added = [k for k in new if k not in old]
    removed = [k for k in old if k not in new]
    changed = [(k, old[k]["state"], new[k]["state"])
               for k in new if k in old and old[k]["state"] != new[k]["state"]]
    unchanged = len(set(old) & set(new)) - len(changed)
    return {"added": added, "removed": removed, "changed": changed, "unchanged": unchanged}


def diff_snapshots(conn, prev_id=None, cur_id=None):
    """Diff two stored snapshots (default: the latest two). Returns None if impossible."""
    if prev_id is None or cur_id is None:
        snaps = conn.execute("SELECT id FROM snapshots ORDER BY id DESC LIMIT 2").fetchall()
        if len(snaps) < 2:
            return None
        cur_id, prev_id = snaps[0][0], snaps[1][0]

    def meta(i):
        r = conn.execute("SELECT timestamp, COALESCE(label,'') FROM snapshots WHERE id=?",
                         (i,)).fetchone()
        return r if r else (None, None)

    prev_ts, prev_label = meta(prev_id)
    cur_ts, cur_label = meta(cur_id)
    if prev_ts is None or cur_ts is None:
        return None

    old, new = _read_connections(conn, prev_id), _read_connections(conn, cur_id)
    d = diff_indexes(old, new)
    d.update(prev_id=prev_id, cur_id=cur_id, prev_ts=prev_ts, cur_ts=cur_ts,
             prev_label=prev_label, cur_label=cur_label, old=old, new=new)
    return d


def _fmt_key(key, table):
    proto, lip, lport, rip, rport, pid, _ = key
    name = table[key]["process_name"]
    return (f"{proto:3} {format_endpoint(lip, lport)} -> {format_endpoint(rip, rport)}  "
            f"PID={pid} ({name})")


def _group(keys, table, hosts):
    """Ephemeral local ports make raw diffs noisy; group by process + remote endpoint."""
    counts = Counter()
    for k in keys:
        if k[0] == "TCP" and k[3] not in ("0.0.0.0", "::", "*"):
            host = (hosts or {}).get(k[3])
            remote = format_endpoint(k[3], k[4]) + (f" [{host}]" if host else "")
            counts[(table[k]["process_name"], remote)] += 1
    return counts


def format_diff(d, verbose=True, hosts=None):
    """Render a diff dict as text (so the same output can go to console AND a file)."""
    out = ["=" * 70, "SNAPSHOT COMPARISON", "=" * 70,
           f"Previous : #{d['prev_id']}  {d['prev_ts']}  {d['prev_label']}",
           f"Current  : #{d['cur_id']}  {d['cur_ts']}  {d['cur_label']}",
           "",
           f"Added     : {len(d['added'])}",
           f"Removed   : {len(d['removed'])}",
           f"Changed   : {len(d['changed'])}",
           f"Unchanged : {d['unchanged']}"]

    if verbose:
        out += ["", "--- Added ---"]
        out += [_fmt_key(k, d["new"]) + f"  [{d['new'][k]['state']}]"
                for k in sorted(d["added"], key=str)]
        out += ["", "--- Removed ---"]
        out += [_fmt_key(k, d["old"]) + f"  [{d['old'][k]['state']}]"
                for k in sorted(d["removed"], key=str)]
        out += ["", "--- State changes ---"]
        out += [f"{_fmt_key(k, d['new'])}: {a} -> {b}"
                for k, a, b in sorted(d["changed"], key=lambda x: str(x[0]))]

    out += ["", "--- Added, grouped by process / remote endpoint ---"]
    out += [f"{n:3} x {name} -> {remote}"
            for (name, remote), n in _group(d["added"], d["new"], hosts).most_common(15)]
    out += ["", "--- Removed, grouped by process / remote endpoint ---"]
    out += [f"{n:3} x {name} -> {remote}"
            for (name, remote), n in _group(d["removed"], d["old"], hosts).most_common(15)]
    return "\n".join(out)


# --------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------

def export_csv(conn, snapshot_id, path, hosts=None):
    rows = conn.execute(
        f"""SELECT {ROW_COLS}, ip_version FROM connections
            WHERE snapshot_id = ? ORDER BY protocol, ip_version, local_port""",
        (snapshot_id,)).fetchall()

    header = ["protocol", "local_address", "local_port", "remote_address",
              "remote_port", "state", "pid", "process_name", "ip_version"]
    if hosts is not None:
        header.append("remote_host")

    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        for r in rows:
            w.writerow(list(r) + ([hosts.get(r[3], "")] if hosts is not None else []))
    return path
