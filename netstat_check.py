# ==========================================
# netstat_check.py
# Cross-check this tool against `netstat -ano`
# ==========================================

import subprocess
from datetime import datetime

from common import OUTPUT_DIR, normalize_ip, format_endpoint
from db import index_rows, index_connections, diff_indexes

NETSTAT_STATE_MAP = {"LISTENING": "LISTEN"}


def run_netstat():
    return subprocess.run(["netstat", "-ano"], capture_output=True, text=True,
                          check=True).stdout


def _split_endpoint(text):
    if text == "*:*":
        return "*", 0
    host, _, port = text.rpartition(":")
    host = host.strip("[]")
    return normalize_ip(host), int(port)


def parse_netstat(text):
    """netstat -ano text -> rows (protocol, laddr, lport, raddr, rport, state, pid, name)."""
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        try:
            if parts[0] == "TCP" and len(parts) in (4, 5):
                lip, lport = _split_endpoint(parts[1])
                rip, rport = _split_endpoint(parts[2])
                # a blank state column (4 fields) happens for the odd listener states
                state = NETSTAT_STATE_MAP.get(parts[3], parts[3]) if len(parts) == 5 else ""
                rows.append(("TCP", lip, lport, rip, rport, state, int(parts[-1]), ""))
            elif parts[0] == "UDP" and len(parts) == 4:
                lip, lport = _split_endpoint(parts[1])
                rows.append(("UDP", lip, lport, "*", 0, "NONE", int(parts[3]), ""))
        except ValueError:
            continue                       # header or malformed line
    return rows


def _normalised_tool_rows(connections):
    return [(c.protocol, normalize_ip(c.local_address), c.local_port,
             normalize_ip(c.remote_address), c.remote_port, c.state, c.pid, c.process_name)
            for c in connections]


def compare(connections, netstat_text):
    """Return (report_text, stats). Both sides are indexed with the same identity key."""
    ns_rows = parse_netstat(netstat_text)

    # Builds with the listener-state quirk make netstat print blank/odd states for listeners.
    # A TCP row whose remote endpoint is 0.0.0.0:0 / [::]:0 IS a listener, so compare it as LISTEN.
    quirk = 0
    fixed = []
    for r in ns_rows:
        if r[0] == "TCP" and r[3] in ("0.0.0.0", "::") and r[4] == 0 and r[5] != "LISTEN":
            r = r[:5] + ("LISTEN",) + r[6:]
            quirk += 1
        fixed.append(r)
    ns_rows = fixed
    tool_rows = _normalised_tool_rows(connections)
    ns_idx, tool_idx = index_rows(ns_rows), index_rows(tool_rows)
    d = diff_indexes(ns_idx, tool_idx)       # "added" = only in tool, "removed" = only in netstat

    matched = len(set(ns_idx) & set(tool_idx))
    state_ok = matched - len(d["changed"])
    pct = 100.0 * state_ok / max(1, len(ns_idx))

    def fmt(k, table):
        proto, lip, lport, rip, rport, pid, _ = k
        return (f"{proto:3} {format_endpoint(lip, lport)} -> {format_endpoint(rip, rport)} "
                f"PID={pid} [{table[k]['state']}]")

    L = ["=" * 70, "CROSS-CHECK vs netstat -ano", "=" * 70,
         f"netstat rows        : {len(ns_idx)}",
         f"this tool's rows    : {len(tool_idx)}",
         f"identical rows      : {state_ok}  ({pct:.1f}% of netstat)",
         f"same row, other state: {len(d['changed'])}",
         f"only in netstat     : {len(d['removed'])}",
         f"only in this tool   : {len(d['added'])}",
         "",
         "Differences of a few ephemeral-port rows are normal: the two reads happen",
         "milliseconds apart and short-lived connections open/close in between.",
         "netstat prints LISTENING; this tool prints LISTEN (normalised for comparison)."]
    if quirk:
        L.append(f"{quirk} netstat listener row(s) had a blank/odd state (Windows-build quirk) "
                 "and were compared as LISTEN.")
    if d["changed"]:
        L += ["", "--- same connection, different state ---"]
        L += [f"{fmt(k, tool_idx)}  netstat={a} tool={b}" for k, a, b in d["changed"]]
    if d["removed"]:
        L += ["", "--- only in netstat ---"] + [fmt(k, ns_idx) for k in sorted(d["removed"], key=str)]
    if d["added"]:
        L += ["", "--- only in this tool ---"] + [fmt(k, tool_idx) for k in sorted(d["added"], key=str)]

    stats = {"netstat": len(ns_idx), "tool": len(tool_idx), "identical": state_ok,
             "percent": pct, "state_mismatch": len(d["changed"]),
             "only_netstat": len(d["removed"]), "only_tool": len(d["added"]),
             "listener_quirk": quirk}
    return "\n".join(L), stats


def run_check():
    """Read netstat and the kernel tables back-to-back, write a report, return (path, stats)."""
    from collector import collect_all
    netstat_text = run_netstat()
    _, tcp, udp = collect_all()
    report, stats = compare(tcp + udp, netstat_text)

    OUTPUT_DIR.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    (OUTPUT_DIR / f"netstat_raw_{stamp}.txt").write_text(netstat_text, encoding="utf-8")
    path = OUTPUT_DIR / f"netstat_check_{stamp}.txt"
    path.write_text(report + "\n", encoding="utf-8")
    return path, report, stats
