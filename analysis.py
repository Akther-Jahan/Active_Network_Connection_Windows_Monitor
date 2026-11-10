# ==========================================
# analysis.py
# pandas summaries, the two required charts, and a data-driven interpretation
# ==========================================

import pandas as pd
import matplotlib.pyplot as plt

from common import OUTPUT_DIR

# Order follows the life of a connection, not the alphabet
STATE_ORDER = ["LISTEN", "SYN_SENT", "SYN_RECEIVED", "ESTABLISHED", "FIN_WAIT_1",
               "FIN_WAIT_2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT",
               "CLOSED", "DELETE_TCB", "UNKNOWN"]


def load_data(conn, snapshot_id):
    return pd.read_sql_query("SELECT * FROM connections WHERE snapshot_id = ?",
                             conn, params=(snapshot_id,))


def _finish(fig_name, show):
    OUTPUT_DIR.mkdir(exist_ok=True)
    path = OUTPUT_DIR / fig_name
    plt.tight_layout()
    plt.savefig(path, dpi=110)
    if show:
        plt.show()
    plt.close()
    return path


def _kind(row):
    if row.protocol == "UDP":
        return "UDP endpoint"
    return "TCP LISTEN" if row.state == "LISTEN" else "TCP connection"


def connections_per_process(conn, snapshot_id, show=False):
    """Top 10 process names, stacked by kind so listeners / UDP aren't mistaken for connections."""
    df = load_data(conn, snapshot_id)
    if df.empty:
        print("No data available.")
        return None

    df["kind"] = df.apply(_kind, axis=1)
    top = df["process_name"].value_counts().head(10).index
    table = (df[df["process_name"].isin(top)]
             .groupby(["process_name", "kind"]).size().unstack(fill_value=0).loc[top])

    ax = table.plot(kind="bar", stacked=True, figsize=(10, 6))
    for i, total in enumerate(table.sum(axis=1)):
        ax.text(i, total + 0.5, str(total), ha="center", fontsize=9)
    plt.title(f"Top Processes by Socket Count (snapshot {snapshot_id})")
    plt.xlabel("Process name (all PIDs with that name combined)")
    plt.ylabel("Sockets")
    plt.xticks(rotation=45, ha="right")
    return _finish(f"connections_per_process_{snapshot_id}.png", show)


def tcp_state_distribution(conn, snapshot_id, show=False):
    df = load_data(conn, snapshot_id)
    tcp = df[df["protocol"] == "TCP"]
    if tcp.empty:
        print("No TCP data available.")
        return None

    counts = tcp.groupby("state").size()
    order = [s for s in STATE_ORDER if s in counts.index] + \
            [s for s in counts.index if s not in STATE_ORDER]
    counts = counts.loc[order]

    ax = counts.plot(kind="bar", figsize=(9, 5))
    for i, v in enumerate(counts):
        ax.text(i, v + 0.3, str(v), ha="center", fontsize=9)
    plt.title(f"TCP State Distribution (snapshot {snapshot_id})")
    plt.xlabel("TCP state")
    plt.ylabel("Count")
    plt.xticks(rotation=45, ha="right")
    return _finish(f"tcp_state_distribution_{snapshot_id}.png", show)


def summary_report(conn, snapshot_id):
    df = load_data(conn, snapshot_id)
    print("=" * 50)
    print(f"SUMMARY REPORT (snapshot {snapshot_id})")
    print("=" * 50)
    print("Total sockets    :", len(df))
    print("TCP              :", (df.protocol == "TCP").sum())
    print("UDP              :", (df.protocol == "UDP").sum())
    if "ip_version" in df:
        print("IPv4 / IPv6      :", (df.ip_version == 4).sum(), "/", (df.ip_version == 6).sum())
    print("Distinct PIDs    :", df.pid.nunique())
    print("\nTop 10 process names (sockets / distinct PIDs)")
    top = (df.groupby("process_name")
             .agg(sockets=("pid", "size"), pids=("pid", "nunique"))
             .sort_values("sockets", ascending=False).head(10))
    print(top)


def write_interpretation(conn, snapshot_id):
    """
    Written interpretation of the two charts, built from the snapshot's REAL numbers,
    so the report always matches the charts it sits next to.
    """
    df = load_data(conn, snapshot_id)
    if df.empty:
        return None
    OUTPUT_DIR.mkdir(exist_ok=True)

    df["kind"] = df.apply(_kind, axis=1)
    per_proc = (df.groupby("process_name")
                  .agg(sockets=("pid", "size"), pids=("pid", "nunique"))
                  .sort_values("sockets", ascending=False))
    top_name, top = per_proc.index[0], per_proc.iloc[0]
    top_kinds = df[df.process_name == top_name]["kind"].value_counts()
    listeners = int(top_kinds.get("TCP LISTEN", 0)) + int(top_kinds.get("UDP endpoint", 0))

    tcp = df[df.protocol == "TCP"]
    st = tcp["state"].value_counts()
    n = lambda s: int(st.get(s, 0))
    total_tcp = len(tcp)

    L = [f"# Interpretation of snapshot {snapshot_id}", "",
         "## Sockets per process", "",
         f"`{top_name}` owns the most sockets: {int(top.sockets)} spread over "
         f"{int(top.pids)} distinct PID(s); {listeners} of them are listeners or UDP "
         "endpoints rather than live conversations."]

    if top_name.lower() == "svchost.exe":
        L.append("This is expected: the chart groups by process *name*, and Windows runs "
                 "many separate svchost.exe processes, each hosting a group of system "
                 "services (RPC, DNS client, DHCP, Windows Update ...). One name therefore "
                 "stands for many PIDs and many service endpoints, while a user "
                 "application is a single process family that only holds the connections "
                 "the user opened.")
    elif int(top.pids) > 1:
        L.append(f"The count is high partly because several processes share the name "
                 f"`{top_name}` and the chart adds them together.")

    others = per_proc.drop(index=[i for i in per_proc.index if i.lower() == "svchost.exe"])
    if not others.empty and top_name.lower() == "svchost.exe":
        L.append(f"By contrast the busiest non-svchost process is `{others.index[0]}` "
                 f"with {int(others.iloc[0].sockets)} sockets over "
                 f"{int(others.iloc[0].pids)} PID(s).")

    L += ["", "## TCP state distribution", "",
          f"The snapshot has {total_tcp} TCP sockets: {n('ESTABLISHED')} ESTABLISHED, "
          f"{n('LISTEN')} LISTEN, {n('TIME_WAIT')} TIME_WAIT, {n('CLOSE_WAIT')} CLOSE_WAIT, "
          f"{n('FIN_WAIT_1') + n('FIN_WAIT_2')} FIN_WAIT, {n('LAST_ACK')} LAST_ACK, "
          f"{n('SYN_SENT')} SYN_SENT."]

    dominant = st.index[0] if len(st) else None
    if dominant == "ESTABLISHED":
        L.append("ESTABLISHED dominates because browsers and cloud-connected apps keep many "
                 "long-lived HTTPS sessions open.")
    elif dominant == "LISTEN":
        L.append("LISTEN dominates: this machine is mostly services waiting for traffic "
                 "rather than active clients.")
    L.append("LISTEN sockets are servers bound to a port, waiting for incoming connections.")
    L.append(f"TIME_WAIT ({n('TIME_WAIT')}) is not a leak: the OS deliberately keeps a "
             "fully closed connection for a short interval (about 2 x MSL) so delayed "
             "duplicate packets cannot be mistaken for a new connection on the same ports.")
    if n("CLOSE_WAIT"):
        L.append(f"CLOSE_WAIT ({n('CLOSE_WAIT')}) means the remote side closed but the local "
                 "application has not closed its socket yet; rows that stay here for a long "
                 "time point to an application that forgets to close sockets.")
    if n("LAST_ACK") or n("FIN_WAIT_1") or n("FIN_WAIT_2"):
        L.append("FIN_WAIT_* / LAST_ACK rows are connections caught mid-teardown, which is "
                 "why the shape of this chart changes from run to run.")
    if n("UNKNOWN"):
        L += ["", f"**WARNING:** {n('UNKNOWN')} TCP rows have an unrecognised state code. "
                  "That indicates a decoding problem and these numbers should not be trusted."]

    path = OUTPUT_DIR / f"interpretation_{snapshot_id}.md"
    path.write_text("\n".join(L) + "\n", encoding="utf-8")
    return path
