# ==========================================
# live.py
# Extension: continuously redrawing console view
# Watch a connection move through SYN_SENT -> ESTABLISHED -> FIN_WAIT -> TIME_WAIT live.
# ==========================================

import os
import time
from collections import Counter, deque
from datetime import datetime

from collector import collect_all
from common import format_endpoint
from db import index_connections, diff_indexes


def _clear():
    os.system("cls" if os.name == "nt" else "clear")


def run_live(interval=2.0, name_filter=None, max_events=22):
    """Poll every `interval` seconds, redraw the screen, keep a log of state transitions."""
    previous, events = None, deque(maxlen=max_events)
    polls = 0

    while True:
        _, tcp, udp = collect_all()
        conns = [c for c in tcp + udp
                 if not name_filter or name_filter.lower() in c.process_name.lower()]
        current = index_connections(conns)
        stamp = datetime.now().strftime("%H:%M:%S")
        polls += 1

        if previous is not None:
            d = diff_indexes(previous, current)
            for k in d["added"]:
                events.appendleft((stamp, "NEW    ", k, f"-> {current[k]['state']}"))
            for k, a, b in d["changed"]:
                events.appendleft((stamp, "CHANGE ", k, f"{a} -> {b}"))
            for k in d["removed"]:
                events.appendleft((stamp, "GONE   ", k, f"(was {previous[k]['state']})"))

        _clear()
        states = Counter(c.state for c in conns if c.protocol == "TCP")
        procs = Counter(c.process_name for c in conns).most_common(6)
        print(f"Network Connections Monitor - LIVE (every {interval}s, poll #{polls}, Ctrl+C to stop)"
              + (f"   filter='{name_filter}'" if name_filter else ""))
        print(f"{stamp} | sockets: {len(conns)} | TCP: {sum(states.values())} | "
              f"UDP: {sum(1 for c in conns if c.protocol == 'UDP')}")
        print("TCP states : " + "  ".join(f"{s}={n}" for s, n in states.most_common()))
        print("Top procs  : " + "  ".join(f"{p}={n}" for p, n in procs))
        print("\nRecent events (newest first):")
        print(f"{'time':8} {'event':7} {'proto':5} {'local':<28} {'remote':<28} {'pid':>6}  change")
        for ts, kind, k, change in events:
            proto, lip, lport, rip, rport, pid, _ = k
            print(f"{ts:8} {kind} {proto:5} {format_endpoint(lip, lport):<28} "
                  f"{format_endpoint(rip, rport):<28} {pid:>6}  {change}")

        previous = current
        time.sleep(interval)
