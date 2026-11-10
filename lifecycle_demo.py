# ==========================================
# lifecycle_demo.py
# Deterministic demo of the TCP state machine, observed in the kernel table.
#   python main.py --lifecycle
# We open our OWN loopback connection (so we know exactly which rows are ours),
# close it in stages, and poll the kernel table to log every state change.
# ==========================================

import socket
import time

from common import OUTPUT_DIR, format_endpoint


def _default_reader():
    from tcp_table import get_tcp_connections
    return get_tcp_connections({})


def _label(c, server_port):
    if c.remote_port == 0:
        return "listener"
    return "server-side" if c.local_port == server_port else "client-side"


def run(reader=None, sleep=time.sleep, clock=time.monotonic):
    """Returns the list of log lines (also printed and saved)."""
    reader = reader or _default_reader
    log, last, t0 = [], {}, clock()

    def emit(text):
        line = f"[{clock() - t0:5.2f}s] {text}"
        log.append(line)
        print(line)

    def observe(seconds, match, label_fn):
        """Poll ~20x/s; log a line whenever a matching row appears, changes or disappears."""
        end = clock() + seconds
        while True:
            seen = {}
            for c in reader():
                if match(c):
                    seen[(c.local_port, c.remote_port)] = (label_fn(c), c)
            for key, (lab, c) in seen.items():
                if last.get(key) != c.state:
                    old = last.get(key)
                    emit(f"{lab:11} {format_endpoint(c.local_address, c.local_port)} -> "
                         f"{format_endpoint(c.remote_address, c.remote_port)}  "
                         + (f"{old} -> {c.state}" if old else f"appeared as {c.state}"))
                    last[key] = c.state
            for key in [k for k in last if k not in seen]:
                emit(f"{'':11} ports {key[0]} -> {key[1]}  {last.pop(key)} -> (gone from table)")
            if clock() >= end:
                return
            sleep(0.05)

    # ---- Part 1: SYN_SENT (connect to a black-holed documentation address) -------------
    emit("PART 1: SYN_SENT - connecting to 192.0.2.1:9 (TEST-NET, normally never answers)")
    probe = socket.socket()
    probe.setblocking(False)
    probe.connect_ex(("192.0.2.1", 9))
    observe(2.0, lambda c: c.remote_address == "192.0.2.1", lambda c: "client-side")
    probe.close()
    observe(0.5, lambda c: c.remote_address == "192.0.2.1", lambda c: "client-side")
    if not any("SYN_SENT" in line for line in log):
        emit("(no SYN_SENT seen: your network answered or rejected the probe immediately)")
    last.clear()

    # ---- Part 2: a full connection life cycle on loopback -------------------------------
    emit("PART 2: full life cycle on 127.0.0.1")
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    ours = lambda c: c.local_port == port or c.remote_port == port
    lab = lambda c: _label(c, port)

    observe(0.4, ours, lab)
    emit(f"-> client connects to port {port}")
    client = socket.create_connection(("127.0.0.1", port))
    conn, _ = server.accept()
    observe(0.6, ours, lab)

    emit("-> client closes first (sends FIN); server has NOT closed yet")
    client.close()
    observe(2.0, ours, lab)

    emit("-> server closes (sends its FIN)")
    conn.close()
    observe(1.0, ours, lab)

    emit("-> listener closed")
    server.close()
    observe(0.6, ours, lab)

    emit("Done. The client-side row normally stays in TIME_WAIT (~2 minutes) before leaving the table.")

    OUTPUT_DIR.mkdir(exist_ok=True)
    path = OUTPUT_DIR / "state_lifecycle_demo.txt"
    path.write_text("\n".join(log) + "\n", encoding="utf-8")
    print(f"\nSaved to {path}")
    return log
