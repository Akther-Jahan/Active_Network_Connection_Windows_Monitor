# ==========================================
# diagnose.py
# Dump RAW dwState values from the kernel so a decoding problem can be pinned down
#   python main.py --diagnose
# ==========================================

import platform
import subprocess
import sys
from collections import Counter

from common import DWORD, AF_INET, OUTPUT_DIR, fetch_table

CLASSES = {3: "OWNER_PID_LISTENER", 4: "OWNER_PID_CONNECTIONS", 5: "OWNER_PID_ALL"}
WORDS = ("state", "laddr", "lport", "raddr", "rport", "pid")


def raw_rows(table_class):
    from tcp_table import GetExtendedTcpTable
    buffer, count = fetch_table(GetExtendedTcpTable, AF_INET, table_class)
    if count == 0:
        return []
    words = (DWORD * (count * 6)).from_buffer(buffer, 4)
    return [tuple(words[i * 6:(i + 1) * 6]) for i in range(count)]


def run():
    out = [f"Python {sys.version.split()[0]} ({platform.architecture()[0]}) | "
           f"Windows {sys.getwindowsversion().major}.{sys.getwindowsversion().minor} "
           f"build {sys.getwindowsversion().build}", ""]

    tables = {}
    for cls, name in CLASSES.items():
        rows = raw_rows(cls)
        tables[cls] = rows
        out.append(f"class {cls} {name}: {len(rows)} rows | raw dwState counts: "
                   f"{dict(sorted(Counter(r[0] for r in rows).items()))}")

    out += ["", "First rows of class 5 with remote port 0 (listener-like), raw DWORDs in hex:",
            "  " + "  ".join(f"{w:>10}" for w in WORDS)]
    shown = 0
    for r in tables[5]:
        if r[4] == 0 and shown < 12:
            out.append("  " + "  ".join(f"{w:>#10x}" for w in r))
            shown += 1

    try:
        text = subprocess.run(["netstat", "-ano", "-p", "tcp"], capture_output=True,
                              text=True, check=True).stdout
        out += ["", f"netstat -ano -p tcp: {text.count('LISTENING')} LISTENING, "
                    f"{text.count('ESTABLISHED')} ESTABLISHED, {text.count('TIME_WAIT')} TIME_WAIT"]
    except Exception as e:               # noqa: BLE001 - diagnostic only
        out.append(f"netstat failed: {e}")

    report = "\n".join(out)
    OUTPUT_DIR.mkdir(exist_ok=True)
    (OUTPUT_DIR / "diagnose.txt").write_text(report + "\n", encoding="utf-8")
    print(report)
    print(f"\nSaved to {OUTPUT_DIR / 'diagnose.txt'}")
