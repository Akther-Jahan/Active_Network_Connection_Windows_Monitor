# ==========================================
# demo.py
# Guided "open a browser tab / close a browser tab" snapshot-diff demo
# ==========================================

import time

from collector import collect_all
from common import OUTPUT_DIR
from db import save_snapshot, diff_snapshots, format_diff


def _snap(conn, label):
    _, tcp, udp = collect_all()
    sid = save_snapshot(conn, tcp + udp, label=label)
    print(f"  -> snapshot #{sid} saved ({len(tcp)} TCP, {len(udp)} UDP)")
    return sid


def run_demo(conn, settle=10):
    print("\nSNAPSHOT DIFF DEMO - four snapshots around opening and closing a browser tab\n")
    input("1) Close extra browser tabs, then press Enter to take the BASELINE snapshot...")
    s1 = _snap(conn, "baseline")

    input("\n2) Open a NEW browser tab and load a website. When it has loaded, press Enter...")
    s2 = _snap(conn, "tab_open")

    input("\n3) Now CLOSE that tab and immediately press Enter...")
    s3 = _snap(conn, "tab_closed")

    print(f"\n4) Waiting {settle} s so teardown states (FIN_WAIT / TIME_WAIT) can settle...")
    time.sleep(settle)
    s4 = _snap(conn, f"tab_closed_plus_{settle}s")

    sections = []
    for title, a, b in (("OPENING the tab", s1, s2),
                        ("CLOSING the tab", s2, s3),
                        (f"{settle} seconds after closing", s3, s4)):
        d = diff_snapshots(conn, a, b)
        sections.append(f"\n##### {title} #####\n" + format_diff(d, verbose=True))

    text = "\n".join(sections)
    OUTPUT_DIR.mkdir(exist_ok=True)
    path = OUTPUT_DIR / "snapshot_diff_demo.txt"
    path.write_text(text + "\n", encoding="utf-8")
    print(text)
    print(f"\nDemo evidence saved to {path}")
    return path
