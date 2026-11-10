# ==========================================
# main.py
# Active Network Connections Monitor (IPv4 + IPv6)
# ==========================================

import argparse
import sys
import time

from common import OUTPUT_DIR

WINDOWS_ONLY = ("live", "demo", "netstat_check", "watch")


def take_snapshot(conn, args):
    from collector import collect_all, sanity_warnings
    from db import save_snapshot

    process_map, tcp, udp = collect_all()
    print(f"Processes: {len(process_map)} | TCP: {len(tcp)} | UDP: {len(udp)} | "
          f"IPv6 rows: {sum(c.ip_version == 6 for c in tcp + udp)}")
    for w in sanity_warnings(tcp):
        print(f"[warn] {w}")
    import tcp_table
    if tcp_table.LISTENER_RAW_ANOMALIES:
        print(f"[info] {tcp_table.LISTENER_RAW_ANOMALIES} listener row(s) carried a raw state other "
              "than LISTEN (a quirk of some Windows builds; netstat shows it too). They were "
              "labelled LISTEN because they come from the kernel's LISTENER table.")

    if not args.quiet:
        for title, rows in (("TCP CONNECTIONS", tcp), ("UDP ENDPOINTS", udp)):
            print("\n" + "=" * 110 + f"\n{title}\n" + "=" * 110)
            for c in rows:
                print(c)

    return save_snapshot(conn, tcp + udp)


def remote_hosts(conn, snapshot_id):
    """Reverse-DNS every remote address in a snapshot (extension)."""
    from enrich import resolve_many
    ips = {r[0] for r in conn.execute(
        "SELECT DISTINCT remote_address FROM connections WHERE snapshot_id=?", (snapshot_id,))}
    return resolve_many(conn, ips)


def build_parser():
    p = argparse.ArgumentParser(description="Active Network Connections Monitor (IPv4 + IPv6)")
    p.add_argument("--no-diff", action="store_true", help="skip snapshot comparison")
    p.add_argument("--no-plots", action="store_true", help="skip charts")
    p.add_argument("--show", action="store_true", help="open chart windows (blocks)")
    p.add_argument("--csv", action="store_true", help="export snapshot to CSV")
    p.add_argument("--quiet", action="store_true", help="do not print every connection")
    p.add_argument("--resolve", action="store_true", help="reverse-DNS remote addresses")
    p.add_argument("--watch", type=float, metavar="SECONDS",
                   help="snapshot every N seconds, save to DB and print the diff")
    p.add_argument("--live", type=float, nargs="?", const=2.0, metavar="SECONDS",
                   help="redrawing live console view (default every 2 s)")
    p.add_argument("--filter", metavar="NAME", help="with --live: only processes containing NAME")
    p.add_argument("--demo", action="store_true", help="guided browser-tab snapshot-diff demo")
    p.add_argument("--lifecycle", action="store_true",
                   help="demo: watch a connection go LISTEN/ESTABLISHED/FIN_WAIT/TIME_WAIT")
    p.add_argument("--netstat-check", action="store_true", help="cross-check against netstat -ano")
    p.add_argument("--diagnose", action="store_true", help="dump raw kernel state values")
    p.add_argument("--list", action="store_true", help="list stored snapshots and exit")
    p.add_argument("--diff", nargs=2, type=int, metavar=("OLD_ID", "NEW_ID"),
                   help="diff two stored snapshots and exit")
    p.add_argument("--report", type=int, metavar="ID",
                   help="charts + interpretation for a stored snapshot and exit")
    p.add_argument("--prune", type=int, metavar="N", help="keep only the newest N snapshots")
    return p


def main():
    args = build_parser().parse_args()

    needs_windows = (args.live is not None or args.diagnose or args.lifecycle or args.demo or args.netstat_check or args.watch
                     or not (args.list or args.diff or args.report or args.prune))
    if needs_windows and sys.platform != "win32":
        sys.exit("This tool reads Windows kernel tables and only runs on Windows.\n"
                 "(--list, --diff, --report and --prune work on stored data anywhere.)")

    import analysis
    from db import (connect, create_database, diff_snapshots, format_diff,
                    export_csv, list_snapshots, prune)

    if args.live is not None:
        from live import run_live
        try:
            run_live(args.live, args.filter)
        except KeyboardInterrupt:
            print("\nStopped.")
        return

    if args.lifecycle:
        import lifecycle_demo
        lifecycle_demo.run()
        return

    if args.diagnose:
        from diagnose import run
        run()
        return

    if args.netstat_check:
        from netstat_check import run_check
        try:
            path, report, _ = run_check()
        except OSError as e:
            sys.exit(f"Failed: {e}")
        print(report)
        print(f"\nReport saved to {path}")
        return

    conn = connect()
    create_database(conn)

    try:
        if args.list:
            print(f"{'id':>4}  {'timestamp':19}  {'rows':>5}  label")
            for sid, ts, label, n in list_snapshots(conn):
                print(f"{sid:>4}  {ts:19}  {n:>5}  {label}")
            return

        if args.diff:
            d = diff_snapshots(conn, *args.diff)
            print(format_diff(d) if d else "Unknown snapshot id.")
            return

        if args.report:
            analysis.summary_report(conn, args.report)
            print("Charts:", analysis.connections_per_process(conn, args.report),
                  analysis.tcp_state_distribution(conn, args.report))
            print("Interpretation:", analysis.write_interpretation(conn, args.report))
            return

        if args.prune:
            print(f"Deleted {prune(conn, args.prune)} old snapshot(s).")
            return

        if args.demo:
            from demo import run_demo
            run_demo(conn)
            return

        if args.watch:
            args.quiet = True
            while True:
                take_snapshot(conn, args)
                d = diff_snapshots(conn)
                if d:
                    print(format_diff(d, verbose=False))
                time.sleep(args.watch)

        snapshot_id = take_snapshot(conn, args)
        print(f"\nSnapshot {snapshot_id} saved.")

        hosts = remote_hosts(conn, snapshot_id) if args.resolve else None

        if args.csv:
            OUTPUT_DIR.mkdir(exist_ok=True)
            print("CSV written:", export_csv(conn, snapshot_id,
                  OUTPUT_DIR / f"snapshot_{snapshot_id}.csv", hosts))

        if not args.no_diff:
            d = diff_snapshots(conn)
            print(format_diff(d, hosts=hosts) if d else "Not enough snapshots to compare.")

        analysis.summary_report(conn, snapshot_id)

        if not args.no_plots:
            analysis.connections_per_process(conn, snapshot_id, show=args.show)
            analysis.tcp_state_distribution(conn, snapshot_id, show=args.show)
            print("Interpretation:", analysis.write_interpretation(conn, snapshot_id))
            print(f"Charts saved in {OUTPUT_DIR}")

    except KeyboardInterrupt:
        print("\nStopped.")
    except OSError as e:
        sys.exit(f"Windows API call failed: {e}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
