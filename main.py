# ==========================================
# main.py
# Active Network Connections Monitor
# ==========================================

from tcp_table import get_tcp_connections
from udp_table import get_udp_connections
from process_resolver import build_process_map

from db import (
    create_database,
    save_snapshot,
    save_connections
)

from analysis import (
    summary_report,
    connections_per_process,
    tcp_state_distribution
)


def print_connections(title, connections):

    print("\n" + "=" * 100)
    print(title)
    print("=" * 100)

    for connection in connections:
        print(connection)


def main():

    print("=" * 100)
    print("ACTIVE NETWORK CONNECTIONS MONITOR")
    print("=" * 100)

    # --------------------------------------
    # Build PID -> Process Name Map
    # --------------------------------------

    print("\nLoading Process List...")

    process_map = build_process_map()

    print(f"Processes Loaded : {len(process_map)}")

    # --------------------------------------
    # Read TCP Connections
    # --------------------------------------

    print("\nReading TCP Connections...")

    tcp_connections = get_tcp_connections(process_map)

    print(f"TCP Connections : {len(tcp_connections)}")

    # --------------------------------------
    # Read UDP Connections
    # --------------------------------------

    print("\nReading UDP Connections...")

    udp_connections = get_udp_connections(process_map)

    print(f"UDP Connections : {len(udp_connections)}")

    # --------------------------------------
    # Print Connections
    # --------------------------------------

    print_connections("TCP CONNECTIONS", tcp_connections)

    print_connections("UDP CONNECTIONS", udp_connections)

    # --------------------------------------
    # Database
    # --------------------------------------

    print("\nSaving Snapshot to SQLite...")

    create_database()

    snapshot_id = save_snapshot()

    save_connections(snapshot_id, tcp_connections)

    save_connections(snapshot_id, udp_connections)

    print("Snapshot Saved Successfully.")

    # --------------------------------------
    # Analysis
    # --------------------------------------

    print("\nGenerating Analysis...")

    summary_report()

    connections_per_process()

    tcp_state_distribution()

    print("\nAll Tasks Completed Successfully.")


if __name__ == "__main__":
    main()