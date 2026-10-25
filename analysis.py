# ==========================================
# analysis.py
# ==========================================

import sqlite3
import pandas as pd
import matplotlib.pyplot as plt

DATABASE_NAME = "network_monitor.db"


# ------------------------------------------
# Load Data
# -----------------------------------------

def load_data():

    conn = sqlite3.connect(DATABASE_NAME)

    query = """
        SELECT *
        FROM connections
        WHERE snapshot_id = (
            SELECT MAX(id)
            FROM snapshots
        )
    """

    df = pd.read_sql_query(query, conn)

    conn.close()

    return df



# ------------------------------------------
# Connections Per Process
# ------------------------------------------

def connections_per_process():

    df = load_data()

    if df.empty:

        print("No data available.")

        return

    result = (

        df.groupby("process_name")

        .size()

        .sort_values(ascending=False)

        .head(10)

    )

    plt.figure(figsize=(10,6))

    result.plot(kind="bar")

    plt.title("Top Processes by Connection Count")

    plt.xlabel("Process Name")

    plt.ylabel("Connections")

    plt.tight_layout()

    plt.savefig("connections_per_process.png")

    plt.show()


# ------------------------------------------
# TCP State Distribution
# ------------------------------------------

def tcp_state_distribution():

    df = load_data()

    if df.empty:

        print("No data available.")

        return

    tcp = df[df["protocol"] == "TCP"]

    result = (

        tcp.groupby("state")

        .size()

    )

    plt.figure(figsize=(8,5))

    result.plot(kind="bar")

    plt.title("TCP State Distribution")

    plt.xlabel("TCP State")

    plt.ylabel("Count")

    plt.tight_layout()

    plt.savefig("tcp_state_distribution.png")

    plt.show()


# ------------------------------------------
# Summary Report
# ------------------------------------------

def summary_report():

    df = load_data()

    print("=" * 50)

    print("SUMMARY REPORT")

    print("=" * 50)

    print()

    print("Total Connections :", len(df))

    print("TCP Connections   :",

          len(df[df.protocol == "TCP"]))

    print("UDP Connections   :",

          len(df[df.protocol == "UDP"]))

    print()

    print("Top 10 Processes")

    print(

        df["process_name"]

        .value_counts()

        .head(10)

    )