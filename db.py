# ==========================================
# db.py
# ==========================================

import sqlite3
from datetime import datetime

DATABASE_NAME = "network_monitor.db"


# ------------------------------------------
# Create Database
# ------------------------------------------

def create_database():

    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    # Snapshot Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS snapshots(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        timestamp TEXT

    )
    """)

    # Connection Table
    cursor.execute("""
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

        process_name TEXT
    )
    """)

    conn.commit()
    conn.close()


# ------------------------------------------
# Save Snapshot
# ------------------------------------------

def save_snapshot():

    conn = sqlite3.connect(DATABASE_NAME)

    cursor = conn.cursor()

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    cursor.execute(

        """
        INSERT INTO snapshots(timestamp)
        VALUES(?)
        """,

        (timestamp,)
    )

    snapshot_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return snapshot_id


# ------------------------------------------
# Save Connections
# ------------------------------------------

def save_connections(snapshot_id, connections):

    conn = sqlite3.connect(DATABASE_NAME)

    cursor = conn.cursor()

    for c in connections:

        cursor.execute("""

        INSERT INTO connections(

            snapshot_id,

            protocol,

            local_address,

            local_port,

            remote_address,

            remote_port,

            state,

            pid,

            process_name

        )

        VALUES(?,?,?,?,?,?,?,?,?)

        """,

        (

            snapshot_id,

            c.protocol,

            c.local_address,

            c.local_port,

            c.remote_address,

            c.remote_port,

            c.state,

            c.pid,

            c.process_name

        ))

    conn.commit()

    conn.close()