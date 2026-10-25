# ==========================================
# tcp_table.py
# Part 1
# ==========================================

import ctypes
import socket
import struct

from ctypes import wintypes

from models import Connection


# ------------------------------------------
# Windows DLL
# ------------------------------------------

iphlpapi = ctypes.WinDLL("iphlpapi.dll")

AF_INET = 2

TCP_TABLE_OWNER_PID_ALL = 5

NO_ERROR = 0

ERROR_INSUFFICIENT_BUFFER = 122


# ------------------------------------------
# TCP STATE MAP
# ------------------------------------------

TCP_STATES = {

    1: "CLOSED",
    2: "LISTEN",
    3: "SYN_SENT",
    4: "SYN_RECEIVED",
    5: "ESTABLISHED",
    6: "FIN_WAIT_1",
    7: "FIN_WAIT_2",
    8: "CLOSE_WAIT",
    9: "CLOSING",
    10: "LAST_ACK",
    11: "TIME_WAIT",
    12: "DELETE_TCB"

}


# ------------------------------------------
# MIB_TCPROW_OWNER_PID
# ------------------------------------------

class MIB_TCPROW_OWNER_PID(ctypes.Structure):

    _fields_ = [

        ("dwState", wintypes.DWORD),

        ("dwLocalAddr", wintypes.DWORD),

        ("dwLocalPort", wintypes.DWORD),

        ("dwRemoteAddr", wintypes.DWORD),

        ("dwRemotePort", wintypes.DWORD),

        ("dwOwningPid", wintypes.DWORD)

    ]


# ------------------------------------------
# Dynamic Table Header
# ------------------------------------------

class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):

    _fields_ = [

        ("dwNumEntries", wintypes.DWORD),

        ("table", MIB_TCPROW_OWNER_PID * 1)

    ]


# ------------------------------------------
# Declare Windows API
# ------------------------------------------

GetExtendedTcpTable = iphlpapi.GetExtendedTcpTable

GetExtendedTcpTable.argtypes = [

    ctypes.c_void_p,
    ctypes.POINTER(wintypes.ULONG),
    wintypes.BOOL,
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.ULONG

]

GetExtendedTcpTable.restype = wintypes.DWORD

# ==========================================
# tcp_table.py
# Part 2
# ==========================================

def get_tcp_connections(process_map):

    size = wintypes.ULONG(0)

    # ------------------------------------------
    # First Call
    # Get required buffer size
    # ------------------------------------------

    result = GetExtendedTcpTable(

        None,
        ctypes.byref(size),
        False,
        AF_INET,
        TCP_TABLE_OWNER_PID_ALL,
        0

    )

    if result != ERROR_INSUFFICIENT_BUFFER:
        raise ctypes.WinError(result)

    # ------------------------------------------
    # Allocate Buffer
    # ------------------------------------------

    buffer = ctypes.create_string_buffer(size.value)

    # ------------------------------------------
    # Second Call
    # Read Kernel TCP Table
    # ------------------------------------------

    result = GetExtendedTcpTable(

        buffer,
        ctypes.byref(size),
        False,
        AF_INET,
        TCP_TABLE_OWNER_PID_ALL,
        0

    )

    if result != NO_ERROR:
        raise ctypes.WinError(result)

    # ------------------------------------------
    # Cast Buffer
    # ------------------------------------------

    table = ctypes.cast(
        buffer,
        ctypes.POINTER(MIB_TCPTABLE_OWNER_PID)
    ).contents

    num_entries = table.dwNumEntries

    # ------------------------------------------
    # Pointer to First Row
    # ------------------------------------------

    row_ptr = ctypes.cast(

        ctypes.addressof(buffer)
        + ctypes.sizeof(wintypes.DWORD),

        ctypes.POINTER(MIB_TCPROW_OWNER_PID)

    )

    
    connections = []

    # Decode every TCP row
    for i in range(num_entries):

        row = row_ptr[i]

        # 1. Decode local IP address
        local_ip = socket.inet_ntoa(
            struct.pack("<L", row.dwLocalAddr)
        )

        # 2. Decode remote IP address
        remote_ip = socket.inet_ntoa(
            struct.pack("<L", row.dwRemoteAddr)
        )

        # 3. Decode port numbers
        local_port = socket.ntohs(
            row.dwLocalPort & 0xFFFF
        )

        remote_port = socket.ntohs(
            row.dwRemotePort & 0xFFFF
        )

        # 4. Convert numeric TCP state to readable text
        state = TCP_STATES.get(
            row.dwState,
            "UNKNOWN"
        )

        # 5. Get process ID
        pid = row.dwOwningPid

        # 6. Find process name using PID
        process_name = process_map.get(
            pid,
            "Unknown"
        )

        # 7. Create a Connection object
        conn = Connection(
            protocol="TCP",
            local_address=local_ip,
            local_port=local_port,
            remote_address=remote_ip,
            remote_port=remote_port,
            state=state,
            pid=pid,
            process_name=process_name
        )

        # 8. Add this connection to the list
        connections.append(conn)

    # Return only after processing every row
    return connections
 
    # ------------------------------------------
    # Decode Every Row
    # ------------------------------------------

    for i in range(num_entries):

        row = row_ptr[i]

        # Local IP Address
        local_ip = socket.inet_ntoa(
            struct.pack("<L", row.dwLocalAddr)
        )

        # Remote IP Address
        remote_ip = socket.inet_ntoa(
            struct.pack("<L", row.dwRemoteAddr)
        )

        # Convert Network Byte Order Port -> Host Order
        local_port = socket.ntohs(row.dwLocalPort & 0xFFFF)
        remote_port = socket.ntohs(row.dwRemotePort & 0xFFFF)

        # TCP State
        state = TCP_STATES.get(
            row.dwState,
            "UNKNOWN"
        )

        # PID
        pid = row.dwOwningPid

        # Process Name
        process_name = process_map.get(
            pid,
            "Unknown"
        )

        # Create Connection Object
        conn = Connection(

            protocol="TCP",

            local_address=local_ip,
            local_port=local_port,

            remote_address=remote_ip,
            remote_port=remote_port,

            state=state,

            pid=pid,
            process_name=process_name

        )

        connections.append(conn)

    return connections


