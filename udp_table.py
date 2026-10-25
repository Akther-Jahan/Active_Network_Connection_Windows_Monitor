# ==========================================
# udp_table.py
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

UDP_TABLE_OWNER_PID = 1

NO_ERROR = 0

ERROR_INSUFFICIENT_BUFFER = 122


# ------------------------------------------
# MIB_UDPROW_OWNER_PID
# ------------------------------------------

class MIB_UDPROW_OWNER_PID(ctypes.Structure):

    _fields_ = [

        ("dwLocalAddr", wintypes.DWORD),

        ("dwLocalPort", wintypes.DWORD),

        ("dwOwningPid", wintypes.DWORD)

    ]


# ------------------------------------------
# UDP Table Header
# ------------------------------------------

class MIB_UDPTABLE_OWNER_PID(ctypes.Structure):

    _fields_ = [

        ("dwNumEntries", wintypes.DWORD),

        ("table", MIB_UDPROW_OWNER_PID * 1)

    ]


# ------------------------------------------
# Declare Windows API
# ------------------------------------------

GetExtendedUdpTable = iphlpapi.GetExtendedUdpTable

GetExtendedUdpTable.argtypes = [

    ctypes.c_void_p,
    ctypes.POINTER(wintypes.ULONG),
    wintypes.BOOL,
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.ULONG

]

GetExtendedUdpTable.restype = wintypes.DWORD

# ==========================================
# udp_table.py
# Part 2
# ==========================================

def get_udp_connections(process_map):

    size = wintypes.ULONG(0)

    # ------------------------------------------
    # First Call
    # Get Required Buffer Size
    # ------------------------------------------

    result = GetExtendedUdpTable(

        None,
        ctypes.byref(size),
        False,
        AF_INET,
        UDP_TABLE_OWNER_PID,
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
    # Read UDP Table
    # ------------------------------------------

    result = GetExtendedUdpTable(

        buffer,
        ctypes.byref(size),
        False,
        AF_INET,
        UDP_TABLE_OWNER_PID,
        0

    )

    if result != NO_ERROR:
        raise ctypes.WinError(result)

    # ------------------------------------------
    # Read Header
    # ------------------------------------------

    table = ctypes.cast(

        buffer,

        ctypes.POINTER(
            MIB_UDPTABLE_OWNER_PID
        )

    ).contents

    num_entries = table.dwNumEntries

    # ------------------------------------------
    # First Row Pointer
    # ------------------------------------------

    row_ptr = ctypes.cast(

        ctypes.addressof(buffer)
        + ctypes.sizeof(wintypes.DWORD),

        ctypes.POINTER(
            MIB_UDPROW_OWNER_PID
        )

    )

    connections = []

    # ------------------------------------------
    # Parse Every UDP Row
    # ------------------------------------------

    for i in range(num_entries):

        row = row_ptr[i]

        local_ip = socket.inet_ntoa(
            struct.pack("<L", row.dwLocalAddr)
        )

        local_port = socket.ntohs(
            row.dwLocalPort & 0xFFFF
        )

        pid = row.dwOwningPid

        process_name = process_map.get(
            pid,
            "Unknown"
        )

        conn = Connection(

            protocol="UDP",

            local_address=local_ip,
            local_port=local_port,

            remote_address="*",
            remote_port=0,

            state="NONE",

            pid=pid,
            process_name=process_name

        )

        connections.append(conn)

    return connections
