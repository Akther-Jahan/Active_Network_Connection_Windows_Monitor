# ==========================================
# udp_table.py
# IPv4 + IPv6 UDP tables via GetExtendedUdpTable
# UDP rows have NO remote endpoint and NO state (connectionless).
# ==========================================

import ctypes
import sys
from ctypes import wintypes

from common import DWORD, AF_INET, AF_INET6, fetch_table, decode_ip, decode_ipv6, decode_port
from models import Connection

UDP_TABLE_OWNER_PID = 1


class MIB_UDPROW_OWNER_PID(ctypes.Structure):          # 12 bytes
    _fields_ = [
        ("dwLocalAddr", DWORD),
        ("dwLocalPort", DWORD),
        ("dwOwningPid", DWORD),
    ]


class MIB_UDP6ROW_OWNER_PID(ctypes.Structure):         # 28 bytes
    _fields_ = [
        ("ucLocalAddr", ctypes.c_ubyte * 16),
        ("dwLocalScopeId", DWORD),
        ("dwLocalPort", DWORD),
        ("dwOwningPid", DWORD),
    ]


def _load():
    if sys.platform != "win32":
        return None
    fn = ctypes.WinDLL("iphlpapi.dll").GetExtendedUdpTable
    fn.argtypes = [ctypes.c_void_p, ctypes.POINTER(DWORD), wintypes.BOOL,
                   DWORD, DWORD, DWORD]
    fn.restype = DWORD
    return fn


GetExtendedUdpTable = _load()


def parse_udp4(buffer, count, process_map):
    if count == 0:
        return []
    rows = (MIB_UDPROW_OWNER_PID * count).from_buffer(buffer, ctypes.sizeof(DWORD))
    return [Connection(
        protocol="UDP",
        local_address=decode_ip(r.dwLocalAddr), local_port=decode_port(r.dwLocalPort),
        remote_address="*", remote_port=0, state="NONE",
        pid=r.dwOwningPid, process_name=process_map.get(r.dwOwningPid, "Unknown"),
        ip_version=4) for r in rows]


def parse_udp6(buffer, count, process_map):
    if count == 0:
        return []
    rows = (MIB_UDP6ROW_OWNER_PID * count).from_buffer(buffer, ctypes.sizeof(DWORD))
    return [Connection(
        protocol="UDP",
        local_address=decode_ipv6(r.ucLocalAddr, r.dwLocalScopeId),
        local_port=decode_port(r.dwLocalPort),
        remote_address="*", remote_port=0, state="NONE",
        pid=r.dwOwningPid, process_name=process_map.get(r.dwOwningPid, "Unknown"),
        ip_version=6) for r in rows]


def get_udp_connections(process_map):
    connections = []

    buffer, count = fetch_table(GetExtendedUdpTable, AF_INET, UDP_TABLE_OWNER_PID)
    connections += parse_udp4(buffer, count, process_map)

    try:
        buffer, count = fetch_table(GetExtendedUdpTable, AF_INET6, UDP_TABLE_OWNER_PID)
        connections += parse_udp6(buffer, count, process_map)
    except OSError as e:
        print(f"[warn] IPv6 UDP table unavailable: {e}", file=sys.stderr)

    return connections
