# ==========================================
# tcp_table.py
# IPv4 + IPv6 TCP tables via GetExtendedTcpTable
# ==========================================

import ctypes
import sys
from ctypes import wintypes

from common import DWORD, AF_INET, AF_INET6, fetch_table, decode_ip, decode_ipv6, decode_port
from models import Connection

TCP_TABLE_OWNER_PID_LISTENER = 3      # listening sockets only (by definition)
TCP_TABLE_OWNER_PID_CONNECTIONS = 4   # everything that is not a listener
TCP_TABLE_OWNER_PID_ALL = 5           # kept for reference / --diagnose

# Some Windows builds (seen on Insider build 26300) put garbage such as 0, 1 or 6 into dwState
# for LISTEN sockets in the ALL table; even the LISTENER table returns them. The table CLASS is
# reliable, so rows from the LISTENER table are labelled LISTEN. This counts how often the raw
# value disagreed, so the tool can say so instead of hiding it.
LISTENER_RAW_ANOMALIES = 0

# MIB_TCP_STATE values from the Windows headers
TCP_STATES = {
    1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RECEIVED",
    5: "ESTABLISHED", 6: "FIN_WAIT_1", 7: "FIN_WAIT_2", 8: "CLOSE_WAIT",
    9: "CLOSING", 10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB",
}


class MIB_TCPROW_OWNER_PID(ctypes.Structure):          # 24 bytes
    _fields_ = [
        ("dwState", DWORD),
        ("dwLocalAddr", DWORD),
        ("dwLocalPort", DWORD),
        ("dwRemoteAddr", DWORD),
        ("dwRemotePort", DWORD),
        ("dwOwningPid", DWORD),
    ]


class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):         # 56 bytes
    _fields_ = [
        ("ucLocalAddr", ctypes.c_ubyte * 16),
        ("dwLocalScopeId", DWORD),
        ("dwLocalPort", DWORD),
        ("ucRemoteAddr", ctypes.c_ubyte * 16),
        ("dwRemoteScopeId", DWORD),
        ("dwRemotePort", DWORD),
        ("dwState", DWORD),
        ("dwOwningPid", DWORD),
    ]


def _load():
    if sys.platform != "win32":
        return None
    fn = ctypes.WinDLL("iphlpapi.dll").GetExtendedTcpTable
    fn.argtypes = [ctypes.c_void_p, ctypes.POINTER(DWORD), wintypes.BOOL,
                   DWORD, DWORD, DWORD]
    fn.restype = DWORD
    return fn


GetExtendedTcpTable = _load()


def _state(raw, force_state):
    """Raw dwState -> name. force_state is set for rows of the LISTENER table."""
    global LISTENER_RAW_ANOMALIES
    if force_state:
        if raw != 2:
            LISTENER_RAW_ANOMALIES += 1
        return force_state
    return TCP_STATES.get(raw, "UNKNOWN")


def parse_tcp4(buffer, count, process_map, force_state=None):
    """Turn a MIB_TCPTABLE_OWNER_PID buffer into Connection objects."""
    if count == 0:
        return []
    rows = (MIB_TCPROW_OWNER_PID * count).from_buffer(buffer, ctypes.sizeof(DWORD))
    return [Connection(
        protocol="TCP",
        local_address=decode_ip(r.dwLocalAddr), local_port=decode_port(r.dwLocalPort),
        remote_address=decode_ip(r.dwRemoteAddr), remote_port=decode_port(r.dwRemotePort),
        state=_state(r.dwState, force_state),
        pid=r.dwOwningPid, process_name=process_map.get(r.dwOwningPid, "Unknown"),
        ip_version=4) for r in rows]


def parse_tcp6(buffer, count, process_map, force_state=None):
    """Turn a MIB_TCP6TABLE_OWNER_PID buffer into Connection objects."""
    if count == 0:
        return []
    rows = (MIB_TCP6ROW_OWNER_PID * count).from_buffer(buffer, ctypes.sizeof(DWORD))
    return [Connection(
        protocol="TCP",
        local_address=decode_ipv6(r.ucLocalAddr, r.dwLocalScopeId),
        local_port=decode_port(r.dwLocalPort),
        remote_address=decode_ipv6(r.ucRemoteAddr, r.dwRemoteScopeId),
        remote_port=decode_port(r.dwRemotePort),
        state=_state(r.dwState, force_state),
        pid=r.dwOwningPid, process_name=process_map.get(r.dwOwningPid, "Unknown"),
        ip_version=6) for r in rows]


def get_tcp_connections(process_map):
    """
    Listeners come from the LISTENER table, everything else from the CONNECTIONS table.
    Together they hold exactly the same rows as the ALL table, but the state of a listener
    no longer depends on the raw dwState value (see LISTENER_RAW_ANOMALIES).
    """
    connections = []
    for family, parse in ((AF_INET, parse_tcp4), (AF_INET6, parse_tcp6)):
        try:
            for table_class, force in ((TCP_TABLE_OWNER_PID_LISTENER, "LISTEN"),
                                       (TCP_TABLE_OWNER_PID_CONNECTIONS, None)):
                buffer, count = fetch_table(GetExtendedTcpTable, family, table_class)
                connections += parse(buffer, count, process_map, force)
        except OSError as e:
            if family == AF_INET:
                raise
            print(f"[warn] IPv6 TCP table unavailable: {e}", file=sys.stderr)   # IPv6 may be disabled
    return connections
