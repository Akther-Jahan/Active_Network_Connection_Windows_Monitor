# ==========================================
# common.py
# Shared constants, the two-call helper, decoders
# ==========================================

import ctypes
import ipaddress
import socket
import struct
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "network_monitor.db"
OUTPUT_DIR = BASE_DIR / "output"

AF_INET = 2
AF_INET6 = 23
# Fixed-width 32-bit type: identical to Windows' DWORD/ULONG, but also correct
# when the parsing code is unit-tested on Linux (where ctypes c_ulong is 64-bit).
DWORD = ctypes.c_uint32

NO_ERROR = 0
ERROR_INSUFFICIENT_BUFFER = 122


def fetch_table(func, family, table_class, retries=5, slack=4096):
    """
    The two-call pattern for a variable-length kernel structure.

    Call 1: null buffer -> the API fails with ERROR_INSUFFICIENT_BUFFER and
            writes the byte count it needs into `size`.
    Call 2: allocate that many bytes (+ slack, because the table can grow
            between the calls) and call again to fill the buffer.
    If call 2 still reports ERROR_INSUFFICIENT_BUFFER we retry with the new size.

    Returns (buffer, row_count). Rows start at byte offset 4 (after dwNumEntries).
    """
    size = DWORD(0)
    result = func(None, ctypes.byref(size), False, family, table_class, 0)
    if result not in (ERROR_INSUFFICIENT_BUFFER, NO_ERROR):
        raise ctypes.WinError(result)

    for _ in range(retries):
        buffer = ctypes.create_string_buffer(size.value + slack)
        size = DWORD(len(buffer))
        result = func(buffer, ctypes.byref(size), False, family, table_class, 0)
        if result == NO_ERROR:
            count = DWORD.from_buffer(buffer, 0).value
            return buffer, count
        if result != ERROR_INSUFFICIENT_BUFFER:
            raise ctypes.WinError(result)

    raise RuntimeError("Connection table kept growing; gave up after retries.")


def decode_ip(value):
    """Packed 32-bit integer (network byte order, read little-endian) -> dotted string."""
    return socket.inet_ntoa(struct.pack("<L", value))


def decode_port(value):
    """Port lives in the low 16 bits, network byte order."""
    return socket.ntohs(value & 0xFFFF)


def decode_ipv6(value, scope_id=0):
    """16-byte IPv6 address (+ optional interface scope) -> compressed string."""
    address = socket.inet_ntop(socket.AF_INET6, bytes(value))
    if scope_id:
        address = f"{address}%{scope_id}"
    return address


def format_endpoint(address, port):
    """IPv4 -> 1.2.3.4:80   IPv6 -> [::1]:80 (brackets remove the ':' ambiguity)."""
    if ":" in address:
        return f"[{address}]:{port}"
    return f"{address}:{port}"


def normalize_ip(text):
    """Canonical text form of an address so two tools can be compared."""
    base, sep, scope = text.partition("%")
    try:
        base = str(ipaddress.ip_address(base))
    except ValueError:
        return text            # '*' and other non-addresses stay as they are
    return base + (sep + scope if sep else "")
