# ==========================================
# enrich.py
# Extension: reverse DNS for remote addresses (cached in SQLite)
# ==========================================

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import datetime


def _is_public(ip):
    try:
        a = ipaddress.ip_address(ip.partition("%")[0])
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_unspecified
                or a.is_link_local or a.is_multicast)


def _lookup(ip):
    try:
        return socket.gethostbyaddr(ip.partition("%")[0])[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def resolve_many(conn, ips, timeout=3.0, workers=16):
    """
    {ip: hostname}. Private/loopback addresses are skipped (no point asking DNS),
    results (including failures) are cached in the dns_cache table.
    """
    ips = {ip for ip in ips if ip and ip not in ("*", "0.0.0.0", "::")}
    result = {}
    todo = []

    for ip in ips:
        if not _is_public(ip):
            result[ip] = "(local network)"
            continue
        row = conn.execute("SELECT hostname FROM dns_cache WHERE ip=?", (ip,)).fetchone()
        if row is not None:
            result[ip] = row[0]
        else:
            todo.append(ip)

    if todo:
        pool = ThreadPoolExecutor(max_workers=workers)
        futures = {ip: pool.submit(_lookup, ip) for ip in todo}
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with conn:
            for ip, fut in futures.items():
                try:
                    host = fut.result(timeout=timeout)
                except FutureTimeout:
                    host = ""
                result[ip] = host
                conn.execute("INSERT OR REPLACE INTO dns_cache VALUES(?,?,?)", (ip, host, now))
        pool.shutdown(wait=False, cancel_futures=True)

    return result
