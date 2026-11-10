# ==========================================
# collector.py
# One call that gathers a full, self-consistent snapshot
# ==========================================

def collect_all():
    """Return (process_map, tcp_connections, udp_connections). Windows only."""
    from process_resolver import build_process_map
    from tcp_table import get_tcp_connections
    from udp_table import get_udp_connections

    process_map = build_process_map()
    tcp = get_tcp_connections(process_map)
    udp = get_udp_connections(process_map)
    return process_map, tcp, udp


def sanity_warnings(tcp):
    """Cheap self-checks that catch a mis-decoded table (e.g. wrong struct layout)."""
    warnings = []
    unknown = sum(1 for c in tcp if c.state == "UNKNOWN")
    if unknown:
        warnings.append(f"{unknown} TCP rows have an unrecognised state code - "
                        "the row structure may be mis-decoded.")
    if tcp and not any(c.is_listener for c in tcp):
        warnings.append("No LISTEN sockets found; a normal Windows machine always has some.")
    return warnings
