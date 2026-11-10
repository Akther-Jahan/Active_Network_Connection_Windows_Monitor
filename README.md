# Active Network Connections Monitor (Windows, IPv4 + IPv6)

A `netstat` clone that reads the kernel's TCP and UDP connection tables directly through
`iphlpapi.dll` (`GetExtendedTcpTable`, `GetExtendedUdpTable`) with raw `ctypes` - no
Windows-binding package. Each owning PID is resolved to a process name through a Toolhelp
snapshot, every run is stored in SQLite, and snapshots can be diffed.

**Requirements:** Windows 10/11, Python 3.10+, `pip install -r requirements.txt`
(pandas, matplotlib). No administrator rights needed.

## Quick start

```
python main.py                     # snapshot, print, save, diff vs previous, charts, interpretation
python main.py --quiet --csv       # less console output + CSV export
python main.py --resolve --csv     # also reverse-DNS remote addresses (extension)
python main.py --netstat-check     # cross-check against netstat -ano  -> output/netstat_check_*.txt
python main.py --demo              # guided browser-tab before/after demo -> output/snapshot_diff_demo.txt
python main.py --lifecycle         # own loopback connection: LISTEN -> ESTABLISHED -> FIN_WAIT_2/CLOSE_WAIT -> TIME_WAIT
python main.py --live              # redrawing console view, every 2 s (--live 1 --filter chrome)
python main.py --watch 2           # snapshot every 2 s into the DB, print the diff each time
python main.py --list              # stored snapshots
python main.py --diff 3 4          # diff any two stored snapshots
python main.py --report 4          # charts + interpretation for a stored snapshot
python main.py --prune 50          # keep only the newest 50 snapshots
python web.py                      # browser dashboard on http://127.0.0.1:8000 (Snapshot + Timeline views)
python -m unittest discover tests  # unit tests (run on any OS)
```

## Requirements checklist

| Requirement | Where |
|---|---|
| TCP table reader, two-call pattern | `common.fetch_table`, `tcp_table.py` |
| UDP table reader (no state / no remote) | `udp_table.py` |
| Decode addresses, ports, state | `common.decode_*`, `tcp_table.TCP_STATES` |
| PID -> process name (Toolhelp) | `process_resolver.py` |
| OOP model | `models.Connection` |
| SQLite persistence with timestamps | `db.py` |
| Snapshot diff | `db.diff_snapshots` / `format_diff` |
| pandas summaries + 2 bar charts + written interpretation | `analysis.py` (interpretation is generated from the real numbers) |
| Live snapshot output + cross-check vs `netstat -ano` | `main.py` (console/CSV), `netstat_check.py` |
| Snapshot diff demo (open/close a tab) | `demo.py` |
| Design write-up | below |
| Ext.: IPv6 | `MIB_TCP6ROW_OWNER_PID`, `MIB_UDP6ROW_OWNER_PID`, `parse_tcp6/udp6` |
| Ext.: live refreshing view | `live.py` |
| Ext.: reverse DNS | `enrich.py` (cached in SQLite) |
| Ext.: C++ track | not included |

## Producing the deliverables

1. **Live snapshot + netstat cross-check:** `python main.py --csv`, then
   `python main.py --netstat-check`. The report shows how many rows are identical and lists
   rows found by only one side. A few ephemeral-port rows always differ because the two reads
   are milliseconds apart.
2. **Diff demo:** `python main.py --demo` and follow the prompts. It takes four labelled
   snapshots (baseline, tab open, tab closed, closed + 10 s) and writes all three diffs to
   `output/snapshot_diff_demo.txt`.
3. **Charts + interpretation:** `python main.py` writes `connections_per_process_N.png`,
   `tcp_state_distribution_N.png` and `interpretation_N.md`. Paste or adapt the interpretation
   into your report.
4. **Live TCP state machine:** `python main.py --live 1 --filter msedge`, then open and close
   a tab and watch `NEW -> SYN_SENT`, `CHANGE SYN_SENT -> ESTABLISHED`, later `FIN_WAIT` /
   `TIME_WAIT` and `GONE`.

The tool prints a `[warn]` line if any TCP row has an unrecognised state or no LISTEN socket
exists - the signature of a mis-decoded table. A healthy run has `UNKNOWN = 0`.

## Design write-up

**Two-call sizing pattern.** The number of connections changes constantly, so the kernel cannot
return a fixed-size structure. The first call passes a null buffer; the API fails with
`ERROR_INSUFFICIENT_BUFFER` and writes the needed byte count into the size argument. We allocate
that many bytes plus slack and call again to fill the buffer. Because the table can grow between
the calls, the second call sits in a retry loop. The same pattern appears throughout Win32
wherever a kernel structure's size is unknown in advance.

**TCP vs UDP tables.** A TCP row (`MIB_TCPROW_OWNER_PID`, 24 bytes) holds state, local
address/port, remote address/port and owning PID, because a TCP connection is a stateful
relationship between two endpoints. A UDP row (`MIB_UDPROW_OWNER_PID`, 12 bytes) holds only
local address, local port and PID: UDP is connectionless, so there is no remote endpoint and no
state. The tool stores `*`, `0` and `NONE` for those columns. The IPv6 rows (56 and 28 bytes)
replace the 32-bit address with a 16-byte address plus a scope ID for each address.

**PID-based ownership resolution.** The connection tables contain only a PID. Names live in a
different kernel subsystem, the process manager. The tool takes one `CreateToolhelp32Snapshot`
per run, walks it with `Process32FirstW/NextW` into a `{pid: name}` dictionary and joins every
connection row against it. The network stack and the process manager are independent; the PID is
the only shared key. Sockets whose owner exited between the two reads, or that belong to a process
Toolhelp cannot see, show as `Unknown`. PID 0 owns `TIME_WAIT` rows (the kernel itself) and is
shown as `System Idle Process`.

**Decoding.** IPv4 addresses are 32-bit integers in network byte order, read little-endian on
x86, so they are unpacked with `struct.pack("<L", ...)`. Ports sit in the low 16 bits in network
byte order: mask with `0xFFFF`, then `ntohs`. Structures use fixed-width `c_uint32` fields, which
equal Windows' `DWORD`.

## Testing note

The unit tests cover decoding, the two-call/retry logic, parsing of hand-built IPv4/IPv6/UDP
table buffers, diffing, the SQLite round trip, charts, and the netstat parser; they run on any OS.
Calling the real Windows APIs can only be verified on Windows, so run `python main.py` and
`python main.py --netstat-check` there and keep the output as your evidence.

## Web dashboard (`python web.py`)

* **Snapshot view** - cards, top processes, TCP state bars, and the connection table with
  Added / Removed / State-changes tabs against the previous snapshot.
* **Timeline view** - TCP connections over time across the last 10-200 snapshots:
  * *Playback*: slider / play button steps through snapshots and lists the new, gone and
    state-changed connections at each step; "Open full details" jumps to that snapshot.
  * *State counts over time* and *Churn between snapshots* charts.
  * *Connection life lines*: one row per connection, one column per snapshot, coloured by TCP
    state, so a connection is seen moving `SYN_SENT -> ESTABLISHED -> CLOSE_WAIT -> TIME_WAIT -> gone`.
    Filter by text or state, hide listeners, or show only connections that changed.
* Use "Take new snapshot" or the auto-refresh selector to add snapshots while you watch
  (open a browser tab and watch its connection appear). Snapshots saved by older versions of
  this project may contain wrongly decoded states; delete `network_monitor.db` for a clean timeline.

## Windows-build quirk: listener states

On some Windows builds (observed on Insider build 26300) the kernel reports a garbage `dwState`
(0, 1, 6 ...) for LISTEN sockets, even in the listener-only table, and `netstat` shows the same
oddity (it printed only 3 LISTENING rows while the table held 16 listeners). `python main.py
--diagnose` dumps the raw values. Because the table *class* is reliable, `tcp_table.py` reads
listeners from the LISTENER table (labelled LISTEN) and everything else from the CONNECTIONS table,
and prints an `[info]` line when the raw value disagreed. `--netstat-check` treats a netstat row
with remote `0.0.0.0:0` / `[::]:0` as a listener for the same reason. ESTABLISHED and TIME_WAIT
counts matched netstat exactly on that machine.

## Known limitations

- Point-in-time reads: very short-lived connections can be missed or differ from netstat.
- The diff key includes the local port, so ephemeral ports make raw diffs noisy; the grouped
  summary at the bottom of each diff is the readable view.
- Process names come from Toolhelp (executable name only, no path).
