"""Platform-independent tests: decoding, two-call pattern, struct parsing,
diffing, netstat parsing, DB round-trip, charts. Run: python -m unittest discover tests"""

import ctypes
import os
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("MPLBACKEND", "Agg")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import common
import db
import netstat_check
from models import Connection
from tcp_table import parse_tcp4, parse_tcp6
from udp_table import parse_udp4, parse_udp6

PM = {4: "System", 100: "chrome.exe"}


def ip4(text):          # value as it appears in a DWORD field
    return struct.unpack("<L", socket.inet_aton(text))[0]


def port(n):
    return socket.htons(n)


class Decoding(unittest.TestCase):
    def test_ip(self):
        self.assertEqual(common.decode_ip(ip4("192.168.1.101")), "192.168.1.101")

    def test_port(self):
        self.assertEqual(common.decode_port(port(80)), 80)
        self.assertEqual(common.decode_port(port(443) | 0xABCD0000), 443)   # high bits ignored

    def test_ipv6(self):
        raw = socket.inet_pton(socket.AF_INET6, "fe80::1")
        self.assertEqual(common.decode_ipv6(raw), "fe80::1")
        self.assertEqual(common.decode_ipv6(raw, 12), "fe80::1%12")

    def test_endpoint_format(self):
        self.assertEqual(common.format_endpoint("1.2.3.4", 80), "1.2.3.4:80")
        self.assertEqual(common.format_endpoint("::1", 80), "[::1]:80")


class TwoCallPattern(unittest.TestCase):
    def test_sizes_then_fills(self):
        payload = struct.pack("<I", 2) + b"\x01" * 48
        calls = []

        def fake(buf, size_ref, order, family, cls, reserved):
            size = size_ref._obj
            calls.append(buf is None)
            if buf is None or size.value < len(payload):
                size.value = len(payload)
                return common.ERROR_INSUFFICIENT_BUFFER
            ctypes.memmove(buf, payload, len(payload))
            return common.NO_ERROR

        buffer, count = common.fetch_table(fake, common.AF_INET, 5)
        self.assertEqual(count, 2)
        self.assertEqual(calls[0], True)       # first call used a NULL buffer
        self.assertEqual(calls[1], False)      # second call used a real buffer

    def test_retries_when_table_grows(self):
        state = {"n": 0}

        def fake(buf, size_ref, order, family, cls, reserved):
            size = size_ref._obj
            state["n"] += 1
            if state["n"] <= 2:                # first two calls: "need more"
                size.value = 10_000
                return common.ERROR_INSUFFICIENT_BUFFER
            ctypes.memmove(buf, struct.pack("<I", 0), 4)
            return common.NO_ERROR

        _, count = common.fetch_table(fake, common.AF_INET, 5, slack=0)
        self.assertEqual(count, 0)


class StructParsing(unittest.TestCase):
    def test_tcp4(self):
        row = struct.pack("<6I", 2, ip4("0.0.0.0"), port(135), 0, 0, 4)
        row += struct.pack("<6I", 5, ip4("10.0.0.5"), port(51000), ip4("93.184.216.34"), port(443), 100)
        buf = ctypes.create_string_buffer(struct.pack("<I", 2) + row)
        a, b = parse_tcp4(buf, 2, PM)
        self.assertEqual((a.state, a.local_port, a.process_name), ("LISTEN", 135, "System"))
        self.assertEqual((b.state, b.remote_address, b.remote_port, b.process_name),
                         ("ESTABLISHED", "93.184.216.34", 443, "chrome.exe"))
        self.assertTrue(a.is_listener)
        self.assertEqual(a.ip_version, 4)

    def test_tcp6(self):
        loop = socket.inet_pton(socket.AF_INET6, "::1")
        row = struct.pack("<16sII16sIIII", loop, 0, port(8080), b"\0" * 16, 0, 0, 2, 100)
        self.assertEqual(len(row), 56)
        buf = ctypes.create_string_buffer(struct.pack("<I", 1) + row)
        (c,) = parse_tcp6(buf, 1, PM)
        self.assertEqual((c.local_address, c.local_port, c.state, c.ip_version),
                         ("::1", 8080, "LISTEN", 6))

    def test_udp(self):
        r4 = struct.pack("<3I", ip4("0.0.0.0"), port(5353), 100)
        (u,) = parse_udp4(ctypes.create_string_buffer(struct.pack("<I", 1) + r4), 1, PM)
        self.assertEqual((u.remote_address, u.remote_port, u.state), ("*", 0, "NONE"))
        r6 = struct.pack("<16sIII", b"\0" * 16, 0, port(5353), 100)
        self.assertEqual(len(r6), 28)
        (u6,) = parse_udp6(ctypes.create_string_buffer(struct.pack("<I", 1) + r6), 1, PM)
        self.assertEqual((u6.local_address, u6.ip_version), ("::", 6))

    def test_listener_table_forces_listen(self):
        import tcp_table
        tcp_table.LISTENER_RAW_ANOMALIES = 0
        rows = b"".join(struct.pack("<6I", st, 0, port(p), 0, 0, 4)
                        for st, p in ((2, 135), (0, 445), (6, 5040), (1, 7680)))
        buf = ctypes.create_string_buffer(struct.pack("<I", 4) + rows)
        got = parse_tcp4(buf, 4, PM, force_state="LISTEN")
        self.assertEqual({c.state for c in got}, {"LISTEN"})
        self.assertEqual(tcp_table.LISTENER_RAW_ANOMALIES, 3)   # raw 0, 6, 1 disagreed

    def test_unknown_state_code(self):
        row = struct.pack("<6I", 99, 0, 0, 0, 0, 4)
        (c,) = parse_tcp4(ctypes.create_string_buffer(struct.pack("<I", 1) + row), 1, PM)
        self.assertEqual(c.state, "UNKNOWN")

    def test_empty_table(self):
        self.assertEqual(parse_tcp4(ctypes.create_string_buffer(4), 0, PM), [])


def conn(proto="TCP", lip="10.0.0.5", lport=50000, rip="1.1.1.1", rport=443,
         state="ESTABLISHED", pid=100, name="chrome.exe", ver=4):
    return Connection(proto, lip, lport, rip, rport, state, pid, name, ver)


class DiffAndDb(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = db.connect(Path(self.tmp.name) / "t.db")
        db.create_database(self.conn)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_diff_added_removed_changed(self):
        keep = conn(lport=1)
        s1 = db.save_snapshot(self.conn, [keep, conn(lport=2), conn(lport=3, state="ESTABLISHED")],
                              label="before")
        s2 = db.save_snapshot(self.conn, [keep, conn(lport=3, state="CLOSE_WAIT"), conn(lport=4)],
                              label="after")
        d = db.diff_snapshots(self.conn, s1, s2)
        self.assertEqual((len(d["added"]), len(d["removed"]), len(d["changed"]), d["unchanged"]),
                         (1, 1, 1, 1))
        self.assertEqual(d["changed"][0][1:], ("ESTABLISHED", "CLOSE_WAIT"))
        text = db.format_diff(d)
        self.assertIn("before", text)
        self.assertIn("ESTABLISHED -> CLOSE_WAIT", text)

    def test_default_diff_uses_latest_two(self):
        self.assertIsNone(db.diff_snapshots(self.conn))
        db.save_snapshot(self.conn, [conn()])
        db.save_snapshot(self.conn, [conn(), conn(lport=9)])
        self.assertEqual(len(db.diff_snapshots(self.conn)["added"]), 1)

    def test_duplicates_not_collapsed(self):
        u = conn(proto="UDP", rip="*", rport=0, state="NONE")
        s1 = db.save_snapshot(self.conn, [u])
        s2 = db.save_snapshot(self.conn, [u, u])
        self.assertEqual(len(db.diff_snapshots(self.conn, s1, s2)["added"]), 1)

    def test_ipv6_roundtrip_and_csv(self):
        sid = db.save_snapshot(self.conn, [conn(lip="::1", rip="::", rport=0, state="LISTEN", ver=6)])
        path = db.export_csv(self.conn, sid, Path(self.tmp.name) / "o.csv", hosts={"::": "x"})
        text = Path(path).read_text()
        self.assertIn("::1", text)
        self.assertIn("remote_host", text)

    def test_prune(self):
        for _ in range(5):
            db.save_snapshot(self.conn, [conn()])
        db.prune(self.conn, 2)
        self.assertEqual([r[0] for r in db.list_snapshots(self.conn)], [4, 5])

    def test_migrates_old_schema(self):
        old = db.connect(Path(self.tmp.name) / "old.db")
        old.executescript("""CREATE TABLE snapshots(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT);
            CREATE TABLE connections(id INTEGER PRIMARY KEY AUTOINCREMENT, snapshot_id INTEGER,
            protocol TEXT, local_address TEXT, local_port INTEGER, remote_address TEXT,
            remote_port INTEGER, state TEXT, pid INTEGER, process_name TEXT);""")
        db.create_database(old)
        db.save_snapshot(old, [conn()], label="x")
        old.close()

    def test_charts_and_interpretation(self):
        import analysis
        common.OUTPUT_DIR = Path(self.tmp.name)
        analysis.OUTPUT_DIR = Path(self.tmp.name)
        rows = ([conn(lport=i, pid=200 + i % 3, name="svchost.exe", state="LISTEN") for i in range(8)]
                + [conn(lport=100 + i) for i in range(20)]
                + [conn(lport=200, state="TIME_WAIT"), conn(lport=201, state="CLOSE_WAIT"),
                   conn(proto="UDP", rip="*", rport=0, state="NONE")])
        sid = db.save_snapshot(self.conn, rows)
        self.assertTrue(analysis.connections_per_process(self.conn, sid).exists())
        self.assertTrue(analysis.tcp_state_distribution(self.conn, sid).exists())
        md = analysis.write_interpretation(self.conn, sid).read_text()
        self.assertIn("ESTABLISHED dominates", md)
        self.assertIn("TIME_WAIT (1)", md)
        self.assertNotIn("WARNING", md)


NETSTAT = """
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1536
  TCP    10.0.0.5:51000         93.184.216.34:443      ESTABLISHED     100
  TCP    10.0.0.5:51001         93.184.216.34:443      TIME_WAIT       0
  TCP    [::]:135               [::]:0                 LISTENING       1536
  TCP    [fe80::1%12]:49670     [::]:0                 LISTENING       4
  UDP    0.0.0.0:5353           *:*                                    100
  UDP    [fe80::1%12]:1900      *:*                                    4
"""


class NetstatCheck(unittest.TestCase):
    def test_parse(self):
        rows = netstat_check.parse_netstat(NETSTAT)
        self.assertEqual(len(rows), 7)
        self.assertEqual(rows[0][5], "LISTEN")                  # LISTENING normalised
        self.assertEqual(rows[3][1:3], ("::", 135))
        self.assertEqual(rows[4][1], "fe80::1%12")
        self.assertEqual(rows[6][3:5], ("*", 0))

    def test_compare_identical(self):
        tool = [conn("TCP", "0.0.0.0", 135, "0.0.0.0", 0, "LISTEN", 1536, "svchost.exe"),
                conn("TCP", "10.0.0.5", 51000, "93.184.216.34", 443, "ESTABLISHED", 100),
                conn("TCP", "10.0.0.5", 51001, "93.184.216.34", 443, "TIME_WAIT", 0, "System Idle Process"),
                conn("TCP", "::", 135, "::", 0, "LISTEN", 1536, "svchost.exe", 6),
                conn("TCP", "fe80::1%12", 49670, "::", 0, "LISTEN", 4, "System", 6),
                conn("UDP", "0.0.0.0", 5353, "*", 0, "NONE", 100),
                conn("UDP", "fe80::1%12", 1900, "*", 0, "NONE", 4, "System", 6)]
        _, stats = netstat_check.compare(tool, NETSTAT)
        self.assertEqual((stats["identical"], stats["only_netstat"], stats["only_tool"]), (7, 0, 0))

    def test_blank_listener_state_in_netstat(self):
        text = ("  TCP    0.0.0.0:445            0.0.0.0:0              4\n"
                "  TCP    [::]:5040              [::]:0                 CLOSED          7\n")
        tool = [conn("TCP", "0.0.0.0", 445, "0.0.0.0", 0, "LISTEN", 4, "System"),
                conn("TCP", "::", 5040, "::", 0, "LISTEN", 7, "svchost.exe", 6)]
        _, stats = netstat_check.compare(tool, text)
        self.assertEqual((stats["identical"], stats["listener_quirk"]), (2, 2))

    def test_compare_reports_differences(self):
        tool = [conn("TCP", "10.0.0.5", 51000, "93.184.216.34", 443, "CLOSE_WAIT", 100),
                conn("TCP", "9.9.9.9", 1, "8.8.8.8", 2, "ESTABLISHED", 5)]
        report, stats = netstat_check.compare(tool, NETSTAT)
        self.assertEqual(stats["state_mismatch"], 1)
        self.assertEqual(stats["only_tool"], 1)
        self.assertEqual(stats["only_netstat"], 6)
        self.assertIn("netstat=ESTABLISHED tool=CLOSE_WAIT", report)


class TimelineBackend(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = db.connect(Path(self.tmp.name) / "t.db")
        db.create_database(self.conn)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_empty(self):
        import web
        self.assertEqual(web.build_timeline(self.conn), {"empty": True})

    def test_lifecycle_matrix(self):
        import web
        listener = conn("TCP", "0.0.0.0", 135, "0.0.0.0", 0, "LISTEN", 1, "svchost.exe")
        for st in (None, "SYN_SENT", "ESTABLISHED", "CLOSE_WAIT", "TIME_WAIT", None):
            rows = [listener] + ([conn(lport=50100, rip="9.9.9.9", state=st)] if st else [])
            db.save_snapshot(self.conn, rows, label="x" if st == "ESTABLISHED" else None)
        t = web.build_timeline(self.conn, 40)
        self.assertEqual(t["states"], ["LISTEN", "SYN_SENT", "ESTABLISHED", "CLOSE_WAIT", "TIME_WAIT"])
        self.assertEqual(len(t["snapshots"]), 6)
        first = t["rows"][0]                              # interesting rows sort first
        self.assertEqual(first["remote"], "9.9.9.9:443")
        self.assertEqual(first["cells"], [-1, 1, 2, 3, 4, -1])
        self.assertEqual((first["changes"], first["present_all"], first["listener"]), (3, False, False))
        self.assertTrue(t["rows"][-1]["listener"])
        self.assertEqual(t["snapshots"][2]["label"], "x")
        self.assertEqual((t["snapshots"][1]["added"], t["snapshots"][5]["removed"]), (1, 1))
        self.assertIsNone(t["snapshots"][0]["added"])

    def test_last_limits_window(self):
        import web
        for _ in range(6):
            db.save_snapshot(self.conn, [conn()])
        self.assertEqual([s["id"] for s in web.build_timeline(self.conn, 3)["snapshots"]], [4, 5, 6])

    def test_udp_excluded(self):
        import web
        db.save_snapshot(self.conn, [conn(proto="UDP", rip="*", rport=0, state="NONE")])
        self.assertEqual(web.build_timeline(self.conn)["total_rows"], 0)


class LifecycleDemo(unittest.TestCase):
    def test_logs_state_changes_with_scripted_reader(self):
        import lifecycle_demo
        common.OUTPUT_DIR = Path(tempfile.mkdtemp())
        lifecycle_demo.OUTPUT_DIR = common.OUTPUT_DIR
        # fake clock: every sleep advances time, so the demo runs instantly
        now = {"t": 0.0}
        clock = lambda: now["t"]
        sleep = lambda s: now.__setitem__("t", now["t"] + s)
        holder = {}

        def reader():
            port = holder.get("port")
            if port is None:
                return []
            t = now["t"] - holder["t0"]
            rows = [conn("TCP", "127.0.0.1", port, "0.0.0.0", 0, "LISTEN")]
            if 0.3 < t < 3.9:
                st = "ESTABLISHED" if t < 1.2 else "FIN_WAIT_2"
                rows += [conn("TCP", "127.0.0.1", 50000, "127.0.0.1", port, st),
                         conn("TCP", "127.0.0.1", port, "127.0.0.1", 50000,
                              "ESTABLISHED" if t < 1.2 else "CLOSE_WAIT")]
            return rows

        # find the server port the demo picked by wrapping socket creation
        real = lifecycle_demo.socket.socket

        class Spy(real):
            def listen(self, *a):
                holder["port"] = self.getsockname()[1]
                holder["t0"] = now["t"]
                return super().listen(*a)
        lifecycle_demo.socket.socket = Spy
        try:
            log = lifecycle_demo.run(reader=reader, sleep=sleep, clock=clock)
        finally:
            lifecycle_demo.socket.socket = real
        text = "\n".join(log)
        self.assertIn("appeared as LISTEN", text)
        self.assertIn("ESTABLISHED -> FIN_WAIT_2", text)
        self.assertIn("ESTABLISHED -> CLOSE_WAIT", text)


if __name__ == "__main__":
    unittest.main()
