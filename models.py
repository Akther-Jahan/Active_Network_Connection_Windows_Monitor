# ==========================================
# models.py
# ==========================================

from dataclasses import dataclass

from common import format_endpoint


@dataclass
class Connection:
    protocol: str            # "TCP" or "UDP"
    local_address: str
    local_port: int
    remote_address: str      # "*" for UDP
    remote_port: int         # 0 for UDP
    state: str               # "NONE" for UDP
    pid: int
    process_name: str
    ip_version: int = 4      # 4 or 6

    @property
    def is_listener(self):
        return self.protocol == "TCP" and self.state == "LISTEN"

    def __str__(self):
        local = format_endpoint(self.local_address, self.local_port)
        remote = format_endpoint(self.remote_address, self.remote_port)
        return (f"{self.protocol:3} v{self.ip_version} | {local:<38} | {remote:<38} | "
                f"{self.state:<12} | PID={self.pid:<6} | {self.process_name}")
