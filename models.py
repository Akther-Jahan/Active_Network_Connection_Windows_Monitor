# ==========================================
# models.py
# ==========================================

from dataclasses import dataclass


@dataclass
class Connection:

    protocol: str
    local_address: str
    local_port: int

    remote_address: str
    remote_port: int

    state: str

    pid: int
    process_name: str

    def __str__(self):

        return (
            f"{self.protocol:4} | "
            f"{self.local_address}:{self.local_port:<6} | "
            f"{self.remote_address}:{self.remote_port:<6} | "
            f"{self.state:<13} | "
            f"PID={self.pid:<6} | "
            f"{self.process_name}"
        )