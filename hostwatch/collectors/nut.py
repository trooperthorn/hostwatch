"""UPS state from a Network UPS Tools (NUT) server, read-only.

The client speaks the upsd line protocol over TCP (default port 3493) and sends
only these lines: USERNAME and PASSWORD when credentials are configured, LIST VAR,
GET VAR, and LOGOUT. It never sends SET, INSTCMD, FSD or any other command, so a
UPS can witness power loss without hostwatch being able to control it. The
allow-list is enforced in `NutClient._send`, not by convention.

UNVERIFIED: the command names and response lines (`BEGIN LIST VAR`, `VAR <ups>
<name> "<value>"`, `END LIST VAR`, `ERR <code>`) come from the NUT network
protocol documentation, not from the owner's NUT server. Confirm with:
upsc UPSNAME@HOST   and   printf 'LIST VAR UPSNAME\nLOGOUT\n' | nc HOST 3493

Samples, all from the `nut` source:
  ups_status_flag   1 or 0, label flag=OL|OB|LB, always emitted for those three so a
                    transition is visible; any other flag in ups.status (CHRG, DISCHRG,
                    RB, ...) is emitted as 1 while present. Label status holds the raw string.
  battery_charge_pct, battery_runtime_s, input_voltage_v, ups_load_pct
                    None when the server does not report the variable.
"""

from __future__ import annotations

import socket
from pathlib import Path

from .base import Collector

ALLOWED_COMMANDS = ("USERNAME", "PASSWORD", "LIST", "GET", "LOGOUT")
CORE_FLAGS = ("OL", "OB", "LB")
NUMERIC = (
    ("battery.charge", "battery_charge_pct", "%"),
    ("battery.runtime", "battery_runtime_s", "s"),
    ("input.voltage", "input_voltage_v", "V"),
    ("ups.load", "ups_load_pct", "%"),
)
MAX_LINES = 2000


class NutError(Exception):
    pass


def parse_value(raw: str) -> str:
    """Strip one pair of surrounding double quotes and unescape \\" and \\\\."""
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        raw = raw[1:-1]
        out, i = [], 0
        while i < len(raw):
            if raw[i] == "\\" and i + 1 < len(raw) and raw[i + 1] in '"\\':
                out.append(raw[i + 1])
                i += 2
            else:
                out.append(raw[i])
                i += 1
        return "".join(out)
    return raw


def parse_var_line(line: str, ups: str) -> tuple[str, str] | None:
    """Parse `VAR <ups> <name> "<value>"`; None for any other shape."""
    parts = line.split(None, 3)
    if len(parts) < 3 or parts[0] != "VAR" or parts[1] != ups:
        return None
    return parts[2], parse_value(parts[3]) if len(parts) == 4 else ""


class NutClient:
    def __init__(self, host: str, port: int, ups: str, timeout: float,
                 user: str = "", password: str = "") -> None:
        self.host, self.port, self.ups, self.timeout = host, port, ups, timeout
        self.user, self.password = user, password
        self._sock: socket.socket | None = None
        self._buf = b""

    def _send(self, line: str) -> None:
        verb = line.split(" ", 1)[0]
        if verb not in ALLOWED_COMMANDS:
            raise NutError(f"refusing to send command {verb!r}")
        assert self._sock is not None
        self._sock.sendall(line.encode("utf-8") + b"\n")

    def _readline(self) -> str:
        assert self._sock is not None
        while b"\n" not in self._buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise NutError("connection closed by server")
            self._buf += chunk
            if len(self._buf) > 1 << 20:
                raise NutError("response too long")
        line, self._buf = self._buf.split(b"\n", 1)
        return line.decode("utf-8", "replace").strip()

    def _expect_ok(self, line: str) -> None:
        self._send(line)
        reply = self._readline()
        verb = line.split(" ", 1)[0]
        # Never echo the sent line: it may hold the password.
        if reply.startswith("ERR"):
            raise NutError(f"server refused {verb}: {reply}")
        if not reply.startswith("OK"):
            raise NutError(f"unexpected reply to {verb}: {reply[:80]!r}")

    def fetch(self) -> dict[str, str]:
        try:
            self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            self._sock.settimeout(self.timeout)
            if self.user:
                self._expect_ok(f"USERNAME {self.user}")
                self._expect_ok(f"PASSWORD {self.password}")
            self._send(f"LIST VAR {self.ups}")
            first = self._readline()
            if first.startswith("ERR"):
                raise NutError(first)
            if not first.startswith("BEGIN LIST VAR"):
                raise NutError(f"unexpected reply to LIST VAR: {first[:80]!r}")
            values: dict[str, str] = {}
            for _ in range(MAX_LINES):
                line = self._readline()
                if line.startswith("END LIST VAR"):
                    break
                if line.startswith("ERR"):
                    raise NutError(line)
                parsed = parse_var_line(line, self.ups)
                if parsed:
                    values[parsed[0]] = parsed[1]
            else:
                raise NutError("list did not end")
            try:
                self._send("LOGOUT")
            except OSError:
                pass
            return values
        except NutError:
            raise
        except TimeoutError as exc:
            raise NutError(f"timed out after {self.timeout:g}s talking to {self.host}:{self.port}") from exc
        except OSError as exc:
            raise NutError(f"cannot reach {self.host}:{self.port}: {type(exc).__name__}: {exc}") from exc
        finally:
            if self._sock is not None:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None
            self._buf = b""


class NutCollector(Collector):
    id = "nut"

    def __init__(self, sysfs, procfs, host: str = "", ups: str = "", user: str = "",
                 password_file: str = "", port: int = 3493, timeout: float = 5.0) -> None:
        super().__init__(sysfs, procfs)
        self.host, self.ups, self.user = host.strip(), ups.strip(), user.strip()
        self.password_file, self.port, self.timeout = password_file.strip(), port, timeout

    def _configured(self) -> bool:
        return bool(self.host and self.ups)

    def is_absent(self):
        """Absent by configuration: no NUT server was set, so nothing is expected."""
        return not self._configured()

    def _password(self) -> str:
        if not self.user:
            return ""
        if not self.password_file:
            raise NutError("HOSTWATCH_NUT_USER is set but HOSTWATCH_NUT_PASSWORD_FILE is not")
        try:
            return Path(self.password_file).read_text().strip()
        except OSError as exc:
            raise NutError(f"cannot read the NUT password file: {type(exc).__name__}") from exc

    def _fetch(self) -> dict[str, str]:
        client = NutClient(self.host, self.port, self.ups, self.timeout, self.user, self._password())
        return client.fetch()

    def detect(self):
        if not self._configured():
            return False, "HOSTWATCH_NUT_HOST and HOSTWATCH_NUT_UPS not both set"
        try:
            values = self._fetch()
        except NutError as exc:
            return False, f"NUT server unusable at {self.host}:{self.port}: {exc}"
        return True, f"{self.ups}@{self.host}: {len(values)} variable(s)"

    def collect(self):
        """Raises NutError when the server cannot be read, which the agent turns into unavailable."""
        values = self._fetch()
        out = []
        status = values.get("ups.status")
        if status is None:
            for flag in CORE_FLAGS:
                out.append(self.sample("ups_status_flag", None, "", flag=flag, status=""))
        else:
            flags = status.split()
            for flag in CORE_FLAGS:
                out.append(self.sample("ups_status_flag", 1 if flag in flags else 0, "", flag=flag, status=status))
            for flag in flags:
                if flag not in CORE_FLAGS:
                    out.append(self.sample("ups_status_flag", 1, "", flag=flag, status=status))
        for var, metric, unit in NUMERIC:
            try:
                val = float(values[var])
            except (KeyError, ValueError):
                val = None
            if val is not None and val != val:
                val = None
            out.append(self.sample(metric, val, unit))
        return out
