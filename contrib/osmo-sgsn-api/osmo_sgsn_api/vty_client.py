import re
import socket
import time
from typing import List, Optional

from .config import settings


class VtyError(Exception):
    pass


_PROMPT_RE = re.compile(r"OsmoSGSN[#>]\s*$")


class VtyClient:
    """Minimal Osmocom VTY client (telnet, no external osmopy dependency)."""

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        timeout: Optional[float] = None,
    ):
        self.host = host or settings.osmo_sgsn_vty_host
        self.port = port or settings.osmo_sgsn_vty_port
        self.timeout = timeout or settings.osmo_sgsn_vty_timeout
        self._sock: Optional[socket.socket] = None
        self._enabled = False

    def connect(self) -> None:
        self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._sock.settimeout(self.timeout)
        self._read_until_prompt()

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            finally:
                self._sock = None
                self._enabled = False

    def _read_until_prompt(self) -> str:
        if not self._sock:
            raise VtyError("not connected")
        chunks: List[str] = []
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            try:
                data = self._sock.recv(65536)
            except socket.timeout:
                data = b""
            if data:
                chunks.append(data.decode("utf-8", errors="replace"))
            text = "".join(chunks)
            if _PROMPT_RE.search(text):
                return text
            if not data:
                break
        return "".join(chunks)

    def _send_line(self, line: str) -> str:
        if not self._sock:
            raise VtyError("not connected")
        self._sock.sendall((line + "\n").encode("utf-8"))
        time.sleep(0.05)
        return self._read_until_prompt()

    def enable(self) -> None:
        if self._enabled:
            return
        out = self._send_line("enable")
        if "%" in out and "password" in out.lower():
            raise VtyError("VTY requires a password; configure 'line vty' with 'no login'")
        self._enabled = True

    def command(self, cmd: str, require_enable: bool = False) -> str:
        if require_enable:
            self.enable()
        out = self._send_line(cmd)
        return self._strip_echo(cmd, out)

    @staticmethod
    def _strip_echo(cmd: str, raw: str) -> str:
        lines = raw.splitlines()
        if lines and lines[0].strip() == cmd.strip():
            lines = lines[1:]
        if lines and _PROMPT_RE.search(lines[-1]):
            lines = lines[:-1]
        return "\n".join(lines).strip()

    def __enter__(self) -> "VtyClient":
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.close()
