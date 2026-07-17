"""Parse kernel socket tables from procfs and map sockets to processes.

Reads ``/proc/net/{tcp,tcp6,udp,udp6}`` to enumerate sockets (including which
ports are in the LISTEN state) and walks ``/proc/<pid>/fd`` to associate socket
inodes with the owning process id.  Everything uses only the standard library.
"""

from __future__ import annotations

import os
import socket as _socket
from dataclasses import dataclass
from typing import Dict, List, Optional

# TCP connection states as reported in /proc/net/tcp (hex).
TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}

# Paths are relative to ``proc_root`` (default ``/proc``) so callers can point
# at an alternate mount without producing a doubled prefix.
_PROC_NET_FILES = {
    "tcp": ("net/tcp", _socket.AF_INET),
    "tcp6": ("net/tcp6", _socket.AF_INET6),
    "udp": ("net/udp", _socket.AF_INET),
    "udp6": ("net/udp6", _socket.AF_INET6),
}


@dataclass
class SocketEntry:
    proto: str  # tcp | udp (family folded in via ip version)
    family: int  # AF_INET | AF_INET6
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    inode: int
    uid: int

    @property
    def is_listening(self) -> bool:
        # UDP has no LISTEN state; treat a wildcard/zero remote as a bound listener.
        if self.proto == "tcp":
            return self.state == "LISTEN"
        return self.remote_port == 0


def _parse_ipv4(hex_addr: str) -> str:
    raw = bytes.fromhex(hex_addr)
    # Stored as a little-endian 32-bit word.
    return _socket.inet_ntop(_socket.AF_INET, raw[::-1])


def _parse_ipv6(hex_addr: str) -> str:
    raw = bytes.fromhex(hex_addr)
    # Stored as four little-endian 32-bit words; reverse each 4-byte group.
    groups = [raw[i : i + 4][::-1] for i in range(0, 16, 4)]
    return _socket.inet_ntop(_socket.AF_INET6, b"".join(groups))


def _parse_addr(token: str, family: int) -> (str, int):  # type: ignore[valid-type]
    addr_hex, _, port_hex = token.partition(":")
    port = int(port_hex, 16) if port_hex else 0
    if family == _socket.AF_INET:
        return _parse_ipv4(addr_hex), port
    return _parse_ipv6(addr_hex), port


def parse_proc_net(text: str, proto: str, family: int) -> List[SocketEntry]:
    """Parse the content of one ``/proc/net/{tcp,udp}[6]`` file."""

    entries: List[SocketEntry] = []
    lines = text.splitlines()
    for line in lines[1:]:  # skip header
        fields = line.split()
        if len(fields) < 10:
            continue
        try:
            local_ip, local_port = _parse_addr(fields[1], family)
            remote_ip, remote_port = _parse_addr(fields[2], family)
            state = TCP_STATES.get(fields[3], fields[3]) if proto == "tcp" else "-"
            uid = int(fields[7])
            inode = int(fields[9])
        except (ValueError, IndexError):
            continue
        entries.append(
            SocketEntry(
                proto=proto,
                family=family,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                state=state,
                inode=inode,
                uid=uid,
            )
        )
    return entries


def read_all_sockets(proc_root: str = "/proc") -> List[SocketEntry]:
    """Read every supported socket table available under *proc_root*."""

    entries: List[SocketEntry] = []
    for key, (rel, family) in _PROC_NET_FILES.items():
        proto = "tcp" if key.startswith("tcp") else "udp"
        # ``_PROC_NET_FILES`` stores paths relative to ``/proc`` (e.g. "net/tcp");
        # join them onto *proc_root* so a custom root is honoured and we never
        # produce a doubled prefix like ``/proc/proc/net/tcp``.
        path = os.path.join(proc_root, rel)
        try:
            with open(path, "r", encoding="ascii", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        entries.extend(parse_proc_net(text, proto, family))
    return entries


def build_inode_to_pid(proc_root: str = "/proc") -> Dict[int, int]:
    """Return a mapping of socket inode -> owning pid.

    Walks ``/proc/<pid>/fd`` and inspects symlinks of the form
    ``socket:[<inode>]``.  Requires sufficient privileges (root) to see other
    users' processes.
    """

    inode_to_pid: Dict[int, int] = {}
    try:
        pids = [name for name in os.listdir(proc_root) if name.isdigit()]
    except OSError:
        return inode_to_pid

    for pid_str in pids:
        fd_dir = os.path.join(proc_root, pid_str, "fd")
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        pid = int(pid_str)
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if target.startswith("socket:["):
                try:
                    inode = int(target[len("socket:[") : -1])
                except ValueError:
                    continue
                # Keep the first pid seen for an inode (lowest pid wins for shared).
                inode_to_pid.setdefault(inode, pid)
    return inode_to_pid


def listening_sockets(entries: List[SocketEntry]) -> List[SocketEntry]:
    return [e for e in entries if e.is_listening]


def listening_port_map(entries: List[SocketEntry]) -> Dict[int, SocketEntry]:
    """Map listening port -> representative socket entry (for service lookup)."""

    ports: Dict[int, SocketEntry] = {}
    for entry in listening_sockets(entries):
        ports.setdefault(entry.local_port, entry)
    return ports
