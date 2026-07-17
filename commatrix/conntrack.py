"""Read and parse connection tracking data from ``nf_conntrack``.

Two sources are supported, both relying only on the standard library plus the
kernel's own facilities (no libpcap / tcpdump):

* ``procfs`` -- poll ``/proc/net/nf_conntrack`` (a plain text file).  This is the
  most portable option and needs no extra packages, but it is a *snapshot* of
  currently tracked connections, so very short flows may be missed between
  polls.
* ``conntrack-events`` -- stream ``conntrack -E`` (from ``conntrack-tools`` when
  already present on the host).  Optional; never installed by commatrix.
* ``sockets`` -- derive flows from ``/proc/net/{tcp,udp}`` when conntrack procfs
  is unavailable (no extra packages; byte counts are zero).

For byte/packet accounting the kernel must have accounting enabled::

    sysctl -w net.netfilter.nf_conntrack_acct=1
    sysctl -w net.netfilter.nf_conntrack_timestamp=1
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, Iterable, Iterator, List, Optional, Sequence

from . import sockdiag
from .sockets import SocketEntry, read_all_sockets

log = logging.getLogger("commatrix.conntrack")

PROC_CONNTRACK = "/proc/net/nf_conntrack"

# Layer-4 protocol names the kernel emits in the conntrack table.
_L4_PROTOS = {
    "tcp",
    "udp",
    "udplite",
    "dccp",
    "sctp",
    "icmp",
    "icmpv6",
    "gre",
    "unknown",
}

_ACCT_SYSCTL = "/proc/sys/net/netfilter/nf_conntrack_acct"
_TIMESTAMP_SYSCTL = "/proc/sys/net/netfilter/nf_conntrack_timestamp"

# nf_conntrack sysctls commatrix turns on for a run and restores afterwards.
MANAGED_SYSCTLS: Sequence[str] = (_ACCT_SYSCTL, _TIMESTAMP_SYSCTL)

# Where the pre-run sysctl values are persisted so they can be restored even
# after an unclean exit (SIGKILL / OOM / power loss) by a later run or by the
# systemd ``ExecStopPost`` hook. Lives under the unit's RuntimeDirectory.
DEFAULT_SYSCTL_STATE_FILE = "/run/commatrix/sysctl.state"


@dataclass
class ConntrackEntry:
    """A single connection tracking record (bidirectional)."""

    l4proto: str
    state: Optional[str]
    # original direction tuple (as initiated)
    orig_src: str
    orig_dst: str
    orig_sport: Optional[int]
    orig_dport: Optional[int]
    orig_bytes: int
    orig_packets: int
    # reply direction tuple
    reply_src: Optional[str]
    reply_dst: Optional[str]
    reply_sport: Optional[int]
    reply_dport: Optional[int]
    reply_bytes: int
    reply_packets: int
    # metadata
    delta_time: Optional[int] = None  # seconds since flow start (timestamp sysctl)
    event: Optional[str] = None  # NEW / UPDATE / DESTROY when using event source
    assured: bool = False
    unreplied: bool = False

    @property
    def total_bytes(self) -> int:
        return self.orig_bytes + self.reply_bytes

    @property
    def total_packets(self) -> int:
        return self.orig_packets + self.reply_packets

    @property
    def has_accounting(self) -> bool:
        return (self.orig_bytes + self.reply_bytes) > 0 or (
            self.orig_packets + self.reply_packets
        ) > 0


def accounting_enabled() -> bool:
    """Return True if nf_conntrack byte/packet accounting is enabled."""

    return _read_sysctl_flag(_ACCT_SYSCTL)


def timestamp_enabled() -> bool:
    """Return True if nf_conntrack flow timestamping is enabled."""

    return _read_sysctl_flag(_TIMESTAMP_SYSCTL)


def _read_sysctl_flag(path: str) -> bool:
    return read_sysctl_flag(path) is True


def read_sysctl_flag(path: str) -> Optional[bool]:
    """Return the boolean value of a 0/1 sysctl file.

    Returns ``None`` when the file cannot be read (missing sysctl, no
    permission, or ``nf_conntrack`` not loaded), which lets callers tell
    "disabled" apart from "unavailable".
    """

    try:
        with open(path, "r", encoding="ascii") as fh:
            return fh.read().strip() == "1"
    except OSError:
        return None


def write_sysctl_flag(path: str, enabled: bool) -> bool:
    """Write ``1``/``0`` to a sysctl file. Returns True on success.

    Writing usually requires root; failures (permission, missing file) are
    reported via the return value rather than raising.
    """

    try:
        with open(path, "w", encoding="ascii") as fh:
            fh.write("1\n" if enabled else "0\n")
        return True
    except OSError:
        return False


def _remove_file(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


class SysctlGuard:
    """Enable a set of nf_conntrack sysctls for a run and restore them after.

    On :meth:`apply` the current value of each managed sysctl is read and
    persisted to *state_file*, then every writable sysctl that was disabled is
    turned on.  :meth:`restore` puts each changed sysctl back to the value it
    had on entry and removes the state file.

    Because the originals are persisted to disk *before* anything is changed,
    the host can be returned to its original state even if this process is
    ``SIGKILL``ed and never runs :meth:`restore`: a later run recovers the
    stale state on startup (see :meth:`apply`), and the systemd
    ``ExecStopPost`` hook can call :meth:`restore_from_file` directly.

    The guard degrades gracefully: sysctls that cannot be read (``nf_conntrack``
    not loaded) are recorded in :attr:`unavailable`; sysctls that exist but
    cannot be written (not root) set :attr:`enable_failed`.
    """

    def __init__(
        self,
        sysctls: Sequence[str] = MANAGED_SYSCTLS,
        state_file: str = DEFAULT_SYSCTL_STATE_FILE,
    ):
        self.sysctls = list(sysctls)
        self.state_file = state_file
        self.originals: Dict[str, bool] = {}
        # path -> original value we still owe a restore to.
        self.changed: Dict[str, bool] = {}
        self.unavailable: List[str] = []
        self.enable_failed = False
        self.recovered_stale = False

    @property
    def available(self) -> bool:
        return bool(self.originals)

    def apply(self) -> "SysctlGuard":
        # Recover a leftover state file from a previous unclean exit first, so
        # the "original" we capture below is the true pre-commatrix baseline.
        if os.path.exists(self.state_file):
            self.recovered_stale = self.restore_from_file(self.state_file)

        for path in self.sysctls:
            value = read_sysctl_flag(path)
            if value is None:
                self.unavailable.append(path)
            else:
                self.originals[path] = value

        # Persist the baseline before mutating anything.
        if self.originals:
            self._write_state(self.originals)

        for path, original in self.originals.items():
            if original is False:
                if write_sysctl_flag(path, True):
                    self.changed[path] = original
                else:
                    self.enable_failed = True
        return self

    def restore(self) -> None:
        """Restore changed sysctls to their original values (idempotent)."""

        for path in list(self.changed):
            if write_sysctl_flag(path, self.changed[path]):
                del self.changed[path]
        if not self.changed:
            _remove_file(self.state_file)

    def _write_state(self, originals: Dict[str, bool]) -> None:
        payload = {path: ("1" if val else "0") for path, val in originals.items()}
        try:
            parent = os.path.dirname(self.state_file)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(self.state_file, "w", encoding="ascii") as fh:
                json.dump(payload, fh)
        except OSError as exc:
            log.debug("could not persist sysctl state to %s: %s", self.state_file, exc)

    @staticmethod
    def restore_from_file(state_file: str) -> bool:
        """Restore sysctls from a persisted state file, then remove it.

        Returns True if at least one sysctl was changed back.  Safe to call
        when the file is absent (returns False).  Used for crash recovery and
        by the systemd ExecStopPost hook.
        """

        try:
            with open(state_file, "r", encoding="ascii") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return False

        restored = False
        for path, raw in data.items():
            desired = str(raw).strip() == "1"
            current = read_sysctl_flag(path)
            if current is None or current == desired:
                continue
            if write_sysctl_flag(path, desired):
                restored = True
        _remove_file(state_file)
        return restored


def running_under_systemd() -> bool:
    """Return True when the process was started by systemd.

    systemd sets a unique ``INVOCATION_ID`` in the environment of every unit
    it starts (both system and user units), which is the documented way to
    detect a systemd-managed invocation.
    """

    return bool(os.environ.get("INVOCATION_ID"))


def _to_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_conntrack_line(line: str) -> Optional[ConntrackEntry]:
    """Parse a single conntrack text line into a :class:`ConntrackEntry`.

    Handles both ``/proc/net/nf_conntrack`` rows and ``conntrack -E`` event
    lines (which are prefixed with ``[NEW]``/``[UPDATE]``/``[DESTROY]`` and may
    include a leading ``[<timestamp>]`` token).  Returns ``None`` for lines that
    cannot be interpreted (e.g. blank lines).
    """

    line = line.strip()
    if not line:
        return None

    tokens = line.split()
    event: Optional[str] = None

    # Strip an optional leading "[<epoch.usec>]" timestamp token (conntrack -o timestamp).
    idx = 0
    if tokens and tokens[0].startswith("[") and tokens[0].endswith("]"):
        inner = tokens[0][1:-1]
        if _looks_like_float(inner):
            idx = 1

    # Optional "[NEW]" / "[UPDATE]" / "[DESTROY]" event marker.
    if idx < len(tokens) and tokens[idx].startswith("[") and tokens[idx].endswith("]"):
        inner = tokens[idx][1:-1]
        if inner.isupper() and inner.isalpha():
            event = inner
            idx += 1

    # Find the layer-4 protocol name token.
    l4_index = None
    for i in range(idx, len(tokens)):
        if tokens[i] in _L4_PROTOS:
            l4_index = i
            break
    if l4_index is None:
        return None

    l4proto = tokens[l4_index]

    # Tokens after the proto number: optional timeout, optional state, then k=v pairs.
    rest = tokens[l4_index + 1 :]

    state: Optional[str] = None
    assured = False
    unreplied = False

    # Collect key=value pairs; duplicate keys map to original then reply tuple.
    kv_original: Dict[str, str] = {}
    kv_reply: Dict[str, str] = {}
    seen_first: Dict[str, bool] = {}

    for tok in rest:
        if tok.startswith("[") and tok.endswith("]"):
            flag = tok[1:-1]
            if flag == "ASSURED":
                assured = True
            elif flag == "UNREPLIED":
                unreplied = True
            continue
        if "=" in tok:
            key, _, val = tok.partition("=")
            if key in seen_first:
                # second occurrence -> reply direction (only for tuple keys)
                if key not in kv_reply:
                    kv_reply[key] = val
            else:
                kv_original[key] = val
                seen_first[key] = True
        else:
            # A bare uppercase word before any k=v is the TCP state.
            if not kv_original and tok.isupper() and state is None:
                state = tok

    delta_time = _to_int(kv_original.get("delta-time") or kv_reply.get("delta-time"))

    return ConntrackEntry(
        l4proto=l4proto,
        state=state,
        orig_src=kv_original.get("src", ""),
        orig_dst=kv_original.get("dst", ""),
        orig_sport=_to_int(kv_original.get("sport")),
        orig_dport=_to_int(kv_original.get("dport")),
        orig_bytes=_to_int(kv_original.get("bytes")) or 0,
        orig_packets=_to_int(kv_original.get("packets")) or 0,
        reply_src=kv_reply.get("src"),
        reply_dst=kv_reply.get("dst"),
        reply_sport=_to_int(kv_reply.get("sport")),
        reply_dport=_to_int(kv_reply.get("dport")),
        reply_bytes=_to_int(kv_reply.get("bytes")) or 0,
        reply_packets=_to_int(kv_reply.get("packets")) or 0,
        delta_time=delta_time,
        event=event,
        assured=assured,
        unreplied=unreplied,
    )


def _looks_like_float(value: str) -> bool:
    try:
        float(value)
        return True
    except ValueError:
        return False


def parse_conntrack_text(text: str) -> List[ConntrackEntry]:
    """Parse a whole conntrack dump (multiple lines)."""

    entries: List[ConntrackEntry] = []
    for line in text.splitlines():
        entry = parse_conntrack_line(line)
        if entry is not None:
            entries.append(entry)
    return entries


def proc_available(path: str = PROC_CONNTRACK) -> bool:
    return os.path.exists(path)


def entries_from_sockets(sockets: Optional[List[SocketEntry]] = None) -> List[ConntrackEntry]:
    """Build pseudo-conntrack rows from ``/proc/net/{tcp,udp}`` socket tables."""

    if sockets is None:
        sockets = read_all_sockets()
    entries: List[ConntrackEntry] = []
    for sock in sockets:
        if sock.is_listening:
            continue
        if sock.remote_port == 0 and sock.local_port == 0:
            continue
        entries.append(
            ConntrackEntry(
                l4proto=sock.proto,
                state=sock.state if sock.proto == "tcp" else None,
                orig_src=sock.local_ip,
                orig_dst=sock.remote_ip,
                orig_sport=sock.local_port,
                orig_dport=sock.remote_port,
                orig_bytes=0,
                orig_packets=0,
                reply_src=sock.remote_ip,
                reply_dst=sock.local_ip,
                reply_sport=sock.remote_port,
                reply_dport=sock.local_port,
                reply_bytes=0,
                reply_packets=0,
            )
        )
    return entries


def read_socket_entries() -> List[ConntrackEntry]:
    """Snapshot active sockets via procfs only (no conntrack dependency)."""

    return entries_from_sockets()


def entries_from_sockdiag() -> List[ConntrackEntry]:
    """Build conntrack rows from the ``sock_diag`` netlink interface.

    Unlike the plain ``/proc/net/{tcp,udp}`` fallback, this carries *real*
    per-socket byte/packet counters for TCP (from ``tcp_info``) with no extra
    package and no ``nf_conntrack``.  UDP has no such counters, so UDP flows are
    still taken from procfs (with zero bytes) to preserve visibility.
    """

    entries: List[ConntrackEntry] = []
    for d in sockdiag.read_tcp_diag():
        entries.append(
            ConntrackEntry(
                l4proto="tcp",
                state=d.state,
                orig_src=d.local_ip,
                orig_dst=d.remote_ip,
                orig_sport=d.local_port,
                orig_dport=d.remote_port,
                orig_bytes=d.bytes_sent,
                orig_packets=d.packets_sent,
                reply_src=d.remote_ip,
                reply_dst=d.local_ip,
                reply_sport=d.remote_port,
                reply_dport=d.local_port,
                reply_bytes=d.bytes_recv,
                reply_packets=d.packets_recv,
            )
        )
    # UDP has no tcp_info; keep it visible via procfs (zero bytes).
    udp_socks = [s for s in read_all_sockets() if s.proto == "udp"]
    entries.extend(entries_from_sockets(udp_socks))
    return entries


def read_conntrack_list(binary: str = "conntrack") -> List[ConntrackEntry]:
    """Snapshot currently tracked flows via ``conntrack -L`` when already installed."""

    if not conntrack_tool_available(binary):
        raise FileNotFoundError(
            "the 'conntrack' binary is not installed on this host"
        )
    proc = subprocess.run(
        [binary, "-L", "-o", "extended"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"conntrack -L failed (exit {proc.returncode}): {proc.stderr.strip()}"
        )
    return parse_conntrack_text(proc.stdout)


def _try_read_conntrack_list() -> Optional[List[ConntrackEntry]]:
    if not conntrack_tool_available():
        return None
    try:
        return read_conntrack_list()
    except (RuntimeError, OSError):
        return None


def read_conntrack_snapshot(source: str = "auto") -> List[ConntrackEntry]:
    """Read the current flow table using the best available backend (no installs)."""

    effective = resolve_source(source)
    if effective == "procfs":
        if proc_available():
            return read_proc_conntrack()
        listed = _try_read_conntrack_list()
        if listed is not None:
            return listed
        return read_socket_entries()
    if effective == "conntrack-events":
        listed = _try_read_conntrack_list()
        if listed is not None:
            return listed
        if proc_available():
            return read_proc_conntrack()
        return read_socket_entries()
    if effective == "socket-diag":
        try:
            return entries_from_sockdiag()
        except OSError:
            return read_socket_entries()
    if effective == "sockets":
        return read_socket_entries()
    raise ValueError(f"unknown conntrack source: {effective!r}")


def capture_backend(source: str = "auto") -> str:
    """Return the backend :func:`read_conntrack_snapshot` would use."""

    effective = resolve_source(source)
    if effective == "procfs":
        if proc_available():
            return "procfs"
        if conntrack_tool_available():
            return "conntrack-list"
        if sockdiag.available():
            return "socket-diag"
        return "sockets"
    if effective == "conntrack-events":
        if conntrack_tool_available():
            return "conntrack-list"
        if proc_available():
            return "procfs"
        if sockdiag.available():
            return "socket-diag"
        return "sockets"
    if effective == "socket-diag":
        return "socket-diag" if sockdiag.available() else "sockets"
    if effective == "sockets":
        return "sockets"
    raise ValueError(f"unknown conntrack source: {effective!r}")


def capture_quality(backend: str, accounting: bool) -> str:
    """Describe the trustworthiness of byte data for a capture backend.

    * ``exact``          -- conntrack accounting: real cumulative byte/packet
      counters (procfs / conntrack-list / ct-netlink with acct enabled).
    * ``per-socket-tcp`` -- sock_diag: real per-socket TCP byte counters (UDP
      has none, that is inherent).
    * ``topology-only``  -- no byte accounting available (socket tables, or a
      conntrack backend with accounting disabled).
    """

    if backend in ("procfs", "conntrack-list", "ct-netlink"):
        return "exact" if accounting else "topology-only"
    if backend == "socket-diag":
        return "per-socket-tcp"
    return "topology-only"


def read_proc_conntrack(path: str = PROC_CONNTRACK) -> List[ConntrackEntry]:
    """Read and parse the current ``/proc/net/nf_conntrack`` snapshot.

    Raises :class:`PermissionError` if not run as root (the file is root-only).
    """

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse_conntrack_text(fh.read())


def conntrack_tool_available(binary: str = "conntrack") -> bool:
    """Return True if the ``conntrack`` CLI is installed and on PATH."""

    return shutil.which(binary) is not None


def resolve_source(preferred: str) -> str:
    """Resolve the effective capture source.

    * ``auto`` -> ``procfs`` when ``/proc/net/nf_conntrack`` exists, else
      ``conntrack -L`` when the distro already ships ``conntrack``, else
      ``socket-diag`` (sock_diag netlink: real per-socket byte counts, no extra
      package), else ``/proc/net/{tcp,udp}`` socket tables (no byte counts).
    * ``procfs`` / ``conntrack-events`` / ``socket-diag`` / ``sockets`` -> as-is.
    """

    if preferred == "auto":
        if proc_available():
            return "procfs"
        if conntrack_tool_available():
            return "conntrack-events"
        if sockdiag.available():
            return "socket-diag"
        return "sockets"
    if preferred in ("procfs", "conntrack-events", "sockets", "socket-diag"):
        return preferred
    raise ValueError(f"unknown conntrack source: {preferred!r}")


def iter_conntrack_events(
    binary: str = "conntrack",
    extra_args: Optional[Iterable[str]] = None,
) -> Iterator[ConntrackEntry]:
    """Yield :class:`ConntrackEntry` objects from a live ``conntrack -E`` stream.

    This blocks and yields entries as they arrive.  Intended for the
    event-driven capture mode.  Requires ``conntrack-tools``.
    """

    if not conntrack_tool_available(binary):
        raise FileNotFoundError(
            "the 'conntrack' binary is not installed on this host"
        )

    args = [binary, "-E", "-o", "timestamp,extended"]
    if extra_args:
        args.extend(extra_args)

    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            entry = parse_conntrack_line(line)
            if entry is not None:
                yield entry
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()


def is_root() -> bool:
    return os.geteuid() == 0
