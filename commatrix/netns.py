"""Enumerate network namespaces so containers with their own netns are visible.

The host's ``/proc/net/*`` tables only show the host network namespace, so flows
inside containers that have a separate netns are invisible. We enumerate netns
via ``/proc/<pid>/ns/net`` inode identity and, for each, read that namespace's
socket/conntrack tables through ``/proc/<pid>/net/*`` -- no ``setns`` needed
(reading another pid's ``/proc/<pid>/net`` yields that pid's netns tables).

Requires root/CAP_SYS_PTRACE to read other users' ``/proc/<pid>/ns`` and
``/proc/<pid>/net``; as non-root only the caller's own (host) namespace is seen.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, List, Optional

from .processes import _read_text, _parse_cgroup


@dataclass
class NetnsInfo:
    inode: str                      # e.g. "net:[4026531840]"
    pid: int                        # representative pid whose /proc/<pid>/net to read
    is_host: bool = False
    container_id: Optional[str] = None
    container_runtime: Optional[str] = None
    pod: Optional[str] = None

    @property
    def label(self) -> str:
        if self.is_host:
            return "host"
        if self.container_id:
            return f"{self.container_runtime or 'container'}:{self.container_id[:12]}"
        return self.inode

    @property
    def proc_root(self) -> str:
        return f"/proc/{self.pid}"


def _netns_inode(pid: str, proc_root: str) -> Optional[str]:
    try:
        return os.readlink(os.path.join(proc_root, pid, "ns", "net"))
    except OSError:
        return None


def enumerate_netns(proc_root: str = "/proc", include_host: bool = True) -> List[NetnsInfo]:
    """Return one :class:`NetnsInfo` per distinct network namespace.

    The representative pid for each netns prefers a containerized process (so
    container/pod metadata is populated). The host netns is pid 1's namespace.
    """

    host_inode = _netns_inode("1", proc_root)
    try:
        pids = sorted((p for p in os.listdir(proc_root) if p.isdigit()), key=int)
    except OSError:
        return []

    by_inode: Dict[str, NetnsInfo] = {}
    for pid in pids:
        inode = _netns_inode(pid, proc_root)
        if inode is None:
            continue
        is_host = inode == host_inode
        cgroup = _read_text(os.path.join(proc_root, pid, "cgroup")) or ""
        _unit, container_id, runtime, pod = _parse_cgroup(cgroup)

        info = by_inode.get(inode)
        if info is None:
            by_inode[inode] = NetnsInfo(
                inode=inode, pid=int(pid), is_host=is_host,
                container_id=container_id, container_runtime=runtime, pod=pod,
            )
        elif container_id and not info.container_id:
            # Upgrade the representative to a pid that reveals container/pod.
            info.pid = int(pid)
            info.container_id = container_id
            info.container_runtime = runtime
            info.pod = pod

    result = list(by_inode.values())
    if not include_host:
        result = [n for n in result if not n.is_host]
    return result
