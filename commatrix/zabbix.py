"""Integration with the local Zabbix agent.

Two directions are supported:

* *Reading host parameters* -- parse the agent configuration for the canonical
  ``Hostname``/``HostMetadata`` (so records line up with Zabbix inventory) and,
  when ``zabbix_get`` is available, query the local agent for standard item
  values.  When the agent is not reachable we fall back to :mod:`platform` and
  procfs so the tool still works stand-alone.
* *Exporting summary data* -- push metrics to a Zabbix trapper item via
  ``zabbix_sender`` (optional transport for centralisation).

Everything relies only on the standard library plus the Zabbix CLI tools that
ship with the agent.
"""

from __future__ import annotations

import glob
import os
import platform
import shutil
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Zabbix agent item keys queried for host parameters (best effort).
DEFAULT_AGENT_KEYS = [
    "agent.hostname",
    "agent.version",
    "system.uname",
    "system.hostname",
    "system.sw.os",
    "system.cpu.num",
    "vm.memory.size[total]",
    "system.uptime",
]


@dataclass
class AgentConfig:
    hostname: Optional[str] = None
    host_metadata: Optional[str] = None
    servers: List[str] = field(default_factory=list)
    server_active: List[str] = field(default_factory=list)
    listen_port: Optional[int] = None
    raw: Dict[str, str] = field(default_factory=dict)


def _iter_config_lines(path: str, _seen: Optional[set] = None) -> List[str]:
    if _seen is None:
        _seen = set()
    real = os.path.realpath(path)
    if real in _seen:
        return []
    _seen.add(real)

    lines: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return lines

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("include="):
            target = line.split("=", 1)[1].strip()
            for included in _expand_include(target):
                lines.extend(_iter_config_lines(included, _seen))
        else:
            lines.append(line)
    return lines


def _expand_include(target: str) -> List[str]:
    # Include may point to a file, a directory, or a glob pattern.
    if os.path.isdir(target):
        return sorted(
            os.path.join(target, name)
            for name in os.listdir(target)
            if os.path.isfile(os.path.join(target, name))
        )
    if any(ch in target for ch in "*?["):
        return sorted(glob.glob(target))
    return [target]


def parse_agent_config(path: str) -> AgentConfig:
    """Parse a ``zabbix_agentd.conf`` / ``zabbix_agent2.conf`` file."""

    cfg = AgentConfig()
    if not path or not os.path.exists(path):
        return cfg

    for line in _iter_config_lines(path):
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        cfg.raw[key] = value
        lkey = key.lower()
        if lkey == "hostname":
            cfg.hostname = value
        elif lkey == "hostmetadata":
            cfg.host_metadata = value
        elif lkey == "server":
            cfg.servers = [v.strip() for v in value.split(",") if v.strip()]
        elif lkey == "serveractive":
            cfg.server_active = [v.strip() for v in value.split(",") if v.strip()]
        elif lkey == "listenport":
            try:
                cfg.listen_port = int(value)
            except ValueError:
                pass
    return cfg


def resolve_hostname(agent_cfg: AgentConfig, override: Optional[str] = None) -> str:
    if override:
        return override
    if agent_cfg.hostname and agent_cfg.hostname.lower() != "hostname":
        return agent_cfg.hostname
    return socket.gethostname()


def zabbix_get_available(binary: str = "zabbix_get") -> bool:
    return shutil.which(binary) is not None


def query_agent_key(key: str, binary: str = "zabbix_get", host: str = "127.0.0.1") -> Optional[str]:
    if not zabbix_get_available(binary):
        return None
    try:
        out = subprocess.run(
            [binary, "-s", host, "-k", key],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    value = out.stdout.strip()
    if not value or value.startswith("ZBX_NOTSUPPORTED"):
        return None
    return value


def _fallback_params() -> Dict[str, object]:
    params: Dict[str, object] = {
        "system.hostname": socket.gethostname(),
        "system.uname": " ".join(platform.uname()),
        "os.system": platform.system(),
        "os.release": platform.release(),
        "os.machine": platform.machine(),
        "cpu.num": os.cpu_count(),
        "python.version": platform.python_version(),
    }
    meminfo = _read_meminfo()
    if meminfo is not None:
        params["memory.total_kb"] = meminfo
    loadavg = _read_loadavg()
    if loadavg is not None:
        params["loadavg"] = loadavg
    interfaces = _read_interfaces()
    if interfaces:
        params["net.interfaces"] = interfaces
    return params


def _read_meminfo() -> Optional[int]:
    try:
        with open("/proc/meminfo", "r", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return None
    return None


def _read_loadavg() -> Optional[str]:
    try:
        with open("/proc/loadavg", "r", encoding="ascii") as fh:
            return fh.read().split()[0]
    except (OSError, IndexError):
        return None


def _read_interfaces() -> List[str]:
    ifaces: List[str] = []
    try:
        with open("/proc/net/dev", "r", encoding="ascii") as fh:
            for line in fh.readlines()[2:]:
                name = line.split(":", 1)[0].strip()
                if name and name != "lo":
                    ifaces.append(name)
    except OSError:
        pass
    return ifaces


def collect_host_params(
    agent_conf_path: str,
    zabbix_get_bin: str = "zabbix_get",
    keys: Optional[List[str]] = None,
    hostname_override: Optional[str] = None,
) -> Dict[str, object]:
    """Return a dict of host parameters, preferring the Zabbix agent.

    Always includes a resolved ``hostname`` and ``host_metadata`` (if set in the
    agent config).  Falls back to procfs/:mod:`platform` values when the agent
    cannot be queried.
    """

    agent_cfg = parse_agent_config(agent_conf_path)
    hostname = resolve_hostname(agent_cfg, hostname_override)

    params: Dict[str, object] = {
        "hostname": hostname,
        "source": "fallback",
    }
    if agent_cfg.host_metadata:
        params["host_metadata"] = agent_cfg.host_metadata
    if agent_cfg.servers:
        params["zabbix_server"] = agent_cfg.servers
    if agent_cfg.server_active:
        params["zabbix_server_active"] = agent_cfg.server_active

    queried_any = False
    if zabbix_get_available(zabbix_get_bin):
        for key in keys or DEFAULT_AGENT_KEYS:
            value = query_agent_key(key, binary=zabbix_get_bin)
            if value is not None:
                params[key] = value
                queried_any = True

    # Always merge fallback values for keys the agent did not answer.
    for k, v in _fallback_params().items():
        params.setdefault(k, v)

    params["source"] = "zabbix_agent" if queried_any else "fallback"
    return params


def send_via_sender(
    server: str,
    host: str,
    items: Dict[str, object],
    binary: str = "zabbix_sender",
    port: int = 10051,
) -> bool:
    """Push ``key -> value`` items to a Zabbix trapper via ``zabbix_sender``.

    Returns True on success.  Values are sent one per line on stdin using the
    ``-i -`` batch input format.
    """

    if not shutil.which(binary):
        return False
    payload_lines = [f'"{host}" "{key}" "{value}"' for key, value in items.items()]
    payload = "\n".join(payload_lines) + "\n"
    try:
        out = subprocess.run(
            [binary, "-z", server, "-p", str(port), "-i", "-"],
            input=payload,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return out.returncode == 0
