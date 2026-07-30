"""Configuration handling for commatrix.

Configuration is stored in a simple INI file parsed with :mod:`configparser`
(standard library).  All settings have sane defaults so the tool runs without a
configuration file; a file only needs to override what differs from the
defaults.

Example ``/etc/commatrix/commatrix.conf``::

    [collector]
    poll_interval = 5
    database = /var/lib/commatrix/commatrix.db
    source = auto

    [network]
    internal_cidrs = 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12

    [zabbix]
    agent_conf = /etc/zabbix/zabbix_agentd.conf
    zabbix_get = /usr/bin/zabbix_get

    [export]
    snapshot_dir = /var/lib/commatrix/snapshots
"""

from __future__ import annotations

import configparser
import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional

DEFAULT_CONFIG_PATHS = (
    "/etc/commatrix/commatrix.conf",
    os.path.expanduser("~/.config/commatrix/commatrix.conf"),
)

# Private / non-routable ranges treated as "internal" unless overridden.
DEFAULT_INTERNAL_CIDRS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
    "::1/128",
]

log = logging.getLogger("commatrix.config")


@dataclass
class Config:
    """Resolved runtime configuration."""

    # [collector]
    poll_interval: float = 5.0
    database: str = "/var/lib/commatrix/commatrix.db"
    source: str = "auto"  # auto | procfs | conntrack-events | sockets
    hostname: Optional[str] = None  # override; otherwise derived from zabbix/os
    # Where pre-run nf_conntrack sysctl values are persisted so they can be
    # restored after an unclean exit (see conntrack.SysctlGuard).
    sysctl_state_file: str = "/run/commatrix/sysctl.state"
    # By default commatrix runs unprivileged (topology is still captured;
    # sysctl toggling and full process attribution then need CAP_NET_ADMIN /
    # CAP_DAC_READ_SEARCH or root). Set true to hard-require root.
    require_root: bool = False
    # Append-only IR history: log a "reactivated" event when an edge becomes
    # active again after being idle at least this many seconds (0 = only log
    # brand-new edges).
    event_min_gap_seconds: float = 60.0

    # [network]
    internal_cidrs: List[str] = field(default_factory=lambda: list(DEFAULT_INTERNAL_CIDRS))
    resolve_external: bool = False  # reverse-DNS external peers (can be slow)

    # [zabbix]
    agent_conf: str = "/etc/zabbix/zabbix_agentd.conf"
    zabbix_get: str = "zabbix_get"
    zabbix_sender: str = "zabbix_sender"

    # [export]
    snapshot_dir: str = "/var/lib/commatrix/snapshots"
    html_report: bool = True  # write HTML dashboard when a collect session ends
    html_report_path: Optional[str] = None  # default: <database>-report.html

    # [signatures]
    signatures_dir: Optional[str] = None  # None -> packaged defaults

    # [dns]
    dns_enabled: bool = True  # log DNS queries via systemd-resolved monitor
    dns_enrich_flows: bool = True  # annotate flows with the resolved domain

    # [time]
    # Optional NTP server for an active SNTP offset probe (UDP/123). When empty,
    # the offset is read from the local sync daemon only (no network).
    ntp_check_server: Optional[str] = None

    # [capture]
    # Capture mode: auto (event-driven when a conntrack event source is
    # available, else polling), events (force event-driven), poll (force polling).
    capture_mode: str = "auto"
    # Network-namespace scope: auto/all enumerate container/other netns via
    # /proc/<pid>/net/* (needs root); host-only reads just the host namespace.
    netns_scope: str = "auto"  # auto | host-only | all

    # [sni]
    sni_enabled: bool = False  # opt-in AF_PACKET TLS ClientHello SNI capture
    sni_interface: Optional[str] = None  # None -> all interfaces
    sni_ports: List[int] = field(default_factory=lambda: [443, 853])

    # [resources]
    cpu_budget_percent: float = 10.0  # max % of TOTAL compute (all cores)
    disk_budget_percent: float = 10.0  # max % of free disk the DB may use
    min_free_disk_percent: float = 5.0  # pause writes below this free %
    retention_days: float = 30.0  # drop edges not seen within this window
    memory_max_mb: int = 128  # advisory; enforced by systemd MemoryMax

    @property
    def internal_cidr_list(self) -> List[str]:
        return self.internal_cidrs

    @property
    def cpu_budget(self) -> float:
        return self.cpu_budget_percent / 100.0

    @property
    def disk_budget(self) -> float:
        return self.disk_budget_percent / 100.0

    @property
    def min_free_disk(self) -> float:
        return self.min_free_disk_percent / 100.0


def _typed(sec, key, default, kind, section):
    """Read one typed config value, falling back to the default on garbage.

    CODE-021: configparser's getfloat/getint/getboolean raise ValueError on a
    malformed value, and nothing caught it -- so a single typo such as
    ``require_root = enabled`` stopped the collector from starting at all,
    with a traceback rather than a diagnosis. A bad value now degrades to the
    default and says so.
    """

    if key not in sec:
        return default
    try:
        if kind == "float":
            return sec.getfloat(key, default)
        if kind == "int":
            return sec.getint(key, default)
        if kind == "bool":
            return sec.getboolean(key, default)
    except ValueError:
        log.warning(
            "config [%s] %s=%r is not a valid %s; using default %r",
            section, key, sec.get(key), kind, default,
        )
    return default


def _split_list(value: str) -> List[str]:
    parts = []
    for chunk in value.replace("\n", ",").split(","):
        chunk = chunk.strip()
        if chunk:
            parts.append(chunk)
    return parts


def load_config(path: Optional[str] = None) -> Config:
    """Load configuration from *path* or the first default location found.

    Missing files are not an error; defaults are used.
    """

    cfg = Config()
    parser = configparser.ConfigParser()

    candidate_paths: List[str] = []
    if path:
        candidate_paths.append(path)
    else:
        candidate_paths.extend(DEFAULT_CONFIG_PATHS)

    existing = [p for p in candidate_paths if os.path.exists(p)]
    read = parser.read(existing)
    # CODE-022: configparser silently skips a file it cannot open, so an
    # unreadable /etc/commatrix/commatrix.conf looked exactly like "no config"
    # and the collector came up on defaults -- wrong database, wrong budgets,
    # no clue why. Say something.
    for candidate in existing:
        if candidate not in read:
            log.warning(
                "config %s exists but could not be read (permissions?); "
                "continuing with defaults for its settings", candidate
            )
    if not read:
        if path:
            log.warning("config %s not found or unreadable; using defaults", path)
        return cfg

    if parser.has_section("collector"):
        sec = parser["collector"]
        cfg.poll_interval = _typed(sec, "poll_interval", cfg.poll_interval, "float", "collector")
        cfg.database = sec.get("database", cfg.database)
        cfg.source = sec.get("source", cfg.source)
        cfg.hostname = sec.get("hostname", cfg.hostname)
        cfg.sysctl_state_file = sec.get("sysctl_state_file", cfg.sysctl_state_file)
        cfg.require_root = _typed(sec, "require_root", cfg.require_root, "bool", "collector")
        cfg.event_min_gap_seconds = _typed(sec, "event_min_gap_seconds", cfg.event_min_gap_seconds, "float", "collector")

    if parser.has_section("network"):
        sec = parser["network"]
        if "internal_cidrs" in sec:
            cfg.internal_cidrs = _split_list(sec["internal_cidrs"])
        cfg.resolve_external = _typed(sec, "resolve_external", cfg.resolve_external, "bool", "network")

    if parser.has_section("zabbix"):
        sec = parser["zabbix"]
        cfg.agent_conf = sec.get("agent_conf", cfg.agent_conf)
        cfg.zabbix_get = sec.get("zabbix_get", cfg.zabbix_get)
        cfg.zabbix_sender = sec.get("zabbix_sender", cfg.zabbix_sender)

    if parser.has_section("export"):
        sec = parser["export"]
        cfg.snapshot_dir = sec.get("snapshot_dir", cfg.snapshot_dir)
        cfg.html_report = _typed(sec, "html_report", cfg.html_report, "bool", "export")
        cfg.html_report_path = sec.get("html_report_path", cfg.html_report_path)

    if parser.has_section("signatures"):
        sec = parser["signatures"]
        cfg.signatures_dir = sec.get("dir", cfg.signatures_dir)

    if parser.has_section("dns"):
        sec = parser["dns"]
        cfg.dns_enabled = _typed(sec, "enabled", cfg.dns_enabled, "bool", "dns")
        cfg.dns_enrich_flows = _typed(sec, "enrich_flows", cfg.dns_enrich_flows, "bool", "dns")

    if parser.has_section("time"):
        sec = parser["time"]
        cfg.ntp_check_server = sec.get("ntp_check_server", cfg.ntp_check_server) or None

    if parser.has_section("capture"):
        sec = parser["capture"]
        cfg.capture_mode = sec.get("mode", cfg.capture_mode)
        cfg.netns_scope = sec.get("netns", cfg.netns_scope)

    if parser.has_section("sni"):
        sec = parser["sni"]
        cfg.sni_enabled = _typed(sec, "enabled", cfg.sni_enabled, "bool", "sni")
        cfg.sni_interface = sec.get("interface", cfg.sni_interface) or None
        if "ports" in sec:
            cfg.sni_ports = [int(p) for p in _split_list(sec["ports"]) if p.isdigit()]

    if parser.has_section("resources"):
        sec = parser["resources"]
        cfg.cpu_budget_percent = _typed(sec, "cpu_budget_percent", cfg.cpu_budget_percent, "float", "resources")
        cfg.disk_budget_percent = _typed(sec, "disk_budget_percent", cfg.disk_budget_percent, "float", "resources")
        cfg.min_free_disk_percent = _typed(sec, "min_free_disk_percent", cfg.min_free_disk_percent, "float", "resources")
        cfg.retention_days = _typed(sec, "retention_days", cfg.retention_days, "float", "resources")
        cfg.memory_max_mb = _typed(sec, "memory_max_mb", cfg.memory_max_mb, "int", "resources")

    return cfg
