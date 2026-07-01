"""Application identification and catalog helpers.

Turns raw per-process/per-port observations into logical application names and
inferred layer-7 protocols using a signature database, and provides drift
detection between two sets of communication edges.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from .processes import ProcessInfo

_PKG_SIGNATURE_DIR = os.path.join(os.path.dirname(__file__), "signatures")


@dataclass
class PortSignature:
    service: str
    l7: Optional[str] = None
    cleartext: bool = False


@dataclass
class ProcessPattern:
    regex: "re.Pattern[str]"
    application: str
    l7: Optional[str] = None


@dataclass
class Signatures:
    ports: Dict[int, PortSignature] = field(default_factory=dict)
    patterns: List[ProcessPattern] = field(default_factory=list)

    def port_info(self, port: int) -> Optional[PortSignature]:
        return self.ports.get(port)

    def match_process(self, text: str) -> Optional[ProcessPattern]:
        for pat in self.patterns:
            if pat.regex.search(text):
                return pat
        return None


def load_signatures(signatures_dir: Optional[str] = None) -> Signatures:
    """Load port and process signatures from *signatures_dir* (or packaged)."""

    base = signatures_dir or _PKG_SIGNATURE_DIR
    sig = Signatures()

    ports_path = os.path.join(base, "ports.json")
    try:
        with open(ports_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for port_str, info in data.get("ports", {}).items():
            try:
                port = int(port_str)
            except ValueError:
                continue
            sig.ports[port] = PortSignature(
                service=info.get("service", f"port-{port}"),
                l7=info.get("l7"),
                cleartext=bool(info.get("cleartext", False)),
            )
    except (OSError, json.JSONDecodeError):
        pass

    patterns_path = os.path.join(base, "process_patterns.json")
    try:
        with open(patterns_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for entry in data.get("patterns", []):
            pattern = entry.get("pattern")
            if not pattern:
                continue
            try:
                regex = re.compile(pattern, re.IGNORECASE)
            except re.error:
                continue
            sig.patterns.append(
                ProcessPattern(
                    regex=regex,
                    application=entry.get("application", "unknown"),
                    l7=entry.get("l7"),
                )
            )
    except (OSError, json.JSONDecodeError):
        pass

    return sig


@dataclass
class ServiceIdentity:
    service_name: str
    l7_protocol: Optional[str]
    cleartext: bool = False
    confidence: str = "low"  # low | medium | high
    source: str = "unknown"  # process | port | fallback


def identify_service(
    service_port: int,
    signatures: Signatures,
    process: Optional[ProcessInfo] = None,
) -> ServiceIdentity:
    """Identify the logical service for a given port and optional process.

    Process signatures take precedence (higher confidence) over port-based
    guesses; the port signature supplies the layer-7 protocol / cleartext flag.
    """

    port_sig = signatures.port_info(service_port)

    if process is not None:
        haystack = " ".join(
            part for part in (process.comm, process.cmdline, process.exe) if part
        )
        match = signatures.match_process(haystack)
        if match is not None:
            return ServiceIdentity(
                service_name=match.application,
                l7_protocol=match.l7 or (port_sig.l7 if port_sig else None),
                cleartext=port_sig.cleartext if port_sig else False,
                confidence="high",
                source="process",
            )
        # Process known but unmatched: use comm as the name.
        if process.comm:
            return ServiceIdentity(
                service_name=process.comm,
                l7_protocol=port_sig.l7 if port_sig else None,
                cleartext=port_sig.cleartext if port_sig else False,
                confidence="medium",
                source="process",
            )

    if port_sig is not None:
        return ServiceIdentity(
            service_name=port_sig.service,
            l7_protocol=port_sig.l7,
            cleartext=port_sig.cleartext,
            confidence="medium",
            source="port",
        )

    return ServiceIdentity(
        service_name=f"port-{service_port}",
        l7_protocol=None,
        cleartext=False,
        confidence="low",
        source="fallback",
    )


# -- drift detection -----------------------------------------------------
EdgeKey = Tuple[str, str, str, str, int]  # host, proto, direction, peer_ip, service_port


def edge_key_from_row(row: Dict[str, object]) -> EdgeKey:
    return (
        str(row.get("host", "")),
        str(row.get("proto", "")),
        str(row.get("direction", "")),
        str(row.get("peer_ip", "")),
        int(row.get("service_port", 0) or 0),
    )


@dataclass
class DriftReport:
    added: List[EdgeKey] = field(default_factory=list)
    removed: List[EdgeKey] = field(default_factory=list)
    common: List[EdgeKey] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed)


def diff_edges(
    baseline: Iterable[Dict[str, object]],
    current: Iterable[Dict[str, object]],
) -> DriftReport:
    """Compare two sets of flow rows and report added/removed communications."""

    base_keys = {edge_key_from_row(r) for r in baseline}
    cur_keys = {edge_key_from_row(r) for r in current}
    report = DriftReport()
    report.added = sorted(cur_keys - base_keys)
    report.removed = sorted(base_keys - cur_keys)
    report.common = sorted(cur_keys & base_keys)
    return report
