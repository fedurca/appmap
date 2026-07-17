"""Detect flows to known encrypted-DNS (DoH/DoT) resolver endpoints.

Complements :mod:`commatrix.dohcheck` (which reports whether DoH is *configured*
off) by flagging flows that actually go to a known DoH/DoT resolver - i.e. a
host is doing encrypted DNS that bypasses the system resolver and DNS logging.
The content is invisible, but the fact that it happens (and to which provider)
is a useful SOC signal.

Signatures live in ``signatures/doh_endpoints.json`` (IP CIDRs + domains +
ports) and are editable. Standard library only.
"""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, field
from typing import List, Optional

_PKG_SIGNATURE_DIR = os.path.join(os.path.dirname(__file__), "signatures")


@dataclass
class DohSignatures:
    doh_ports: set = field(default_factory=lambda: {443})
    dot_ports: set = field(default_factory=lambda: {853})
    # (provider, ip_network) and (provider, domain-substring)
    networks: list = field(default_factory=list)
    domains: list = field(default_factory=list)

    def classify(
        self, peer_ip: Optional[str], port: Optional[int], peer_domain: Optional[str] = None
    ) -> Optional[str]:
        """Return "doh"/"dot" plus provider (e.g. "doh:cloudflare") or None."""

        proto = None
        if port in self.doh_ports:
            proto = "doh"
        elif port in self.dot_ports:
            proto = "dot"
        if proto is None:
            return None

        provider = None
        if peer_ip:
            try:
                addr = ipaddress.ip_address(peer_ip)
                for name, net in self.networks:
                    if addr.version == net.version and addr in net:
                        provider = name
                        break
            except ValueError:
                pass
        if provider is None and peer_domain:
            low = peer_domain.lower()
            for name, dom in self.domains:
                if dom in low:
                    provider = name
                    break
        if provider is None:
            return None
        return f"{proto}:{provider}"


def load_doh_signatures(signatures_dir: Optional[str] = None) -> DohSignatures:
    base = signatures_dir or _PKG_SIGNATURE_DIR
    sig = DohSignatures()
    path = os.path.join(base, "doh_endpoints.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return sig

    sig.doh_ports = set(data.get("doh_ports", [443]))
    sig.dot_ports = set(data.get("dot_ports", [853]))
    for provider in data.get("providers", []):
        name = provider.get("name", "unknown")
        for cidr in provider.get("cidrs", []):
            try:
                sig.networks.append((name, ipaddress.ip_network(cidr, strict=False)))
            except ValueError:
                continue
        for dom in provider.get("domains", []):
            if dom:
                sig.domains.append((name, dom.lower()))
    return sig
