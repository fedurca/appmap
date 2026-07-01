"""Commatrix: network communication matrix and application catalog.

A standard-library-only toolkit for Linux servers (typically running a Zabbix
agent) that observes network flows via ``nf_conntrack``, attributes them to the
owning local process/application, enriches them with Zabbix host parameters and
aggregates data from many hosts into a communication matrix and application
catalog.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
