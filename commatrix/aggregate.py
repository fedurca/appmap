"""Aggregate per-host data into a central communication-matrix database.

Two ingest paths are provided:

* JSON snapshots produced by ``commatrix export`` (default file-pull transport).
* Direct merge of per-host SQLite databases.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Iterable, List

from .store import Store

log = logging.getLogger("commatrix.aggregate")


def export_snapshot(db_path: str, out_path: str, host: str = None) -> str:  # type: ignore[assignment]
    """Export a host database to a JSON snapshot file. Returns the path."""

    store = Store(db_path, read_only=True)
    try:
        payload = store.export_dict(host)
    finally:
        store.close()

    directory = os.path.dirname(os.path.abspath(out_path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, mode=0o750, exist_ok=True)
    # Snapshots contain the full topology; do not expose them world-readable.
    fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
    try:
        os.chmod(out_path, 0o640)
    except OSError:
        pass
    return out_path


def import_snapshot_file(central: Store, path: str) -> int:
    with open(path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    return central.import_dict(payload)


def aggregate_snapshots(central_db: str, snapshot_paths: Iterable[str]) -> int:
    """Merge one or more JSON snapshots into the central DB. Returns row count."""

    central = Store(central_db)
    total = 0
    try:
        for path in snapshot_paths:
            try:
                merged = import_snapshot_file(central, path)
                total += merged
                log.info("merged %d flows from %s", merged, path)
            except (OSError, json.JSONDecodeError) as exc:
                log.error("failed to read snapshot %s: %s", path, exc)
    finally:
        central.close()
    return total


def aggregate_databases(central_db: str, db_paths: Iterable[str]) -> int:
    """Merge per-host SQLite databases directly into the central DB."""

    central = Store(central_db)
    total = 0
    try:
        for path in db_paths:
            if os.path.abspath(path) == os.path.abspath(central_db):
                continue
            try:
                src = Store(path)
                try:
                    payload = src.export_dict()
                finally:
                    src.close()
                merged = central.import_dict(payload)
                total += merged
                log.info("merged %d flows from %s", merged, path)
            except Exception as exc:  # noqa: BLE001 - best-effort merge
                log.error("failed to merge database %s: %s", path, exc)
    finally:
        central.close()
    return total


def discover_snapshots(directory: str) -> List[str]:
    if not os.path.isdir(directory):
        return []
    return sorted(
        os.path.join(directory, name)
        for name in os.listdir(directory)
        if name.endswith(".json")
    )
