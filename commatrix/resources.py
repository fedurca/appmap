"""Resource governor: keep the collector from ever hurting the host.

Two hard limits are enforced, using only the standard library:

* **CPU** -- the collector process must never average more than a configurable
  fraction (default 10%) of the host's *total* compute power (all cores).  After
  each poll we measure how much CPU the process actually consumed and sleep long
  enough that the average over the poll cycle stays within budget.  We also back
  off further when the system load average is high.
* **Disk** -- the database must never grow beyond a configurable fraction
  (default 10%) of the free space on its filesystem, and writes are paused if
  free space drops below a hard floor (default 5%).

The process also lowers its own scheduling priority (nice) so it always yields
to real workloads.
"""

from __future__ import annotations

import logging
import os
import shutil
from dataclasses import dataclass

log = logging.getLogger("commatrix.resources")


def cpu_count() -> int:
    return os.cpu_count() or 1


def process_cpu_seconds() -> float:
    """Cumulative CPU seconds used by this process and its children."""

    t = os.times()
    return t.user + t.system + t.children_user + t.children_system


def lower_priority() -> None:
    """Best-effort: run as nicely as possible so we always yield to real work."""

    try:
        os.nice(19)
    except (OSError, AttributeError):
        pass


@dataclass
class DiskStatus:
    total: int
    free: int
    db_bytes: int
    budget_bytes: int
    free_fraction: float

    @property
    def over_budget(self) -> bool:
        return self.db_bytes > self.budget_bytes


class ResourceGovernor:
    def __init__(
        self,
        cpu_budget: float = 0.10,
        disk_budget: float = 0.10,
        min_free_disk: float = 0.05,
        ncpu: int | None = None,
        min_interval: float = 1.0,
        load_backoff_threshold: float = 0.8,
    ):
        self.cpu_budget = max(0.001, cpu_budget)
        self.disk_budget = max(0.001, disk_budget)
        self.min_free_disk = max(0.0, min_free_disk)
        self.ncpu = ncpu or cpu_count()
        self.min_interval = min_interval
        self.load_backoff_threshold = load_backoff_threshold

    # -- CPU -----------------------------------------------------------
    def throttle_sleep(
        self, cpu_used_seconds: float, elapsed_seconds: float, base_interval: float
    ) -> float:
        """Return the number of seconds to sleep after a poll.

        Guarantees that ``cpu_used / (cycle * ncpu) <= cpu_budget`` where the
        cycle is ``elapsed + sleep``.  Never returns less than what is needed to
        respect ``base_interval`` / ``min_interval``.
        """

        cores = self.ncpu
        required_cycle = cpu_used_seconds / (self.cpu_budget * cores)
        target_cycle = max(base_interval, self.min_interval, required_cycle)

        # Extra backoff when the host is already busy.
        try:
            load1 = os.getloadavg()[0]
            if cores and (load1 / cores) > self.load_backoff_threshold:
                target_cycle *= 1.5
        except (OSError, AttributeError):
            pass

        return max(0.0, target_cycle - elapsed_seconds)

    # -- Disk ----------------------------------------------------------
    def disk_status(self, path: str, db_bytes: int) -> DiskStatus:
        directory = os.path.dirname(os.path.abspath(path)) or "."
        try:
            # Cross-platform (Linux + Windows); avoids os.statvfs which is POSIX-only.
            usage = shutil.disk_usage(directory)
        except OSError:
            # Unknown filesystem; report permissive status.
            return DiskStatus(total=0, free=0, db_bytes=db_bytes, budget_bytes=db_bytes + 1, free_fraction=1.0)
        free = usage.free
        total = usage.total
        # Budget is a fraction of what would be free if the DB were removed,
        # so the limit is stable as the DB grows.
        budget = int((free + db_bytes) * self.disk_budget)
        free_fraction = (free / total) if total else 1.0
        return DiskStatus(
            total=total,
            free=free,
            db_bytes=db_bytes,
            budget_bytes=budget,
            free_fraction=free_fraction,
        )

    def should_pause_writes(self, status: DiskStatus) -> bool:
        return status.free_fraction < self.min_free_disk
