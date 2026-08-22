"""One drain-loop pattern for every background capture thread.

Cross-cutting finding behind SEC-010, SEC-013, SEC-014 and CODE-026: each
capture thread caught a hand-picked tuple of exceptions around its parse step
(``OSError``, ``IndexError``, sometimes ``struct.error``), and every one of
those tuples was missing something the parser could actually raise. When it
did, the exception unwound ``run()``, the thread exited, the collector kept
running as if nothing had happened, and the first sign of trouble was a report
with no DNS names or no SNI in it -- days later.

The rule these helpers encode:

* one malformed input must never end the thread -- log it, count it, continue;
* the thread's own outer loop must also be guarded, so a bug in the
  *handling* code cannot silently kill capture either;
* both are visible: a counter for tests and health output, a log line with a
  traceback for humans.

Deliberately narrow: no retries, no backoff, no state. Backoff belongs to the
loop that knows what it is reconnecting to.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Iterator, Optional


class DrainCounters:
    """Per-thread tallies of what the guards swallowed."""

    __slots__ = ("dropped_items", "loop_errors")

    def __init__(self) -> None:
        self.dropped_items = 0
        self.loop_errors = 0

    def as_dict(self) -> dict:
        return {
            "dropped_items": self.dropped_items,
            "loop_errors": self.loop_errors,
        }


@contextmanager
def drain_item(
    log: logging.Logger, what: str, counters: Optional[DrainCounters] = None
) -> Iterator[None]:
    """Swallow any failure while handling ONE item from a stream.

    ``BaseException`` subclasses that are not ``Exception`` -- KeyboardInterrupt,
    SystemExit, GeneratorExit -- deliberately propagate: those mean "stop", not
    "this message was malformed". RecursionError and struct.error do not, which
    is the whole point.
    """

    try:
        yield
    except Exception as exc:  # noqa: BLE001 - see module docstring
        if counters is not None:
            counters.dropped_items += 1
        log.debug("%s: dropped one item (%s: %s)", what, type(exc).__name__, exc)


@contextmanager
def drain_iteration(
    log: logging.Logger, what: str, counters: Optional[DrainCounters] = None
) -> Iterator[None]:
    """Swallow any failure in one pass of a thread's outer loop.

    Logged at warning with a traceback: unlike a malformed packet, reaching
    here means our own code failed and somebody should look at it.
    """

    try:
        yield
    except Exception as exc:  # noqa: BLE001 - see module docstring
        if counters is not None:
            counters.loop_errors += 1
        log.warning("%s: loop iteration failed (%s)", what, exc, exc_info=True)
