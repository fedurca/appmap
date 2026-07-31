# Changelog

All notable changes to Commatrix are documented in this file.

## [1.1.0] — 2026-07-31

Security and correctness release addressing findings from the code/security review of revision `344112e` (`commatrix-review.pdf`). All Critical (5/5) and High (6/6) findings are closed, plus the highest-impact Medium issues that caused irreversible data loss or cross-host data leakage. Regression coverage: 155 → 244 tests.

### Security

- **Privilege model (SEC-005, SEC-006, SEC-008, SEC-022)** — Added `--profile topology` (NET_ADMIN + NET_RAW only) and `--profile attribution` (default). Attribution is constrained with seccomp + mount namespace hiding of sensitive paths. Windows no longer grants `SeDebugPrivilege` by default (`--allow-sedebug` opt-in). Residual risk is warned at elevate time instead of claiming “no path to root”.
- **Install / delegation root paths (SEC-030, SEC-031, SEC-032, CODE-032)** — Closed journalctl pager escape via sudoers, lab sudoers + `--config` / PYTHONPATH root RCE, and Bash arithmetic injection via `--cpu-percent`.
- **Push server defaults (SEC-001, SEC-002, SEC-003, SEC-004, SEC-014, SEC-020, SEC-046)** — `serve` requires `--token`, default bind is `127.0.0.1`, constant-time token compare, token no longer exposed via argv; DoS/resource limits and tests added.
- **Systemd units (SEC-038, SEC-039)** — Server unit requires `EnvironmentFile` for the token; export unit runs as `commatrix` (not root); unit files no longer ship world-readable secrets.
- **Broken revoke (SEC-007, SEC-024, CODE-025)** — Re-apply no longer overwrites the saved “before” state, so `--revoke` actually restores prior privileges on Linux and Windows.
- **Containers (SEC-043, SEC-044 partial)** — Docs/Dockerfile drop `--privileged` in favor of `--cap-drop ALL` + needed caps; image runs as UID 65532. Base-image digest pin (SEC-044) remains a TODO.
- **Stored XSS / CSV injection (SEC-017, SEC-018)** — Mermaid topology labels are escaped; CSV formula cells are neutralized.
- **Parser / resource resilience (SEC-010, SEC-011, SEC-016, SEC-019, CODE-003, CODE-004, CODE-020)** — Hardened parsers and resource bounds so background collectors fail closed instead of silently dying.

### Correctness & performance

- **Merge data loss (CODE-015)** — Snapshot merge uses `COALESCE` so missing fields no longer wipe existing `first_seen`, `max_gap`, `bytes`, and `observations`.
- **Cross-host leakage (CODE-018, CODE-019)** — Host scoping applied to `topology_dot()`, `topology_mermaid()`, `build_catalog()`, and related report paths.
- **Resource budget (CODE-002, CODE-031)** — Retention prune and edge writes batched (large speedups); Windows CPU governor fixed to measure correctly without `children_*` times.
- **Other integrity fixes (CODE-021, CODE-022)** — Additional store/aggregate integrity and scoping corrections.

### Breaking changes

| Before | After |
| --- | --- |
| `commatrix serve` without `--token` started | Refuses to start |
| `commatrix serve --host` default `0.0.0.0` | Default `127.0.0.1` |
| `commatrix-server.service` worked without token | Requires `/etc/commatrix/server.env` |
| `commatrix-export.service` ran as root | Runs as `commatrix` |
| `elevate-windows` granted `SeDebugPrivilege` | Opt-in `--allow-sedebug` |
| Docker documented as `--privileged` / root | Cap-drop + non-root UID 65532 |

### Documentation

- README (CS/EN) privilege claims corrected; remediation TODO list in `todo.txt` for remaining Medium/Low findings.

## [1.0.0] — 2026-07

Initial packaged release (WiX/MSI, multi-format packaging, CI/CD, dual READMEs, elevation helpers).
