# Changelog

All notable changes to Commatrix are documented in this file.

## [Unreleased] — Medium/Low remediation

Closes the remaining Medium, Low and Info findings from the review of `344112e`, plus the review's cross-cutting recommendations. Regression coverage: 244 → 401 tests; line coverage of the `commatrix` package is 71%.

Every regression test in this release was verified by temporarily reverting its fix and confirming the test fails. Where that check is not meaningful — the SEC-012 test *hangs* against the old code rather than failing — it is called out in the test file.

### Security

- **Bounded caches (SEC-009, SEC-027)** — The DNS and SNI IP→name maps were plain dicts pruned by TTL only once past 20000 entries, which is not a bound: 20001 distinct destinations inside the 15-minute window prune nothing. All of them now use `IpNameCache`, an LRU with a hard ceiling *and* a TTL.
- **DNS monitor input handling (SEC-012, SEC-013)** — The varlink receive buffer is capped at 1 MiB, and a deeply nested payload no longer raises `RecursionError` out of the monitor thread, which used to leave the collector running with DNS enrichment silently dead.
- **Injection in outputs (SEC-015, SEC-021)** — `zabbix_sender` batch fields are quoted and escaped (a value with a quote could append items for other hosts); every markdown emitter neutralises HTML, pipes and control characters, so a PTR record of `<img src=x onerror=…>` is no longer script execution wherever the report is rendered.
- **Windows secrets and ACLs (SEC-023, SEC-025)** — The service account password no longer touches any command line: the account is managed through PowerShell on stdin and the scheduled task is registered from an S4U XML definition that needs no password. The data-at-rest ACL now includes the account the collector actually runs as, and `elevate-windows` re-ACLs pre-existing files — without this, elevation reliably produced "Access Denied", whose obvious operator fix is to put the task back on SYSTEM.
- **Windows parsing (SEC-026, SEC-028, SEC-029)** — `GetExtendedTcpTable` retries the racy two-call sizing pattern instead of dropping a whole address family; event-log XML rejects DTD/entity declarations; kernel32 calls declare `argtypes`/`restype` so 64-bit handles are not truncated.
- **Supply chain (SEC-033, SEC-034, SEC-035, SEC-036, SEC-037, SEC-040, SEC-041, SEC-042, SEC-044, SEC-045)** — The MSI verifies the embedded CPython against a recorded SHA256 before unpacking it; the Ansible deploy stops defaulting to root, refuses a mutable git ref, runs `elevate-windows`, and uses `win_command` instead of interpolated `win_shell`; release artifacts and the container image are signed with cosign; the image carries SLSA provenance and an SBOM; and `packaging/pin_supply_chain.py` resolves and enforces the Action, base-image and interpreter pins, checked offline by CI.

### Correctness

- **False inter-host edges (CODE-017)** — `_ip_to_host()` assumed an IP identifies one machine. In a fleet where every box runs a docker bridge, `172.17.0.2` collapsed onto whichever host was processed last and every other host's container traffic was drawn as an edge into that machine. Merging a peer into a named host node now requires the address to provably identify exactly one host; genuine inter-VM edges still link.
- **Per-edge data quality (CODE-030)** — Windows `data_quality` was one host-wide boolean, so a single ESTATS-capable TCP connection marked every edge on the host — UDP included — as byte-accurate.
- **Version stamping (CODE-033)** — `re.sub` returns its input unchanged when nothing matches, so a renamed field silently produced a release stamped with the previous version. It now aborts.

### Resource safety

- **Per-poll work (CODE-010, CODE-011, CODE-014, CODE-028)** — One `/proc` walk per poll instead of one per network namespace; package resolution budgeted (16 lookups / 2 s) instead of up to 200 serial 5-second subprocesses; the `zabbix_get` batch shares a 6-second deadline and fails fast; `tasklist /svc` is cached for 60 s.
- **Reconnects and reclaim (CODE-013, CODE-016)** — A clean EOF from systemd-resolved no longer produces a busy reconnect loop (exponential backoff, 1 s → 60 s); `prune_to_budget()` reclaims incrementally instead of running up to 21 full VACUUMs on the almost-full disk that triggered it.
- **Duplicate DNS rows (CODE-027)** — `WinDnsMonitor` tracks the highest ingested `EventRecordID`; it previously re-recorded the same events roughly 3.4 million times a day.
- **Job Object limits (CODE-029)** — Every Win32 BOOL return is checked, so `apply_job_limits()` no longer reports a hard ceiling that does not exist.

### Cross-cutting

- **One drain-loop pattern** — Each capture thread caught a hand-picked exception tuple around its parse step, and every tuple was missing something the parser could raise; when it did, the thread exited and the collector kept reporting success. `commatrix/threadguard.py` now holds the single pattern, used by `ctnetlink`, `dns`, `sni`, `winsni` and `winetw`, each exposing `drain_counters` so dropped messages are countable.
- **Permission constants (CODE-023)** — One source of truth in `commatrix.platform`; `store.DB_FILE_MODE` was declared but never applied.
- **Schema guard** — `_migrate()` never read `meta.schema_version` and `INSERT OR IGNORE` pinned every pre-existing database to its creation version, so an older binary would open and half-write a newer database. Opening a newer schema now raises `SchemaVersionError`.
- **Clean shutdown (CODE-006)** — The push server handles SIGTERM/SIGHUP, so `systemctl stop` no longer cuts in-flight `/ingest` writes.

### Verification the review deferred to "a real machine"

Three of those items turned out to be runnable offline, so they now run in CI (`hardening` and `container-uid` jobs) instead of once by hand — and running them found two things.

- **`visudo -cf`** on both generated sudoers drop-ins: parse OK, including for a `firstname.lastname` account.
- **`systemd-analyze security --offline=true`** (systemd 255 does not need a running systemd for this) on every unit and on the collector unit with each `elevate-linux` drop-in merged in. This surfaced a real inversion: the whole sandbox block lived inside the `attribution` branch, so **`--profile topology` — the profile you pick when you want *less* privilege — produced a *less* confined service than `attribution`, and a slightly worse one than not elevating at all** (exposure 6.5 vs 5.2 vs 6.4). The profile-independent confinement now applies to both. Exposure after: collector 6.4 → 4.6, export 5.3 → 1.2, merged attribution 5.2 → 4.4, merged topology 6.5 → 4.3. `packaging/check_hardening.py` holds a per-unit budget so a regression fails the build.
- **`ProtectSystem=strict` vs `StateDirectory`**: no conflict — `StateDirectory=`/`RuntimeDirectory=` are writable under `strict` automatically. But an operator who points `database`, `html_report_path` or `snapshot_dir` outside `/var/lib/commatrix` hits a read-only filesystem at the first write, long after elevate reported success; `elevate-linux` now reads the config and emits matching `ReadWritePaths`.
- **Container UID 65532** — this was a bug, and not the one the note in the Dockerfile predicted. The constraint is the *database* directory, not the output directory: the database is in WAL mode and a read-only WAL reader still has to create the `-shm` file next to it, which needs write permission on that directory. The documented split (`collect` as `--user 0`, `report` as the default 65532) failed with `attempt to write a readonly database` on its first SELECT — so every documented `report`/`export`/`aggregate` invocation in the container was broken. Read-only opens now fall back to SQLite's `immutable=1` and warn about what that gives up (WAL contents, concurrent-writer safety). The `container-uid` CI job reproduces the exact UID split without a Docker daemon.

Deliberately **not** applied, with the reasons recorded next to them so the `systemd-analyze` findings are not "fixed" later by someone without the context: `ProtectKernelTunables=true` (toggling the `nf_conntrack` sysctls is the collector's job), `RestrictAddressFamilies=` on the collector (it needs `AF_UNIX`, `AF_NETLINK`, `AF_INET`/`AF_INET6`, plus `AF_PACKET` when SNI is on — an allow list that omits `AF_PACKET` breaks SNI silently), `UMask=0077` (the data is intentionally group-readable by the `commatrix` group), and `IPAddressDeny=any` on the export unit (it doubles as the `push` transport).

### Supply-chain pins, filled in

`SEC-040` all fifteen Actions are pinned to commit SHAs, `SEC-044` the base image to the multi-arch index digest `sha256:2c941e86…63c4a`, and `SEC-033` the embedded CPython is verified by signature. Enforcement is on, so a regression now fails the build.

Two things worth knowing about how those were produced:

- The resolver was rewritten from the REST API to `git ls-remote`. The API returned a *different* commit for `actions/checkout@v4` than the tag actually points at, and more importantly it hides the annotated-tag problem: for four of the fifteen actions (`attest-build-provenance`, `snapcore/action-build`, `flatpak-github-actions`, `cosign-installer`) `refs/tags/vX` advertises the **tag object's** SHA, not the commit's — and a workflow pinned to a tag-object SHA does not run. `ls-remote` asks for the peeled value, has no rate limit, and is the ref advertisement itself rather than a field in a JSON summary. Every SHA is then independently confirmed with `git fetch --depth 1 <sha>`; `--write` refuses to record a value it cannot fetch back.
- `SEC-033` is not a hash pin. python.org publishes only an MD5 beside each download, and chosen-prefix collisions against MD5 are practical, so it establishes nothing against an attacker who can serve a different file. The build now verifies the **Sigstore bundle** python.org publishes alongside the artifact, which proves who produced it and does not need a fresh value for every patch release. The release-manager identities live in `packaging/windows/python-embed-trust.json`, copied from python.org's own table — note the OIDC issuer is *not* Google for every series, and hardcoding one would silently verify against the wrong thing. A recorded SHA256 remains an optional second check for reproducibility.

### Verification, round two

The remaining "verify on a real host" items were run rather than reasoned about, and two of them found bugs.

- **`commatrix serve` and SIGTERM (CODE-006, the other half).** Handling the signal was not enough. `ThreadingHTTPServer` runs handlers on daemon threads, so once `serve_forever()` returns the interpreter exits and anything mid-request dies where it stands. Measured: SIGTERM during an `/ingest` merge gave the client an empty reply and wrote **zero rows** — the snapshot that agent had just spent a poll interval producing was gone, with no error on either side. Shutdown now waits for in-flight handlers, with a 30-second deadline so one wedged request cannot stop the unit from stopping.
- **`--profile topology` costs far more than "less attribution".** Measured on a 37-socket container: **92% of sockets attributed under `attribution` versus 8% under `topology`, and 0% of the sockets owned by another user.** Without `CAP_DAC_READ_SEARCH` the collector cannot read `/proc/<pid>/fd` for other users' processes at all, so it is a topology-only profile in practice. That number is now in the `--profile` help and in the warning `elevate-linux` prints, and `packaging/measure_attribution.py` measures it on any host under any profile.
- **`--revoke`'s new unit-User check does not cry wolf**: it stays silent when the user matches, distinguishes "could not read" from "drifted", and is skipped when there was no daemon-reload.

### Verification, round three: the deployment glue

The Ansible playbooks had never been run through Ansible — they are deployment glue, not Python, so the test suite never reached them. Doing it found a bug older than the review:

- **`ansible/collect.yml` referenced `ansible.windows.win_fetch`, a module that does not exist and never has.** The Windows snapshot play could not be parsed, let alone collect anything, and it was already broken at `344112e`. Fixed to `ansible.builtin.fetch`, which is what the Linux play four lines above already used.
- Nothing declared which collections a control node needs, which is exactly why nobody noticed: without `ansible.windows` installed the play fails the same way whether the module exists or not. Added `ansible/requirements.yml`.
- `ansible-lint` now passes at the **production** profile, and the SEC-035 mutable-ref guard is executed both ways in CI — silent for a pinned version, failing the run with its intended message for `main`, and honouring the escape hatch.
- The `changed_when` expressions now tolerate a missing `stdout`, so a skipped task cannot turn CODE-034's fix into a new undefined-attribute error.

Also closed as far as this environment allows:

- **Dockerfile**: parses, BuildKit accepts the digest-pinned `FROM`, and `docker buildx build --check` reports no warnings. The actual build and `imagetools inspect` still need registry access.
- **The S4U task XML** is validated against Microsoft's documented schema sequences for `Task`, `Settings`, `Principal` and `Exec`. Task Scheduler uses `xsd:sequence`, not `xsd:all`, so otherwise-valid XML in the wrong order is rejected at registration — the one step that cannot be tried without a Windows host.
- **The sigstore invocation**: `--bundle`, `--cert-identity` and `--cert-oidc-issuer` all exist, with those exact spellings, in sigstore 4.5.0.

### Notes on the review itself

- **SEC-028** could not be fixed the way it is usually written. The standard approach — hooking expat through `XMLParser.parser` — does nothing on Python 3.9+, because `xml.etree` no longer exposes that attribute; code written that way passes its own tests while providing no protection. Replaced with a pre-parse rejection of DOCTYPE/ENTITY/NOTATION markup.
- **SEC-040 / SEC-044 / SEC-033** are enforced but not pre-filled. The check starts in warn mode (`packaging/supply-chain-policy.json`, `enforce: false`) and emits GitHub warning annotations rather than failing: the pins can only be produced by a run with network access, which a pull request cannot provide, and a build that is red on arrival for a reason nobody can fix from a PR is a build people stop reading. `--write` flips enforcement on automatically once nothing is left unpinned; `--check --enforce` fails immediately for anyone who prefers that.
- **SEC-040 / SEC-044 / SEC-033**, on why they are not hardcoded: A plausible-looking wrong digest breaks every build and teaches everyone to bypass the check, so the pins are produced by `python packaging/pin_supply_chain.py --write` (one command, needs network) and verified offline by CI.

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
