# Commatrix Ansible deployment

Deploy the commatrix collector fleet-wide, then pull each host's local database,
merge them on a control node and generate one analytical overview.

## Layout

| File | Purpose |
|---|---|
| `inventory.example.ini` | sample inventory (copy to `inventory.ini`) |
| `group_vars/all.yml` | tunables (repo/version, config, control-node paths) |
| `templates/commatrix.conf.j2` | managed collector config |
| `deploy.yml` | install/refresh the systemd service on every host |
| `collect.yml` | export + fetch a JSON snapshot from every host |
| `report.yml` | merge snapshots + build the report (control node) |
| `pull_and_report.yml` | `collect.yml` + `report.yml` in one run |

## Prerequisites

- Control node: Ansible + the `commatrix` CLI (for `report.yml`). Install with
  `pip install .` from the repo, or set `commatrix_bin` in `group_vars/all.yml`
  to e.g. `python3 -m commatrix` run from a checkout.
- Managed hosts: Python 3.9+, systemd, SSH with a become-capable user, and
  `git` (or use an internal mirror / the copy-based variant below).

## Usage

```bash
cp inventory.example.ini inventory.ini    # edit hosts

# 1) Deploy (or update) the collector everywhere
ansible-playbook -i inventory.ini deploy.yml

# ... let it collect for a while ...

# 2) Pull all local DBs, merge, and build the analytical overview
ansible-playbook -i inventory.ini pull_and_report.yml
# -> ./commatrix-data/commatrix-report.html (+ matrix.md, security.md, central.db)
```

Run only part of it with `deploy.yml`, `collect.yml` or `report.yml` directly.

## Notes

- **Privileges:** `commatrix_run_as_root: true` (default) runs the service as
  root so you get full cross-user process attribution, `nf_conntrack` byte
  accounting and DNS query logging. Set it to `false` to run as the unprivileged
  `commatrix` user (topology + per-socket bytes still work; DNS logging and
  other-user attribution do not).
- **Snapshots, not raw files:** `collect.yml` uses `commatrix export` (a
  read-only, WAL-consistent JSON dump) rather than copying the live `.db`, so
  there are no locking/corruption issues.
- **Air-gapped / no git on hosts:** point `commatrix_repo` at an internal mirror,
  or replace the `git` task in `deploy.yml` with a `synchronize`/`copy` of a
  local checkout to `{{ commatrix_src_dir }}`.
- **Scheduling:** run `pull_and_report.yml` from cron / AWX / a systemd timer on
  the control node for a recurring fleet overview.
- The merged `central.db` distinguishes hosts by the `host` column; the report's
  topology, matrix, per-host DoH/time posture and coverage stats all work across
  the whole fleet.
