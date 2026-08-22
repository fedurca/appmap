# commatrix container image (standard-library only; no pip install needed).
#
# Report and aggregate need no extra privileges at all:
#   docker run --rm -v /var/lib/commatrix:/var/lib/commatrix \
#     ghcr.io/fedurca/commatrix:latest report -f html --database /var/lib/commatrix/central.db
#
# Live capture needs host visibility. Grant exactly the capabilities the
# collector uses and nothing more:
#   docker run --rm --network host --pid host --user 0 \
#     --cap-drop ALL \
#     --cap-add NET_ADMIN --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH \
#     -v /var/lib/commatrix:/var/lib/commatrix \
#     ghcr.io/fedurca/commatrix:latest collect --allow-manual --database /var/lib/commatrix/commatrix.db
#
# Do NOT use --privileged. It disables seccomp, AppArmor/SELinux and the
# device cgroup and grants every capability, which is a trivial host escape --
# the exact opposite of the least-privilege model the elevate-linux and
# elevate-windows paths are built around. --cap-add of the three capabilities
# above is strictly more restrictive and is all the collector needs.
# SEC-044: the base image is pinned to a digest. A tag is mutable -- the same
# Dockerfile would build different software on different days with nothing to
# roll back to. Digest resolved from Docker Hub for the multi-arch index (NOT
# a single-arch manifest: the release builds linux/amd64 and linux/arm64 from
# the same line), last updated upstream 2026-08-16.
#
# Refresh with:  python packaging/pin_supply_chain.py --write
# Dependabot (docker ecosystem) opens the update PRs; the supply-chain-pins CI
# job fails if the digest is ever dropped.
FROM python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a

ARG VERSION=0.0.0
LABEL org.opencontainers.image.title="commatrix" \
      org.opencontainers.image.description="Stdlib-only network communication matrix and application catalog" \
      org.opencontainers.image.source="https://github.com/fedurca/appmap" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.opencontainers.image.version="${VERSION}"

# Copy the package (no build/pip: it is standard-library only).
COPY commatrix /opt/commatrix/commatrix
COPY pyproject.toml README.md LICENSE /opt/commatrix/

ENV PYTHONPATH=/opt/commatrix \
    PYTHONUNBUFFERED=1
WORKDIR /opt/commatrix

# Default to an unprivileged UID (SEC-044). Live capture overrides this with
# --user 0 plus the three --cap-add flags above.
#
# Verified, and it was not what the note here used to claim: the constraint is
# the DATABASE directory, not the output directory. The database runs in WAL
# mode, and a read-only WAL reader still has to create the -shm file beside it,
# which needs write permission on that directory. With `collect` run as
# --user 0 and `report` as the default 65532, every read-only command used to
# fail with "attempt to write a readonly database" on its first query.
# commatrix now falls back to SQLite immutable mode and warns, so reports work
# either way -- but for a live database, prefer giving 65532 write access to
# the directory so the write-ahead log is included:
#   chown -R 65532:65532 /var/lib/commatrix
# or run with  --user "$(id -u):$(id -g)"  to match the host owner.
RUN useradd --system --uid 65532 --no-create-home --shell /usr/sbin/nologin commatrix
USER 65532:65532

ENTRYPOINT ["python", "-m", "commatrix"]
CMD ["--help"]
