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
# SEC-044: this base image must be pinned to a digest. A tag is mutable -- the
# same Dockerfile builds different software on different days, and there is
# nothing to roll back to. The pin is not hardcoded here by hand because a
# wrong digest breaks every build; resolve and write it with
#
#   python packaging/pin_supply_chain.py --write
#
# which rewrites this FROM to  python:3.12-slim@sha256:<digest>, and is
# enforced by the supply-chain-pins job in CI. Dependabot (docker ecosystem)
# keeps the digest current afterwards.
FROM python:3.12-slim

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
# --user 0 plus the three --cap-add flags above. Note for report/aggregate: a
# bind-mounted output directory must be writable by UID 65532, or pass
# --user "$(id -u):$(id -g)" to match the host owner.
RUN useradd --system --uid 65532 --no-create-home --shell /usr/sbin/nologin commatrix
USER 65532:65532

ENTRYPOINT ["python", "-m", "commatrix"]
CMD ["--help"]
