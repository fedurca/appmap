# commatrix container. Runs as root with full privileges.
#
# Live capture on the host:
#   docker run --rm --privileged --network host --pid host \
#     -v /var/lib/commatrix:/var/lib/commatrix \
#     ghcr.io/fedurca/commatrix:latest collect --allow-manual \
#     --database /var/lib/commatrix/commatrix.db
#
# Refresh digest with:  python packaging/pin_supply_chain.py --write
FROM python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a

ARG VERSION=0.0.0
LABEL org.opencontainers.image.title="commatrix" \
      org.opencontainers.image.description="Stdlib-only network communication matrix" \
      org.opencontainers.image.source="https://github.com/fedurca/appmap" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.opencontainers.image.version="${VERSION}"

COPY commatrix /opt/commatrix/commatrix
COPY pyproject.toml README.md LICENSE /opt/commatrix/

ENV PYTHONPATH=/opt/commatrix \
    PYTHONUNBUFFERED=1
WORKDIR /opt/commatrix
USER root

ENTRYPOINT ["python", "-m", "commatrix"]
CMD ["--help"]
