# commatrix container image (standard-library only; no pip install needed).
#
# The collector needs host visibility to be useful, so run it with:
#   docker run --rm --network host --pid host \
#     --cap-add NET_ADMIN --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH \
#     -v /var/lib/commatrix:/var/lib/commatrix \
#     ghcr.io/fedurca/commatrix:latest collect --allow-manual --database /var/lib/commatrix/commatrix.db
# (or simply --privileged). For report/aggregate only, no extra privileges are needed.
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

ENTRYPOINT ["python", "-m", "commatrix"]
CMD ["--help"]
