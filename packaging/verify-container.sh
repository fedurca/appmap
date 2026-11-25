#!/usr/bin/env bash
# Verify the container behaviour this branch changed. Needs a working Docker
# with registry access (this repository's CI sandbox has neither, which is why
# these are the last items left).
#
#   bash packaging/verify-container.sh
#
# Covers:
#   SEC-044  the digest-pinned base image resolves and the image builds
#   SEC-042  the build carries SLSA provenance and an SBOM
#   UID      image runs as root
set -uo pipefail

IMAGE="${IMAGE:-commatrix:verify}"
WORK="$(mktemp -d)"
FAILS=0

pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n    %s\n' "$1" "${2:-}"; FAILS=$((FAILS + 1)); }
check() { if eval "$2" >/dev/null 2>&1; then pass "$1"; else fail "$1" "${3:-command failed: $2}"; fi; }

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

echo "== 0. prerequisites =="
check "docker daemon reachable" "docker info"
[ "$FAILS" -gt 0 ] && { echo "cannot continue without a daemon"; exit 2; }

echo
echo "== 1. SEC-044: the pinned digest resolves and the image builds =="
# Plain build for the functional checks. Attestations are deliberately NOT
# requested here: the default "docker" driver rejects them outright
# ("Attestation is not supported for the docker driver"), so asking for them
# in the same build makes the functional tests unrunnable on a stock install.
if docker buildx build -t "$IMAGE" --load . > "$WORK/build.log" 2>&1; then
    pass "image builds from the digest-pinned base"
else
    fail "image build" "$(tail -5 "$WORK/build.log")"
fi

echo
echo "== 2. SEC-042: provenance and SBOM are attached =="
# Attestations need the docker-container driver (or the containerd image
# store). Build to an OCI layout so this works without a registry: the
# attestation manifests then show up in the layout's index.json.
BUILDER="commatrix-verify"
if docker buildx inspect "$BUILDER" >/dev/null 2>&1    || docker buildx create --name "$BUILDER" --driver docker-container >/dev/null 2>&1; then
    if docker buildx --builder "$BUILDER" build \
            --provenance=mode=max --sbom=true \
            --output "type=oci,dest=$WORK/image.tar" . > "$WORK/attest.log" 2>&1; then
        pass "attested build succeeds"
        mkdir -p "$WORK/oci" && tar xf "$WORK/image.tar" -C "$WORK/oci" 2>/dev/null
        check "provenance attestation in the OCI index" \
              "grep -q 'in-toto' '$WORK/oci/index.json' 2>/dev/null || grep -rq 'in-toto' '$WORK/oci/blobs' 2>/dev/null" \
              "no in-toto attestation found in the built image"
        check "SBOM attestation in the OCI index" \
              "grep -rq 'spdx' '$WORK/oci/blobs' 2>/dev/null" \
              "no SPDX SBOM found in the built image"
    else
        fail "attested build" "$(tail -8 "$WORK/attest.log")"
    fi
    docker buildx rm "$BUILDER" >/dev/null 2>&1 || true
else
    echo "  SKIP  could not create a docker-container builder; verify the"
    echo "        published image instead:"
    echo "          docker buildx imagetools inspect ghcr.io/fedurca/commatrix:<version>"
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo
    echo "The image was not built, so the runtime checks below cannot run."
    echo "$FAILS check(s) FAILED."
    exit 1
fi

echo "== 3. the image runs as root =="
UID_OUT="$(docker run --rm --entrypoint sh "$IMAGE" -c 'id -u' 2>/dev/null || true)"
if [ "$UID_OUT" = "0" ]; then pass "default UID is 0"; else fail "default UID" "got '$UID_OUT'"; fi

echo
if [ "$FAILS" -eq 0 ]; then
    echo "All container checks passed."
else
    echo "$FAILS check(s) FAILED."
fi
exit $(( FAILS > 0 ? 1 : 0 ))
