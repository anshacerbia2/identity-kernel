#!/usr/bin/env bash
# Builds the kernel image twice from nothing and compares the two, checks what the image holds, and
# writes its software bill of materials (TDD-identity-kernel-005 §Build Reproducibility). CI runs it on
# every change; it runs no service.
#
#   scripts/image-build-check.sh [output directory]
#
# BUILDER_1 and BUILDER_2 name the buildx builders for the two builds; CI gives each its own, so the
# second build shares no cache and no state with the first. Without them both use the current builder,
# with --no-cache. A builder must export OCI archives: the docker-container driver, or the docker driver
# with the containerd image store.
#
# Both builds take SOURCE_DATE_EPOCH from the commit and rewrite every timestamp they write to it
# (BuildKit's rewrite-timestamp), so the build date is not a difference. What is left is decided by
# scripts/image-build-compare.py: it fails on any difference outside Keycloak's own build output
# (lib/quarkus), and records the differences inside it.
set -euo pipefail

# anchore/syft:v1.54.1, resolved from Docker Hub on 2026-10-07. Pinned by digest, as the scanner is
# (STD-GLB-009 §Container Images rule 6).
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft@sha256:3eb5379ba7b409c3f4069b686110527af0c47df993fa5c10d13e7cf34f49b1aa}"

OUT="${1:-${RUNNER_TEMP:-$(mktemp -d)}/image-build}"
mkdir -p "$OUT/tmp"

image="$(grep -v '^[[:space:]]*#' image/keycloak.ref | grep -v '^[[:space:]]*$' | head -n 1 | tr -d '[:space:]')"
if ! printf '%s' "$image" | grep -Eq '@sha256:[0-9a-f]{64}$'; then
  echo "::error::image/keycloak.ref must pin the image by sha256 digest, found '$image'"
  exit 1
fi

SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
export SOURCE_DATE_EPOCH

for i in 1 2; do
  builder_var="BUILDER_$i"
  builder=()
  if [ -n "${!builder_var:-}" ]; then builder=(--builder "${!builder_var}"); fi
  echo "== build $i of 2 ${builder[*]}"
  docker buildx build "${builder[@]}" --no-cache --progress plain \
    -f image/Dockerfile \
    --build-arg KEYCLOAK_IMAGE="$image" \
    --build-arg SOURCE_DATE_EPOCH \
    --output "type=oci,dest=$OUT/build-$i.tar,rewrite-timestamp=true" \
    . >"$OUT/build-$i.log" 2>&1 || { tail -n 40 "$OUT/build-$i.log"; exit 1; }
done

# The pinned upstream image's own manifest for this platform: its layers must be the first layers of
# the kernel image, unchanged.
docker buildx imagetools inspect --raw "$image" >"$OUT/upstream-index.json"
upstream_manifest="$(python3 -c '
import json, sys
index = json.load(open(sys.argv[1]))
print(next(m["digest"] for m in index["manifests"]
           if m.get("platform", {}).get("os") == "linux" and m["platform"].get("architecture") == "amd64"))
' "$OUT/upstream-index.json")"
docker buildx imagetools inspect --raw "${image%@*}@$upstream_manifest" >"$OUT/upstream-manifest.json"

# The theme's version is its git tree id: it names exactly the files the image copies.
theme_tree="$(git rev-parse HEAD:themes/scnehaux)"
git ls-files -z themes/scnehaux >"$OUT/theme-files"

python3 scripts/image-build-compare.py compare "$OUT" "$theme_tree"

# The bill of materials of the first build, in CycloneDX JSON. The comparison above found the second
# build's packages to be the same.
digest="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["manifests"][0]["digest"])' "$OUT/index-1.json")"
docker run --rm --user "$(id -u):$(id -g)" \
  -e SYFT_CHECK_FOR_APP_UPDATE=false -e HOME=/tmp -e TMPDIR=/tmp \
  -v "$OUT:/work" -v "$OUT/tmp:/tmp" \
  "$SYFT_IMAGE" oci-archive:/work/build-1.tar \
  --source-name identity-kernel --source-version "$digest" \
  -o cyclonedx-json=/work/sbom.raw.cdx.json -q
python3 scripts/image-build-compare.py sbom "$OUT" "$theme_tree" "$(git rev-parse HEAD)"
