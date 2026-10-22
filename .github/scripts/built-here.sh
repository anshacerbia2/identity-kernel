#!/usr/bin/env bash
# Proves the running container of a compose service uses an image built from a given commit
# (TDD-identity-kernel-005 §Images the Stack Runs). Run in deploy/dev, with COMPOSE_FILE set to the
# file set the stack runs.
#
#   built-here.sh <service> <commit>
#
# The container's image is read by its ID, not by the tag, and must carry <commit> as its
# org.opencontainers.image.revision label, which compose sets from BUILD_REVISION at build time.
# The registry digests of the image prove nothing: with the containerd image store a local build
# is a manifest list too.
set -euo pipefail

service="${1:?service}"
want="${2:?commit}"

cid="$(docker compose ps -aq "$service")"
if [ "$(printf '%s\n' "$cid" | grep -c .)" != 1 ]; then
  echo "::error::expected one $service container, got: $cid"
  exit 1
fi
image_id="$(docker inspect -f '{{.Image}}' "$cid")"
got="$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image_id")"
echo "repo digests of $image_id: $(docker image inspect -f '{{.RepoDigests}}' "$image_id")"
if [ "$got" != "$want" ]; then
  echo "::error::the $service container runs image $image_id with revision '$got', want '$want': it was not built from this commit"
  exit 1
fi
echo "the $service container runs image $image_id, built from $got"
