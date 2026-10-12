#!/usr/bin/env python3
"""No image this stack names without a digest is pulled from a registry (STD-GLB-009 1.8.0
§Container Images rule 11, TDD-identity-kernel-005 §Images the Stack Runs).

    python3 .github/scripts/pull-policy.py <compose config JSON>...

Each argument is `docker compose ... config --format json` for one file set. Compose pulls a service's
image name before building it unless pull_policy says otherwise, and an image published under that name
would run instead. So every image name without a digest must be `pull_policy: build` where the service
builds it, and `never` where it does not. Exits 1 on any other.
"""
import json
import sys


def main(paths):
    bad = []
    for path in paths:
        services = json.load(open(path, encoding="utf-8"))["services"]
        for name, service in sorted(services.items()):
            image = service.get("image")
            if not image or "@sha256:" in image:
                continue
            want = "build" if "build" in service else "never"
            have = service.get("pull_policy")
            if have != want:
                bad.append(f"{path}: {name}: {image} has pull_policy {have!r}, want {want!r}")
            else:
                print(f"{path}: {name}: {image}, pull_policy {want}")
    for message in bad:
        print(f"::error::{message}")
    return 1 if bad else 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1:]))
