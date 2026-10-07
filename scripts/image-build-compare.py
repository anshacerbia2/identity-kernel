#!/usr/bin/env python3
"""The checks behind scripts/image-build-check.sh (TDD-identity-kernel-005 §Build Reproducibility).

  image-build-compare.py compare <dir> <theme tree id>
  image-build-compare.py sbom <dir> <theme tree id> <commit>

compare reads the two OCI archives the builds wrote, build-1.tar and build-2.tar, and:

  1. requires the pinned upstream image's layers, unchanged, at the bottom of both;
  2. requires the layers above them, the ones this repository adds, to hold only Keycloak's build
     output (lib/quarkus) and this repository's theme, byte for byte as git holds it, and no file
     that could carry a key, a certificate, a realm export or an environment file;
  3. compares the two builds file by file. Equal digests pass at once. Otherwise every difference
     outside Keycloak's build output fails, and the differences inside it are recorded: Quarkus writes
     its augmented classes with random names, which this repository cannot change.

sbom completes the CycloneDX document syft wrote: the theme is added as a component, versioned by
its git tree id, and every jar in providers/ must be listed with a version.
"""

import gzip
import io
import json
import os
import sys
import tarfile
import zipfile

# What the kernel's own layers may hold. Parents of these directories may appear as entries too.
ALLOWED_PREFIXES = ("opt/keycloak/lib/quarkus/", "opt/keycloak/themes/scnehaux/")
THEME_PREFIX = "opt/keycloak/themes/scnehaux/"

# Files that would carry a key, a certificate, a realm export, or configuration with a credential.
FORBIDDEN_SUFFIXES = (
    ".jks", ".p12", ".pfx", ".keystore", ".truststore", ".bcfks", ".pem", ".key", ".crt", ".der",
    ".json", ".env", ".conf",
)

# Keycloak's `kc.sh build` output. Recorded, not failed, when it differs between builds: Hibernate's
# proxies take ByteBuddy's random accessor suffix, and Quarkus numbers its recorded proxies in the
# order its parallel build steps finish.
QUARKUS_JARS = (
    "opt/keycloak/lib/quarkus/generated-bytecode.jar",
    "opt/keycloak/lib/quarkus/transformed-bytecode.jar",
)
# Written by java.util.Properties.store, whose first comment line is the date it was written.
DATED_PROPERTIES = ("META-INF/keycloak-persisted.properties",)

SECRET_WORDS = ("PASSWORD", "SECRET", "TOKEN", "CREDENTIAL", "PRIVATE")


class Archive:
    """An OCI image archive, read without unpacking it to disk."""

    def __init__(self, path):
        self.tar = tarfile.open(path)
        self.index = json.loads(self.blob_bytes_at("index.json"))
        if len(self.index["manifests"]) != 1:
            raise SystemExit(f"{path}: expected one manifest, found {len(self.index['manifests'])}")
        self.digest = self.index["manifests"][0]["digest"]
        self.manifest = json.loads(self.blob(self.digest))
        self.config = json.loads(self.blob(self.manifest["config"]["digest"]))
        self.layers = [layer["digest"] for layer in self.manifest["layers"]]

    def blob_bytes_at(self, name):
        return self.tar.extractfile(name).read()

    def blob(self, digest):
        return self.blob_bytes_at("blobs/sha256/" + digest.split(":", 1)[1])

    def files(self, digest):
        """Each entry of a layer: its metadata, and the content of a regular file."""
        raw = self.blob(digest)
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        entries = {}
        with tarfile.open(fileobj=io.BytesIO(raw)) as layer:
            for member in layer.getmembers():
                content = layer.extractfile(member).read() if member.isfile() else None
                meta = (member.type, member.mode, member.uid, member.gid, member.mtime, member.linkname)
                name = member.name[2:] if member.name.startswith("./") else member.name
                entries[name.lstrip("/")] = (meta, content)
        return entries


def fail(errors, message):
    errors.append(message)
    print(f"::error::{message}")


def check_contents(errors, label, entries, theme_dir):
    theme_files = set()
    for name, (meta, content) in sorted(entries.items()):
        if os.path.basename(name).startswith(".wh."):
            fail(errors, f"{label}: the kernel's layers delete {name}; they may only add")
            continue
        if not name.startswith(ALLOWED_PREFIXES) and not any(p.startswith(name.rstrip("/") + "/") for p in ALLOWED_PREFIXES):
            fail(errors, f"{label}: {name} is outside Keycloak's build output and the theme")
            continue
        if name.lower().endswith(FORBIDDEN_SUFFIXES):
            fail(errors, f"{label}: {name} could carry a key, a realm export or a credential")
        if name.startswith(THEME_PREFIX) and content is not None:
            relative = "themes/scnehaux/" + name[len(THEME_PREFIX):]
            theme_files.add(relative)
            if relative not in theme_dir:
                fail(errors, f"{label}: {name} is not a file git tracks")
            elif theme_dir[relative] != content:
                fail(errors, f"{label}: {name} differs from {relative} in git")
    for missing in sorted(set(theme_dir) - theme_files):
        fail(errors, f"{label}: {missing} is tracked but not in the image")


def compare_jar(errors, name, first, second):
    """Returns (entries whose dates differ, class entries whose content differs)."""
    a = zipfile.ZipFile(io.BytesIO(first))
    b = zipfile.ZipFile(io.BytesIO(second))
    names_a = [i.filename for i in a.infolist()]
    names_b = [i.filename for i in b.infolist()]
    if names_a != names_b:
        fail(errors, f"{name}: the two builds hold different entries")
        return 0, []
    dated, classes = 0, []
    for info_a, info_b in zip(a.infolist(), b.infolist()):
        if info_a.date_time != info_b.date_time:
            dated += 1
        x, y = a.read(info_a), b.read(info_b)
        if x == y:
            continue
        entry = info_a.filename
        if entry.endswith(".class"):
            classes.append(entry)
        elif entry in DATED_PROPERTIES and undated(x) == undated(y):
            continue
        else:
            fail(errors, f"{name}: {entry} differs between the builds")
    return dated, classes


def undated(properties):
    return [line for line in properties.splitlines() if not line.startswith(b"#")]


def compare(out, theme_tree):
    errors = []
    one = Archive(os.path.join(out, "build-1.tar"))
    two = Archive(os.path.join(out, "build-2.tar"))
    with open(os.path.join(out, "index-1.json"), "w") as f:
        json.dump(one.index, f)

    upstream = [layer["digest"] for layer in json.load(open(os.path.join(out, "upstream-manifest.json")))["layers"]]
    for label, archive in (("build 1", one), ("build 2", two)):
        if archive.layers[: len(upstream)] != upstream:
            fail(errors, f"{label}: the bottom layers are not the pinned upstream image's")
        env = archive.config.get("config", {}).get("Env", [])
        for variable in env:
            if any(word in variable.split("=", 1)[0].upper() for word in SECRET_WORDS):
                fail(errors, f"{label}: the image sets {variable.split('=', 1)[0]}")
    ours_one, ours_two = one.layers[len(upstream):], two.layers[len(upstream):]
    if len(ours_one) != len(ours_two):
        fail(errors, "the two builds add a different number of layers")

    theme_dir = {}
    with open(os.path.join(out, "theme-files"), "rb") as f:
        for path in filter(None, f.read().decode().split("\0")):
            with open(path, "rb") as content:
                theme_dir[path] = content.read()

    providers, version = [], None
    for layer in one.layers[:len(upstream)]:
        for name, (_, content) in one.files(layer).items():
            if name == "opt/keycloak/version.txt":
                # "Keycloak - Version 26.7.5"
                version = content.decode().split()[-1]
    recorded = []
    for index, (digest_one, digest_two) in enumerate(zip(ours_one, ours_two)):
        entries_one, entries_two = one.files(digest_one), two.files(digest_two)
        check_contents(errors, f"build 1, layer {len(upstream) + index + 1}", entries_one, theme_dir)
        check_contents(errors, f"build 2, layer {len(upstream) + index + 1}", entries_two, theme_dir)
        providers += [n for n, (_, c) in entries_one.items() if n.startswith("opt/keycloak/providers/") and c is not None]
        if digest_one == digest_two:
            continue
        for name in sorted(set(entries_one) | set(entries_two)):
            if name not in entries_one or name not in entries_two:
                fail(errors, f"{name} is in one build only")
                continue
            (meta_one, content_one), (meta_two, content_two) = entries_one[name], entries_two[name]
            if meta_one != meta_two:
                fail(errors, f"{name}: mode, owner, time or link differ between the builds")
            if content_one == content_two:
                continue
            if name in QUARKUS_JARS:
                dated, classes = compare_jar(errors, name, content_one, content_two)
                recorded.append((name, dated, classes))
            else:
                fail(errors, f"{name} differs between the builds")

    for archive in (one, two):
        config = dict(archive.config)
        config.pop("rootfs", None)
        archive.normalized_config = config
    if one.normalized_config != two.normalized_config:
        fail(errors, "the two image configurations differ beyond their layers")

    with open(os.path.join(out, "providers.json"), "w") as f:
        json.dump(sorted(providers), f)
    with open(os.path.join(out, "keycloak-version"), "w") as f:
        f.write(version or "")

    lines = [
        "## Kernel image build",
        "",
        f"- Build 1: `{one.digest}`",
        f"- Build 2: `{two.digest}`",
        f"- Theme: `themes/scnehaux` at tree `{theme_tree}`; Keycloak `{version}`",
    ]
    if one.digest == two.digest:
        lines.append("- **Reproducible:** the two builds have the same digest.")
    else:
        lines.append("- **Not the same digest.** Every layer and every file is the same except Keycloak's build "
                     "output, recorded below (TDD-identity-kernel-005 §Build Reproducibility):")
        for name, dated, classes in recorded:
            lines.append(f"  - `{name}`: {len(classes)} classes differ, {dated} entries carry a different date")
            for entry in classes[:5]:
                lines.append(f"    - `{entry}`")
    lines.append("- **Failed:** " + "; ".join(errors) if errors else "- Contents: upstream layers unchanged; "
                 "the kernel's layers hold only Keycloak's build output and the theme as git holds it.")
    summary("\n".join(lines))
    return 1 if errors else 0


def sbom(out, theme_tree, commit):
    errors = []
    document = json.load(open(os.path.join(out, "sbom.raw.cdx.json")))
    if document.get("bomFormat") != "CycloneDX":
        fail(errors, "syft did not write a CycloneDX document")
    components = document.setdefault("components", [])

    # The theme is files, not a package, so no scanner finds it. CycloneDX 1.7 recommends "library"
    # for a component that is not a framework: "If not, or is unknown, then specifying library is
    # recommended."
    components.append({
        "bom-ref": "scnehaux-login-theme",
        "type": "library",
        "group": "scnehaux",
        "name": "scnehaux-login-theme",
        "version": theme_tree,
        "description": "The hosted login theme, copied into /opt/keycloak/themes/scnehaux (TDD-identity-kernel-004)",
        "properties": [
            {"name": "scnehaux:version-kind", "value": "git tree id of themes/scnehaux"},
            {"name": "scnehaux:git-commit", "value": commit},
        ],
    })
    document.setdefault("metadata", {}).setdefault("properties", []).append(
        {"name": "scnehaux:git-commit", "value": commit})

    def located(component, path):
        return any(p.get("name", "").startswith("syft:location:") and p.get("name", "").endswith(":path")
                   and p.get("value") == path for p in component.get("properties", []))

    # Every extension, with its version (TDD-identity-kernel-005 §Build Reproducibility).
    providers = json.load(open(os.path.join(out, "providers.json")))
    for provider in providers:
        path = "/" + provider
        if not any(located(c, path) and c.get("version") for c in components):
            fail(errors, f"the bill of materials does not list {path} with a version")

    version = open(os.path.join(out, "keycloak-version")).read().strip()
    if not any(c.get("purl", "").startswith("pkg:maven/org.keycloak/keycloak-quarkus-server@" + version)
               for c in components if version):
        fail(errors, f"the bill of materials does not list Keycloak {version or '(no version.txt)'}")

    with open(os.path.join(out, "sbom.cdx.json"), "w") as f:
        json.dump(document, f, indent=2)
    packages = sum(1 for c in components if c.get("type") != "file")
    summary("\n".join([
        "",
        f"- Bill of materials: CycloneDX {document.get('specVersion')}, {packages} components besides files; "
        f"{len(providers)} extensions in `providers/`; the theme at `{theme_tree}`.",
    ] + ([f"- **Failed:** {'; '.join(errors)}"] if errors else [])))
    return 1 if errors else 0


def summary(text):
    print(text)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a") as f:
            f.write(text + "\n")


if __name__ == "__main__":
    command, *arguments = sys.argv[1:]
    sys.exit({"compare": compare, "sbom": sbom}[command](*arguments))
