# The kernel image: the pinned upstream Keycloak with this repository's login theme, built optimized
# (TDD-identity-kernel-005 §Build Inputs, ADR-IAM-001 §5.8). KEYCLOAK_IMAGE is the digest in
# image/keycloak.ref, passed by every build.
#
# Keycloak's container guide: "For the best start up of your Keycloak container, build an image by
# running the `build` step during the container build." Health, metrics and the database vendor are
# build-time options, so they are decided here, once, for the image every environment runs, and the
# container starts with `start --optimized`. No extension is packaged yet.
ARG KEYCLOAK_IMAGE

FROM ${KEYCLOAK_IMAGE} AS upstream

FROM ${KEYCLOAK_IMAGE} AS builder
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true
ENV KC_DB=postgres
# The file vault, a build-time option: "For enabling the file-based vault you need to build Keycloak
# first using the following build option" (Keycloak, Using a vault). The realm signing keystore's
# passwords are ${vault.realm-signing-password}, read from $KC_VAULT_DIR (ADR-IAM-002 §5.3,
# TDD-identity-kernel-002 1.2.0 §Custody as Built).
ENV KC_VAULT=file
COPY --chown=1000:0 themes/scnehaux /opt/keycloak/themes/scnehaux
RUN /opt/keycloak/bin/kc.sh build

# pcre2 upgraded where the image is built (STD-GLB-009 1.8.0 §Container Images rule 10;
# TDD-identity-kernel-005 §Images the Stack Runs). Keycloak 26.7.5's ubi9-micro base carries pcre2 and
# pcre2-syntax 10.40-6.el9; RHEL 9 ships 10.40-7.el9_8, which fixes CVE-2026-103111, CVE-2026-86145
# and CVE-2026-89161 (High). Remove this stage and its COPY below when image/keycloak.ref moves to a
# Keycloak image that carries pcre2 10.40-7.el9_8 or later.
#
# The image has no package manager. Keycloak's container guide installs RPMs "following this
# two-stage pattern established by ubi-micro": dnf --installroot in a registry.access.redhat.com/ubi9
# stage, then a COPY into the Keycloak stage. Here the root is the pinned Keycloak image itself, so
# dnf upgrades the two packages in the image's own rpm database, and only their files and that
# database are copied: a root holding only the new packages would replace the database and hide every
# other package from the scan. The build fails if no repository offers the constraint, or if anything
# but pcre2 and pcre2-syntax changes; the signing key dnf imports to check them is removed again.
# SOURCE_DATE_EPOCH, which scripts/image-build-check.sh passes, sets rpm's install time, so two builds
# of one commit write the same database.
#
# registry.access.redhat.com/ubi9:9.8-1791888712, resolved 2026-10-18 (the manifest list digest).
FROM registry.access.redhat.com/ubi9@sha256:16e9e43d99e181463513cc84a514859b1abb9460f1c4d9e208da4b4e51cd5cc3 AS ubi-micro-build
ARG SOURCE_DATE_EPOCH
COPY --from=upstream / /mnt/rootfs
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN set -eu; \
    rpm --root /mnt/rootfs -qa --qf '%{NAME} %{EVR}\n' | sort >/tmp/rpm-before; \
    dnf install --installroot /mnt/rootfs --releasever 9 --setopt install_weak_deps=false --nodocs -y \
      'pcre2 >= 10.40-7.el9_8' 'pcre2-syntax >= 10.40-7.el9_8'; \
    dnf --installroot /mnt/rootfs clean all; \
    comm -13 /tmp/rpm-before <(rpm --root /mnt/rootfs -qa --qf '%{NAME} %{EVR}\n' | sort) | \
      awk '$1 == "gpg-pubkey" {print "gpg-pubkey-" $2}' | xargs -r rpm --root /mnt/rootfs -e; \
    rpm --root /mnt/rootfs -qa --qf '%{NAME} %{EVR}\n' | sort >/tmp/rpm-after; \
    changed="$(comm -3 /tmp/rpm-before /tmp/rpm-after | awk '{print $1}' | sort -u | grep -Ev '^(pcre2|pcre2-syntax)$' || true)"; \
    if [ -n "$changed" ]; then echo "the pcre2 upgrade changed other packages: $changed" >&2; exit 1; fi; \
    rpm --root /mnt/rootfs -q pcre2 pcre2-syntax; \
    mkdir -p /mnt/patch; \
    cd /mnt/rootfs; \
    { rpm --root /mnt/rootfs -ql pcre2 pcre2-syntax | sed 's|^/||' | while read -r f; do \
        if [ -L "$f" ] || [ -f "$f" ]; then echo "$f"; fi; done; \
      ls var/lib/rpm/rpmdb.sqlite*; } | tar -cf - --no-recursion -T - | tar -xf - -C /mnt/patch

FROM ${KEYCLOAK_IMAGE}
COPY --from=builder /opt/keycloak/ /opt/keycloak/
COPY --from=ubi-micro-build /mnt/patch/ /
# Sessions are read from the database, never from a cache in front of it (TDD-identity-kernel-005
# §Session Store). With the cache on, a request that reads a session while it is being deleted puts it
# back into the cache after the database lost it, and the removed session keeps refreshing
# (keycloak#51127). A runtime option, set here so every environment that runs the image has it.
ENV KC_SPI_USER_SESSIONS__INFINISPAN__USE_CACHES=false
# Where the file vault reads the realm's secrets, a runtime option. Every environment mounts the vault
# here read-only: deploy/dev/compose.yaml from keys/vault, production through the AWS Secrets and
# Configuration Provider (docs/production/realm-signing-secret-provider-class.yaml).
ENV KC_VAULT_DIR=/opt/keycloak/vault
# The entrypoint refuses to start a server without the realm signing keystore and its password, then
# runs kc.sh with the same arguments (image/start.sh, TDD-identity-kernel-002 1.2.0 §Startup as Built).
COPY image/start.sh /opt/scnehaux/start.sh
ENTRYPOINT ["/opt/scnehaux/start.sh"]
