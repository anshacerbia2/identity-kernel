# The kernel image: the pinned upstream Keycloak with this repository's login theme
# (TDD-identity-kernel-005 §Build Inputs). KEYCLOAK_IMAGE is the digest in image/keycloak.ref, passed by
# every build, so the image is the upstream bytes plus the theme and nothing else. No extension is
# packaged yet.
ARG KEYCLOAK_IMAGE
FROM ${KEYCLOAK_IMAGE}
COPY --chown=1000:0 themes/scnehaux /opt/keycloak/themes/scnehaux
