# The kernel image: the pinned upstream Keycloak with this repository's login theme, built optimized
# (TDD-identity-kernel-005 §Build Inputs, ADR-IAM-001 §5.8). KEYCLOAK_IMAGE is the digest in
# image/keycloak.ref, passed by every build.
#
# Keycloak's container guide: "For the best start up of your Keycloak container, build an image by
# running the `build` step during the container build." Health, metrics and the database vendor are
# build-time options, so they are decided here, once, for the image every environment runs, and the
# container starts with `start --optimized`. No extension is packaged yet.
ARG KEYCLOAK_IMAGE

FROM ${KEYCLOAK_IMAGE} AS builder
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true
ENV KC_DB=postgres
COPY --chown=1000:0 themes/scnehaux /opt/keycloak/themes/scnehaux
RUN /opt/keycloak/bin/kc.sh build

FROM ${KEYCLOAK_IMAGE}
COPY --from=builder /opt/keycloak/ /opt/keycloak/
