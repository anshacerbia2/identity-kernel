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
# Sessions are read from the database, never from a cache in front of it (TDD-identity-kernel-005
# §Session Store). With the cache on, a request that reads a session while it is being deleted puts it
# back into the cache after the database lost it, and the removed session keeps refreshing
# (keycloak#51127). A runtime option, set here so every environment that runs the image has it.
ENV KC_SPI_USER_SESSIONS__INFINISPAN__USE_CACHES=false
