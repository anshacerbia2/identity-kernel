# syntax=docker/dockerfile:1
#
# The reverse proxy: Caddy 2.11.7 rebuilt from source with golang.org/x/net v0.60.0, until a Caddy
# release carries the fix (TDD-identity-kernel-005 §Images the Stack Runs, STD-GLB-009 1.8.0
# §Container Images rules 9 and 10). The official caddy:2.11.7-alpine binary is built with go1.26.8 and
# x/net v0.59.0, and is reachable from the public network on 80 and 443: GO-2026-6612 (automatable,
# total technical impact) is to be fixed within 3 days of 2026-10-10. GO-2026-6608 and GO-2026-6613 are
# in the HTTP/1 path, so turning HTTP/2 off would not close them.
#
# The build is the one Caddy documents: the :builder image runs xcaddy, and the second FROM overlays the
# new binary on the regular caddy image. `--replace` writes only a replace directive to go.mod, so the
# module graph is Caddy's own with x/net moved. The builder's Go (1.27.2) carries the standard library
# fixes. When a Caddy release ships x/net >= v0.60.0 and Go >= 1.26.9, this file goes and compose pulls
# that release by digest again.
#
# Bases pinned by digest, with the tag each was resolved from beside it.

# caddy:2.11.7-builder-alpine, resolved 2026-10-10 (go1.27.2, xcaddy v0.4.7)
FROM caddy@sha256:aa705b1e8e4bce41a7a30de934c1e00f6821667c1d1206424465065c92cb7674 AS build
# Modules come through GOPROXY, set in .env (STD-GLB-009 §Development Server Deployment, rule 7). go.sum
# and the checksum database verify each one whichever way it arrives.
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}
RUN xcaddy build v2.11.7 --replace golang.org/x/net=golang.org/x/net@v0.60.0 --output /usr/bin/caddy
# The build fails unless the binary carries what it is built for: x/net v0.60.0 as the module compiled
# in (the replace line, `=>`, when there is one), and a standard library no older than go1.26.9.
RUN go version -m /usr/bin/caddy | awk ' \
      NR == 1 { go = $2 } \
      $1 == "dep" { x = ($2 == "golang.org/x/net"); if (x) v = $3 } \
      $1 == "=>" && x { v = $3 } \
      END { print go, "golang.org/x/net", v; exit (v != "v0.60.0") }' && \
    [ "$(printf 'go1.26.9\n%s\n' "$(go version -m /usr/bin/caddy | head -n 1 | awk '{print $2}')" | sort -V | head -n 1)" = go1.26.9 ]

# caddy:2.11.7-alpine, resolved 2026-10-07
FROM caddy@sha256:d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f
# CVE-2026-85091: the pinned image carries zlib 1.3.2-r0, and Alpine ships the fix as 1.3.2-r1. The
# constraint fails the build when no repository has it. The line goes when the pin moves to an image
# that carries the fix.
RUN apk add --no-cache 'zlib>=1.3.2-r1'
COPY --from=build /usr/bin/caddy /usr/bin/caddy
