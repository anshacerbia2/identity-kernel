# syntax=docker/dockerfile:1
#
# realm-apply as a one-shot container, so `docker compose up` brings the realm to the definition
# instead of leaving that to a remembered command. It needs git at run time: it reads the definition
# at the revision it last applied with `git show`, which is how it tells console drift from a
# changed definition. So the runtime image is git's, and the repository is mounted read-only.
#
# Bases pinned by digest, with the tag each was resolved from beside it.

# golang:1.26.9-alpine
FROM golang@sha256:cdfd4fe2da6b225d8b40c6b7a105736e548e83ff56d5d8f9394446eeb5eb84e0 AS build
WORKDIR /src
# The module has no dependencies, so there is nothing to download: no proxy is involved, and a
# network that intercepts one does not break this build.
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/realm-apply ./cmd/realm-apply && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/client-key ./cmd/client-key

# alpine/git:2.54.0, the rebuild of 2026-10-04, resolved 2026-10-07
FROM alpine/git@sha256:a4bb51f1a3553df194ce679fc1db721d8bfba2046fa1a88fe9d4ac551ffbce25
COPY --from=build /out/realm-apply /usr/local/bin/realm-apply
# client-key rides in the same image, so a server makes and installs client keys with the Docker
# it already has: no Go and no openssl on the host (new-client-key.sh, set-client-key.sh).
COPY --from=build /out/client-key /usr/local/bin/client-key
# The mounted checkout belongs to the host's user, and git refuses a repository owned by someone
# else. Trusting exactly that path, through the environment, writes no config file.
ENV GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/repo
USER 65534:65534
ENTRYPOINT ["realm-apply"]
