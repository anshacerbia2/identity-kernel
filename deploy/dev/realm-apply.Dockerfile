# syntax=docker/dockerfile:1
#
# realm-apply as a one-shot container, so `docker compose up` brings the realm to the definition
# instead of leaving that to a remembered command. It needs git at run time: it reads the definition
# at the revision it last applied with `git show`, which is how it tells console drift from a
# changed definition. So the runtime image is git's, and the repository is mounted read-only.
#
# Bases pinned by digest, with the tag each was resolved from beside it.

# golang:1.26.8-alpine
FROM golang@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS build
WORKDIR /src
# The module has no dependencies, so there is nothing to download: no proxy is involved, and a
# network that intercepts one does not break this build.
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/realm-apply ./cmd/realm-apply

# alpine/git:2.54.0
FROM alpine/git@sha256:ae0f6f4bce38d2b8c40becc0d6241a08d9f57186ea03029de2189a2b5e722d94
COPY --from=build /out/realm-apply /usr/local/bin/realm-apply
# The mounted checkout belongs to the host's user, and git refuses a repository owned by someone
# else. Trusting exactly that path, through the environment, writes no config file.
ENV GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/repo
USER 65534:65534
ENTRYPOINT ["realm-apply"]
