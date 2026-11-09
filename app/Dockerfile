# syntax=docker/dockerfile:1
# Tracks the go directive in go.mod, which pgx/v5 v5.11.0 ratcheted to 1.25.0.
# A lower base image would silently auto-download a toolchain instead of failing.
FROM golang:1.25-alpine AS build
WORKDIR /src
# go.sum must be copied with go.mod: it carries the module hashes verified
# against sum.golang.org. Without it in the build context the image resolves
# dependencies with nothing to check them against.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/api ./api

# --- agent (M2, T6 D2) -------------------------------------------------------
# One binary per image, selected by build arg -- T3 D4's build-tag split
# plumbed through to the artifact. AGENT_TAGS defaults to EMPTY, i.e. the
# HARDENED binary: a forgotten arg builds the safe one, and the binary's
# own startup check (agent.CheckBuildMatchesEnv) refuses if it disagrees
# with $HARDENED. Building both binaries into one image and choosing at
# runtime was rejected: the hardened image would then carry NaiveExecutor
# on disk, weakening D5 from "no tool code in the artifact" to "no tool
# code in the process".
#
# These stages sit BEFORE the api stage on purpose: the last stage is the
# default target, so `docker build` with no --target still builds the api.
FROM build AS agent-build
ARG AGENT_TAGS=
RUN case "$AGENT_TAGS" in \
      ""|vulnerable) ;; \
      *) echo "AGENT_TAGS must be empty (hardened) or 'vulnerable', got '$AGENT_TAGS'" >&2; exit 1 ;; \
    esac \
 && CGO_ENABLED=0 go build -trimpath -tags "$AGENT_TAGS" -o /out/agent ./cmd/agent

FROM gcr.io/distroless/static-debian12:nonroot AS agent
COPY --from=agent-build /out/agent /app/agent
USER nonroot:nonroot
ENTRYPOINT ["/app/agent"]

# --- api (default target) ----------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS api
COPY --from=build /out/api /app/api
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/api"]
