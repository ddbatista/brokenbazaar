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

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/api /app/api
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/api"]
