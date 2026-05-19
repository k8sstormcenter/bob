# Multi-stage: stdlib-only build, distroless runtime. Backend is the
# vulnerable target — keep the image minimal so any extra binary that
# appears at runtime (redis-cli, curl, sh) is unambiguously attacker-
# introduced.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/chain-backend .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/chain-backend /chain-backend
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/chain-backend"]
