# Stdlib-only build, distroless runtime. Frontend is the entrypoint —
# minimal image so any extra binary at runtime is unambiguously attacker-
# introduced (mirrors chain-backend's posture).
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/chain-frontend .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/chain-frontend /chain-frontend
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/chain-frontend"]
