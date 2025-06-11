# syntax=docker/dockerfile:1.4

ARG GO_VERSION=1.24

# Build stage
FROM golang:${GO_VERSION}-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY ./src ./src

# Set necessary Go build flags for static binary and reproducibility
ENV CGO_ENABLED=0
ENV GOOS=linux

RUN go build -trimpath -ldflags="-s -w" -o /out/bobctl ./src/main.go

# Final image
FROM cgr.dev/chainguard/go
COPY --from=builder /out/bobctl /bobctl

ENTRYPOINT ["/bobctl"]