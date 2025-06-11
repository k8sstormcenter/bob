# syntax=docker/dockerfile:1.4

ARG GO_VERSION=1.24

# Build stage
FROM golang:${GO_VERSION}-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Set necessary Go build flags for static binary and reproducibility
ENV CGO_ENABLED=0
ENV GOOS=linux

RUN go build -trimpath -ldflags="-s -w" -o /out/bobctl ./main.go

# Final image
FROM cgr.dev/chainguard/go
COPY --from=builder /out/bobctl /bobctl

ENTRYPOINT ["/bobctl"]