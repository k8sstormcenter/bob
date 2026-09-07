FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN go mod tidy && CGO_ENABLED=0 go build -o /opsboard .

FROM alpine:3.20
RUN apk add --no-cache bind-tools curl
COPY --from=build /opsboard /opsboard
ENTRYPOINT ["/opsboard"]
