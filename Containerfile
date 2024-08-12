FROM docker.io/library/golang:1.22.6-bookworm AS build
WORKDIR /build
COPY . .
RUN go build -o kaleng cmd/kaleng/main.go

FROM docker.io/library/ubuntu:noble

WORKDIR /app
COPY --from=build /build/kaleng kaleng
COPY ubuntu/ ubuntu/
COPY example.json example.json
COPY vendor/ vendor/
COPY run.sh run.sh
