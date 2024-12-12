FROM docker.io/library/golang:1.23-bookworm AS build
WORKDIR /build
COPY . .
RUN go build -o kaleng cmd/kaleng/main.go

FROM docker.io/library/ubuntu:noble

RUN apt update && apt install -y neovim

WORKDIR /app
COPY --from=build /build/kaleng kaleng
COPY example.yaml example.yaml
COPY vendor/ vendor/
