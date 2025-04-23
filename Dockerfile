FROM golang:alpine AS build

WORKDIR /app
COPY . .
RUN go mod download

RUN go build cmd/main.go

FROM alpine:latest

WORKDIR /app
COPY --from=build /app/main .
COPY ca.key ca.crt /app/

COPY ca.crt /usr/local/share/ca-certificates/mitm-ca.crt

RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    sqlite \
    sqlite-dev
RUN update-ca-certificates

EXPOSE 8080

CMD ["./main"]