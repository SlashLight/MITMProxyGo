FROM golang:alpine AS build

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

# Install build dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o main ./cmd/main.go

FROM alpine:latest

WORKDIR /app

# Install required packages
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    sqlite \
    sqlite-dev

# Copy certificates
COPY ca.key ca.crt /app/
COPY ca.crt /usr/local/share/ca-certificates/mitm-ca.crt
RUN update-ca-certificates

# Copy built binary
COPY --from=build /app/main .

EXPOSE 8080

CMD ["./main"]