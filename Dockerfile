# Build stage
FROM golang:1.26.0-alpine3.23 AS builder
WORKDIR /app
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o baffo ./cmd/baffo/main.go

# Run stage
FROM scratch
WORKDIR /app
COPY --from=builder --chown=1000:1000 /app/baffo ./baffo
COPY --from=builder --chown=1000:1000 /app/README.md ./README.md

USER 1000:1000
# Copy any other files needed at runtime here
ENTRYPOINT ["/app/baffo"]
