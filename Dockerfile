# Build stage
FROM golang:alpine AS builder
WORKDIR /app
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN go build -o baffo ./cmd/baffo/main.go

# Run stage
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/baffo ./baffo
COPY --from=builder /app/README.md ./README.md
# Copy any other files needed at runtime here
ENTRYPOINT ["/app/baffo"]
