# Build stage
FROM rust:1.83-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /app
COPY . .

RUN cargo build --release --package whspr-server

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /app/target/release/whspr-server /app/whspr-server

EXPOSE 4433/udp

VOLUME ["/app/data"]

ENV WHSPR_DB_PATH=/app/data/whspr.db

CMD ["./whspr-server"]
