FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src src
RUN cargo build --release --locked

FROM scratch
COPY --from=build /app/target/release/photo-mover /photo-mover
# Listed so container UIs show the settings with their defaults.
ENV INBOX=/inbox \
    LIBRARY=/library \
    INTERVAL=30 \
    IDLE_MINUTES=60 \
    OVERWRITE=skip \
    PORT=8768 \
    LOG_DIR=/data \
    LOG_DAYS=60 \
    GOOGLE_CLIENT_ID="" \
    GOOGLE_CLIENT_SECRET=""
EXPOSE 8768
ENTRYPOINT ["/photo-mover"]
