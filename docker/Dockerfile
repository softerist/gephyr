FROM rust:1.88-slim AS backend-builder
ARG USE_MIRROR=auto

RUN if [ "$USE_MIRROR" = "true" ] || ( [ "$USE_MIRROR" = "auto" ] && ! timeout 3 bash -c "</dev/tcp/www.google.com/80" 2>/dev/null ); then \
    echo "Using Aliyun mirror for APT..."; \
    sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources || \
    sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list; \
    else \
    echo "Using default APT sources..."; \
    fi

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

ENV CARGO_HTTP_MULTIPLEXING=false
RUN if [ "$USE_MIRROR" = "true" ] || ( [ "$USE_MIRROR" = "auto" ] && ! timeout 3 bash -c "</dev/tcp/www.google.com/80" 2>/dev/null ); then \
    echo "Using Aliyun mirror for Cargo..."; \
    mkdir -p /root/.cargo && \
    echo "[source.crates-io]\nreplace-with = 'aliyun'\n\n[source.aliyun]\nregistry = \"sparse+https://mirrors.aliyun.com/crates.io-index/\"" > /root/.cargo/config.toml; \
    else \
    echo "Using default Cargo registry..."; \
    fi

WORKDIR /app
COPY . .

WORKDIR /app/src
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/app/src/target \
    cargo build --release --bin gephyr && \
    cp target/release/gephyr /tmp/gephyr

FROM debian:bookworm-slim
ARG USE_MIRROR=auto
WORKDIR /app

RUN if [ "$USE_MIRROR" = "true" ] || ( [ "$USE_MIRROR" = "auto" ] && ! timeout 3 bash -c "</dev/tcp/www.google.com/80" 2>/dev/null ); then \
    echo "Using Aliyun mirror for APT..."; \
    sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources || \
    sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list; \
    else \
    echo "Using default APT sources..."; \
    fi

RUN apt-get update && apt-get install -y \
    libssl3 \
    libsqlite3-0 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=backend-builder /tmp/gephyr /app/gephyr

RUN useradd -m -u 10001 gephyr && \
    mkdir -p /home/gephyr/.gephyr && \
    chown -R gephyr:gephyr /home/gephyr /app

ENV RUST_LOG=info
ENV PORT=8045
ENV ABV_DATA_DIR=/home/gephyr/.gephyr

USER gephyr

EXPOSE 8045

ENTRYPOINT ["/app/gephyr", "--headless"]
