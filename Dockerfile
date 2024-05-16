FROM rust:1.78-alpine as builder
RUN mkdir /build
RUN apk add --no-cache musl-dev python3 python3-dev openssl openssl-dev
ADD Cargo.toml /build/
WORKDIR /build
ENV RUSTFLAGS="-C target-feature=-crt-static"
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
COPY src /build/src
COPY manifests /build/manifests
RUN cargo build --release
RUN strip /build/target/release/bridgekeeper

FROM alpine:3.19.1
RUN apk add --no-cache python3 openssl libgcc py3-pip
RUN addgroup -g 1000 bridgekeeper && adduser -u 1000 -G bridgekeeper -D bridgekeeper
RUN pip install --break-system-packages kubernetes==29.0.0
COPY --from=builder --chown=1000:1000 /build/target/release/bridgekeeper /usr/local/bin/
USER 1000:1000
