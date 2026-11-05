# syntax=docker/dockerfile:1
# A fully static eventchain-verify for Linux: musl, with libcrypto, gmp and
# libffi linked in, so the binary runs on any Linux of its architecture with
# nothing installed. Alpine is the base because its packages ship the static
# archives. The build machine's architecture is the binary's: build natively,
# or pass --platform.
#
#   docker buildx build -f release/linux.Dockerfile --output type=local,dest=out .
#
# The binary is checked before it is exported: it must be static, and it must
# verify the lifecycle vector. Beside it, openssl-version names the libcrypto
# linked in, for the release notes.
FROM alpine:3.22 AS build
RUN apk add --no-cache bash binutils-gold curl file g++ gcc git gmp-dev gmp-static libffi-dev make \
        ncurses-dev openssl-dev openssl-libs-static perl pkgconf tar xz zlib-static
ENV GHCUP_INSTALL_BASE_PREFIX=/opt/ghcup
ENV PATH=/opt/ghcup/.ghcup/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://get-ghcup.haskell.org -o /tmp/ghcup-install.sh \
    && BOOTSTRAP_HASKELL_NONINTERACTIVE=1 BOOTSTRAP_HASKELL_MINIMAL=1 sh /tmp/ghcup-install.sh \
    && ghcup install ghc 9.12.4 --set && ghcup install cabal 3.16.1.0 --set \
    && rm -rf /opt/ghcup/.ghcup/cache /opt/ghcup/.ghcup/tmp
RUN cabal update
WORKDIR /src
COPY . .
RUN cabal build --disable-tests --disable-benchmarks --enable-executable-static exe:eventchain-verify \
    && mkdir /out && cp "$(cabal list-bin --disable-tests --disable-benchmarks exe:eventchain-verify)" /out/ \
    && strip /out/eventchain-verify \
    && pkg-config --modversion libcrypto > /out/openssl-version
RUN file /out/eventchain-verify | tee /dev/stderr | grep -q 'statically linked' \
    && /out/eventchain-verify aof conformance/vectors/v0-lifecycle.jsonl

FROM scratch
COPY --from=build /out/eventchain-verify /out/openssl-version /
