FROM --platform=$BUILDPLATFORM debian:bookworm AS base

ENV PATH="${PATH}:/bitcoin-25.0/bin"

RUN apt update && apt install -y wget

FROM base AS arm64-build
RUN wget https://bitcoin.org/bin/bitcoin-core-25.0/bitcoin-25.0-aarch64-linux-gnu.tar.gz
RUN tar xzf bitcoin-25.0-aarch64-linux-gnu.tar.gz

FROM base AS amd64-build
RUN wget https://bitcoin.org/bin/bitcoin-core-25.0/bitcoin-25.0-x86_64-linux-gnu.tar.gz
RUN tar xzf bitcoin-25.0-x86_64-linux-gnu.tar.gz

FROM $TARGETARCH-build AS final
RUN mkdir bitcoin-25.0/data
RUN mkdir /.bitcoin

ADD node/bitcoin.conf /.bitcoin/bitcoin.conf

EXPOSE 28332

CMD ["bitcoind", "-conf=/.bitcoin/bitcoin.conf"]
