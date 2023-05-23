# Build Jool userspace utilities and copy them into a minimal alpine image
# This is in place of implementing the jool userspace utilities in Go
FROM alpine:3.17 AS jool-builder

RUN apk add --update --no-cache \
    build-base curl \
    argp-standalone iptables-dev libnl3-dev

WORKDIR /jool

ARG JOOL_VERSION=4.2.0-rc2
ENV JOOL_VERSION=${JOOL_VERSION}
RUN curl -JLO \
    https://github.com/NICMx/Jool/releases/download/v${JOOL_VERSION}/jool-$(echo ${JOOL_VERSION} | tr '-' '.').tar.gz \
    && tar -xzf jool-$(echo ${JOOL_VERSION} | tr '-' '.').tar.gz \
    && cd jool-$(echo ${JOOL_VERSION} | tr '-' '~') \
    && ./configure --prefix=/usr --disable-shared \
    && make \
    && mkdir out \
    && make install DESTDIR=$(pwd)/out \
    && cp -r out/usr /jool-usr

FROM alpine:3.17

# Not all utilities are needed, but are helpful for debugging and testing
# The nftables and nl libraries are needed for jool
RUN apk add --update --no-cache \
    sqlite wireguard-tools iperf3 nftables libnl3 iproute2

COPY --from=jool-builder /jool-usr/bin/jool /usr/bin/jool
COPY --from=jool-builder /jool-usr/bin/jool_mapt /usr/bin/jool_mapt
COPY --from=jool-builder /jool-usr/bin/jool_siit /usr/bin/jool_siit
COPY --from=jool-builder /jool-usr/lib/xtables /usr/lib/xtables

WORKDIR /

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ADD dist/node_${TARGETOS}_${TARGETARCH} /node

ENTRYPOINT ["/node"]
