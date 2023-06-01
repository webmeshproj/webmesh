FROM alpine:3.17 AS tayga-builder

RUN apk add --update --no-cache \
    build-base curl iptables-dev libnl3-dev

WORKDIR /tayga
RUN curl -JLO http://www.litech.org/tayga/tayga-0.9.2.tar.bz2 \
    && tar -xjf tayga-0.9.2.tar.bz2 \
    && cd tayga-0.9.2 \
    && ./configure \
    && make \
    && make install


FROM alpine:3.17

# Not all utilities are needed, but are helpful for debugging and testing
RUN apk add --update --no-cache \
    sqlite wireguard-tools iperf3 nftables libnl3 iproute2

COPY --from=tayga-builder /usr/local/sbin/tayga /usr/local/sbin/tayga

WORKDIR /

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ADD dist/node_${TARGETOS}_${TARGETARCH} /node

ENTRYPOINT ["/node"]
