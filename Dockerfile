FROM alpine:3.17

RUN apk add --update --no-cache \
    sqlite wireguard-tools nftables iproute2

WORKDIR /

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ADD dist/node_${TARGETOS}_${TARGETARCH} /node

ENTRYPOINT ["/node"]
