FROM alpine:3.17

RUN apk add --update --no-cache wireguard-tools nftables iproute2

WORKDIR /

ARG TARGETOS TARGETARCH
ADD dist/node_${TARGETOS}_${TARGETARCH} /node

ENTRYPOINT ["/node"]
