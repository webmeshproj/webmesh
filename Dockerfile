FROM alpine:3.17

RUN apk add --update --no-cache wireguard-tools nftables iproute2

ARG TARGETOS TARGETARCH PREFIX=node
ADD dist/${PREFIX}_${TARGETOS}_${TARGETARCH}*/webmesh-node /webmesh-node
ENTRYPOINT ["/webmesh-node"]
