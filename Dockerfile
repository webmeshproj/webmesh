FROM alpine:3.18

RUN apk add --update --no-cache wireguard-tools net-tools nftables iproute2

ARG TARGETOS TARGETARCH PREFIX=node
ADD dist/${PREFIX}_${TARGETOS}_${TARGETARCH}*/webmesh-node /webmesh-node
ENTRYPOINT ["/webmesh-node"]
