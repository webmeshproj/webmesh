FROM ghcr.io/webmeshproj/alpine:3.18

ARG TARGETOS TARGETARCH PREFIX=node
ADD dist/${PREFIX}_${TARGETOS}_${TARGETARCH}*/webmesh-node /webmesh-node
ENTRYPOINT ["/webmesh-node"]
