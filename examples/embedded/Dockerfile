FROM golang:1.21-alpine

COPY mesh-chat/ /mesh-chat/
RUN cd /mesh-chat && go build -o /chat

ENTRYPOINT ["/chat"]
