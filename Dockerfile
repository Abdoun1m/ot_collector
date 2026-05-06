FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git ca-certificates
ARG REPO_URL=https://github.com/Abdoun1m/ot_collector
ARG REPO_BRANCH=main
RUN git clone --branch ${REPO_BRANCH} ${REPO_URL} /src
WORKDIR /src
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/ot-collector ./cmd/ot-collector

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
RUN adduser -D -H otcollector
RUN mkdir -p /data && chown -R otcollector:otcollector /data
COPY --from=builder /out/ot-collector /usr/local/bin/ot-collector
USER otcollector
EXPOSE 514/udp 1514/tcp 8088/tcp
ENTRYPOINT ["/usr/local/bin/ot-collector"]

