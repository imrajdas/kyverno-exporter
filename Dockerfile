# BUILD STAGE
FROM golang:1.14 AS builder

ADD . /kv-exporter
WORKDIR /kv-exporter
RUN CGO_ENABLED=0 go build -o /output/kv-exporter -v


# DEPLOY STAGE
FROM alpine:3.12.0

COPY --from=builder /output/kv-exporter /

EXPOSE 8080

CMD ["./kv-exporter"]