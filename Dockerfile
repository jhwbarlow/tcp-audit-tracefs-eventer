FROM golang:1.17 AS builder
COPY . /tmp/src
RUN cd /tmp/src && \
    GOOS=linux GOARCH=amd64 go build -buildmode=plugin -trimpath -o /tmp/tcp-audit-tracefs-eventer.so && \
    chmod 400 /tmp/tcp-audit-tracefs-eventer.so

FROM scratch
COPY --from=builder /tmp/tcp-audit-tracefs-eventer.so /tmp/tcp-audit-tracefs-eventer.so
ENTRYPOINT []