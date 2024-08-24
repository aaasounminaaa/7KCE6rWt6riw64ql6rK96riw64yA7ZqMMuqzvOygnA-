FROM alpine:latest

WORKDIR /app
COPY ./order /app/order
RUN apk update && \
    apk add --no-cache libc6-compat libstdc++ libgcc curl openssl && \
    apk upgrade --no-cache busybox && \
    chmod +x /app/order && \
    adduser -D -H -s /bin/sh order && \
    mkdir -p /log/ && \
    chown order:order /log
USER order
EXPOSE 8080

CMD ["/bin/sh", "-c", "/app/order >> /log/order.log 2>&1"]