FROM alpine:latest

# ENV MYSQL_USER=<USERNAME>
# ENV MYSQL_PASSWORD=<PASSWORD>
# ENV MYSQL_HOST=<RDS_EP>
# ENV MYSQL_PORT=<PORT>
# ENV MYSQL_DBNAME=dev

WORKDIR /app
COPY ./product /app/product
RUN apk update && \
    apk add --no-cache libc6-compat libstdc++ libgcc curl openssl && \
    apk upgrade --no-cache busybox && \
    chmod +x /app/product && \
    adduser -D -H -s /bin/sh product && \
    mkdir -p /log/ && \
    chown product:product /log
USER product
EXPOSE 8080

CMD ["/bin/sh", "-c", "/app/product >> /log/product.log 2>&1"]