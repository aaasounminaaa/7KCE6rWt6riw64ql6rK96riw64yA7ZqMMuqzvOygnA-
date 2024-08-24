FROM alpine:latest

# ENV MYSQL_USER=<USERNAME>
# ENV MYSQL_PASSWORD=<PASSWORD>
# ENV MYSQL_HOST=<RDS_EP>
# ENV MYSQL_PORT=<PORT>
# ENV MYSQL_DBNAME=dev

WORKDIR /app
COPY ./customer /app/customer
RUN apk update && \
    apk add --no-cache libc6-compat libstdc++ libgcc curl openssl && \
    apk upgrade --no-cache busybox && \
    chmod +x /app/customer && \
    adduser -D -H -s /bin/sh customer && \
    mkdir -p /log/ && \
    chown customer:customer /log
USER customer
EXPOSE 8080

CMD ["/bin/sh", "-c", "/app/customer >> /log/customer.log 2>&1"]