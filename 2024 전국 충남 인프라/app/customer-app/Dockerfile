FROM alpine:latest
WORKDIR /app
RUN apk update && apk add --no-cache \
    libc6-compat \
    libstdc++ \
    libgcc
RUN apk upgrade --no-cache busybox
COPY ./customer /app/customer
RUN chmod +x /app/customer

# ENV MYSQL_USER=rds_user
# ENV MYSQL_PASSWORD=skill39##
# ENV MYSQL_HOST=database-1-instance-1.cmjijxwdspmf.ap-northeast-2.rds.amazonaws.com
# ENV MYSQL_PORT=3306
# ENV MYSQL_DBNAME=seoul_db

EXPOSE 8080

CMD ["/app/customer"]