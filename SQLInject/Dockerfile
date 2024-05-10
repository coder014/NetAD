FROM alpine:3

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apk/repositories
RUN apk add --no-cache php7 php7-pdo_sqlite sqlite

RUN mkdir -p /var/www/sqlinj
COPY ./index.php /var/www/sqlinj/
WORKDIR /var/www/sqlinj

RUN sqlite3 users.db "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
RUN sqlite3 users.db "INSERT INTO users (username, password) VALUES ('admin', 'adminpw')"

EXPOSE 80

CMD ["php", "-S", "0.0.0.0:80"]