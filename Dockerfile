FROM python:3.9.12-slim-buster AS python

WORKDIR /

COPY . ./

ENV VERSION 1.9

RUN apt update

RUN apt install -y net-tools nano wget cmake make git unzip tar libemu-dev libffi-dev libssl-dev \
 libgdbm-dev libsqlite3-dev zlib1g-dev iptables \
 apache2 mariadb-server php php-mysqli php-gd libapache2-mod-php

RUN chmod +x start.sh

COPY conf/* /tmp/

RUN wget https://github.com/ethicalhack3r/DVWA/archive/v${VERSION}.tar.gz && \
    tar xvf /v${VERSION}.tar.gz && \
    mv -f /DVWA-${VERSION} /app && \
    rm /app/.htaccess && \
    mv /tmp/.htaccess /app && \
    chmod +x /tmp/setup_dvwa.sh && \
    /tmp/setup_dvwa.sh

RUN wget https://lcamtuf.coredump.cx/p0f3/releases/old/2.x/p0f-2.0.8.tgz

RUN tar xvf /p0f-2.0.8.tgz

RUN mkdir /opt/local

RUN mv /p0f/p0f.fp /opt/local

RUN mv /p0f/p0fa.fp /opt/local

RUN mv /p0f/p0fr.fp /opt/local

RUN mv /p0f/p0fo.fp /opt/local

RUN rm -fr /p0f/

RUN rm p0f-2.0.8.tgz

RUN pip3 install -r requirements.txt

FROM zerotier/zerotier:1.8.7 AS zerotier

COPY --from=python . ./

EXPOSE 80 3306

ENTRYPOINT ["/bin/bash", "-c", "/start.sh"]

