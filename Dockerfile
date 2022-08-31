FROM python:3.9.13-slim-buster AS python3

COPY . ./

RUN apt update

RUN apt install -y \ 
    build-essential \   
    cmake \
    check \
    cython3 \
    libcurl4-openssl-dev \
    libemu-dev \
    libpcap-dev \
    libssl-dev \
    fonts-liberation \
    tar unzip \
    libffi-dev \
    wget \
    make \
    git nano \
    net-tools iptables \
    apache2 mariadb-server php php-mysqli php-gd libapache2-mod-php

RUN pip3 install -r requirements.txt

RUN chmod +x start.sh

RUN git clone https://github.com/digininja/DVWA.git

COPY ./DVWA/ /var/www/html/

RUN rm -fr ./DVWA/

RUN wget https://lcamtuf.coredump.cx/p0f3/releases/old/2.x/p0f-2.0.8.tgz

RUN tar xvf ./p0f-2.0.8.tgz

RUN mkdir /opt/local

RUN mv ./p0f/p0f.fp /opt/local

RUN mv ./p0f/p0fa.fp /opt/local

RUN mv ./p0f/p0fr.fp /opt/local

RUN mv ./p0f/p0fo.fp /opt/local

RUN rm -fr ./p0f/

RUN rm p0f-2.0.8.tgz

FROM zerotier/zerotier:1.8.7 AS zerotier

COPY --from=python3 . ./

EXPOSE 80 3306

ENTRYPOINT ["/bin/bash", "-c", "/start.sh"]

