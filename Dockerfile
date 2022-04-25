FROM python:3.9.12-alpine AS python3

COPY . ./

RUN pip3 install -r requirements.txt

FROM ubuntu:focal AS ubuntu_focal

COPY --from=python3 . ./

RUN apt-get update
RUN apt-get install -y wget apt-utils
RUN apt-get install -y \
    build-essential \
    cmake \
    check \
    cython3 \
    libcurl4-openssl-dev \
    libemu-dev \
    libev-dev \
    libglib2.0-dev \
    libloudmouth1-dev \
    libnetfilter-queue-dev \
    libnl-3-dev \
    libpcap-dev \
    libssl-dev \
    libtool \
    libudns-dev \
    fonts-liberation \ 
    git \
    make

RUN git clone https://github.com/DinoTools/dionaea.git
RUN cd dionaea

RUN mkdir build
RUN cd build
RUN cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/dionaea ..

RUN make
RUN make install

FROM zerotier/zerotier:latest AS zerotier

COPY --from=ubuntu_focal . ./

