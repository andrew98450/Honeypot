FROM python:3.9.12-alpine AS python3

COPY . ./

RUN pip3 install -r requirements.txt

FROM ubuntu:focal AS ubuntu_focal

RUN apt-get update
RUN apt-get install -y apt-utils wget
RUN wget http://archive.ubuntu.com/ubuntu/pool/universe/libe/libemu/libemu2_0.2.0+git20120122-1.2build1_amd64.deb http://archive.ubuntu.com/ubuntu/pool/universe/libe/libemu/libemu-dev_0.2.0+git20120122-1.2build1_amd64.deb
RUN apt-get install ./libemu2_0.2.0+git20120122-1.2build1_amd64.deb ./libemu-dev_0.2.0+git20120122-1.2build1_amd64.deb
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

COPY --from=python3 . ./
COPY --from=ubuntu_focal . ./

