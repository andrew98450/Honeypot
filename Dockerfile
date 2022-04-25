FROM python:3.9.12-slim AS python3

COPY . ./

RUN pip3 install -r requirements.txt

FROM zerotier/zerotier:latest AS zerotier

COPY --from=python3 . ./

FROM ubuntu:20.04 AS ubuntu

COPY --from=zerotier . ./

RUN apt-get update
RUN wget http://archive.ubuntu.com/ubuntu/pool/universe/libe/libemu/libemu2_0.2.0+git20120122-1.2build1_amd64.deb http://archive.ubuntu.com/ubuntu/pool/universe/libe/libemu/libemu-dev_0.2.0+git20120122-1.2build1_amd64.deb
RUN apt install ./libemu2_0.2.0+git20120122-1.2build1_amd64.deb ./libemu-dev_0.2.0+git20120122-1.2build1_amd64.deb
RUN apt-get install \
    build-essential \
    cmake \
    check \
    cython3 \
    libcurl4-openssl-dev \
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
RUN sudo make install

