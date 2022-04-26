FROM ubuntu:18.04 AS ubuntu_18

COPY . ./

RUN apt-get update
RUN export DEBIAN_FRONTEND=noninteractive

RUN apt-get install -q -y tzdata
RUN apt-get install -q -y apt-utils
RUN apt-get install -q -y \
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
    python3 \
    python3-pip \
    python3-dev \
    python3-bson \
    python3-yaml \
    python3-boto3 \
    fonts-liberation \
    make \
    git

RUN pip3 install -r requirements.txt

RUN git clone https://github.com/DinoTools/dionaea.git
RUN cd dionaea

RUN mkdir build
RUN cd build
RUN cmake -DCMAKE_INSTALL_PREFIX:PATH="/opt/dionaea" ./dionaea

RUN make
RUN make install

FROM zerotier/zerotier:latest AS zerotier

COPY --from=ubuntu_18 . ./

