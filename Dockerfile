FROM dinotools/dionaea:nightly AS dionaea

COPY . ./

RUN chmod +x start.sh

RUN apt-get update

RUN apt-get install -y net-tools nano wget cmake make build-essential libssl-dev zlib1g-dev \
       libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm \
       libncurses5-dev libncursesw5-dev xz-utils tk-dev libffi-dev

RUN wget https://lcamtuf.coredump.cx/p0f3/releases/p0f-3.09b.tgz

RUN tar xvf p0f-3.09b.tgz

RUN make -C ./p0f-3.09b/

RUN make -C ./p0f-3.09b/ install

RUN wget https://www.python.org/ftp/python/3.9.13/Python-3.9.13.tar.xz

RUN tar xvf Python-3.9.13.tar.xz

RUN ./Python-3.9.13/configure --with-ensurepip=install

RUN make -j2

RUN make install

RUN ldconfig

RUN pip3 install -r requirements.txt

FROM zerotier/zerotier:1.8.10 AS zerotier

COPY --from=dionaea . ./

HEALTHCHECK --interval=5s --timeout=3s CMD /usr/local/sbin/entrypoint.sh &

ENTRYPOINT ["/bin/bash", "-c"]

CMD ["./start.sh"]
