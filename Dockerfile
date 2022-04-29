FROM dinotools/dionaea:nightly AS dionaea

COPY . ./

RUN apt-get update

RUN apt-get install -y python3-pip net-tools nano

RUN /usr/local/sbin/entrypoint.sh &

RUN pip3 install -r requirements.txt

FROM zerotier/zerotier:latest AS zerotier

COPY --from=dionaea . ./

CMD ["python3", "sniff.py"]

