FROM dtagdevsec/dionaea:2204 AS dionaea

COPY . ./

USER root:root

RUN chmod +x start.sh

RUN apt-get update

RUN apt-get install -y python3-pip net-tools nano

RUN pip3 install -r requirements.txt

FROM zerotier/zerotier:latest AS zerotier

COPY --from=dionaea . ./

ENTRYPOINT ["/bin/bash", "-c"]

CMD ["./start.sh"]
