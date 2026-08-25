FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         krb5-kdc krb5-admin-server krb5-user procps \
    && rm -rf /var/lib/apt/lists/*

COPY kdc.conf /etc/krb5kdc/kdc.conf
COPY kadm5.acl /etc/krb5kdc/kadm5.acl
COPY bootstrap.sh /usr/local/bin/bootstrap.sh
RUN chmod +x /usr/local/bin/bootstrap.sh

EXPOSE 88/tcp 88/udp 749/tcp

ENTRYPOINT ["/usr/local/bin/bootstrap.sh"]
