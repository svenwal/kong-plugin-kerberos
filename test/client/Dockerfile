FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         krb5-user curl jq ca-certificates iputils-ping dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /suite
ENTRYPOINT ["/suite/run-tests.sh"]
