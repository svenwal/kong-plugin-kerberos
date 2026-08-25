# Kong Gateway images already ship libgssapi_krb5, but the open source images
# ship no Kerberos libraries at all. This thin layer makes the same test stack
# work against either base.
ARG BASE_IMAGE=kong/kong-gateway:3.14
FROM ${BASE_IMAGE}

USER root
RUN if [ ! -e /usr/lib/*-linux-gnu/libgssapi_krb5.so.2 ]; then \
      apt-get update && \
      apt-get install -y --no-install-recommends libgssapi-krb5-2 && \
      rm -rf /var/lib/apt/lists/*; \
    fi
USER kong
