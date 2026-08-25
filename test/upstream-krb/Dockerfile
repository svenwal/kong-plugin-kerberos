FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         apache2 libapache2-mod-auth-gssapi krb5-user \
    && rm -rf /var/lib/apt/lists/*

RUN a2enmod auth_gssapi cgid \
    && a2dissite 000-default

COPY site.conf /etc/apache2/sites-available/secure.conf
COPY whoami.cgi /usr/lib/cgi-bin/whoami
RUN chmod +x /usr/lib/cgi-bin/whoami && a2ensite secure

EXPOSE 80
CMD ["apachectl", "-D", "FOREGROUND"]
