FROM malice/alpine

LABEL maintainer "https://github.com/blacktop"

LABEL malice.plugin.repository = "https://github.com/malice-plugins/exe.git"
LABEL malice.plugin.category="pe"
LABEL malice.plugin.mime="application/x-dosexec"
LABEL malice.plugin.docker.engine="*"

COPY . /src/github.com/maliceio/malice-pe
RUN apk --update add --no-cache python py-setuptools
RUN apk --update add --no-cache -t .build-deps \
                                   openssl-dev \
                                   build-base \
                                   python-dev \
                                   libffi-dev \
                                   musl-dev \
                                   libc-dev \
                                   py-pip \
                                   gcc \
                                   git \
  && echo "===> Install pe scanner..." \
  && cd /src/github.com/maliceio/malice-pe \
  && export PIP_NO_CACHE_DIR=off \
  && export PIP_DISABLE_PIP_VERSION_CHECK=on \
  && pip install --upgrade pip wheel \
  && echo " [*] Install requirements..." \
  && pip install -U -r requirements.txt \
  && chmod +x pe.py \
  && ln -s /src/github.com/maliceio/malice-pe/pe.py /bin/pescan \
  && apk del --purge .build-deps

WORKDIR /malware

ENTRYPOINT ["su-exec","malice","/sbin/tini","--","pescan"]
CMD ["--help"]
