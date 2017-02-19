FROM malice/alpine

LABEL maintainer "https://github.com/blacktop"

COPY . /src/github.com/maliceio/malice-pe
RUN apk --update add --no-cache python
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
  && ln -s ./pe.py /bin/pescan \
  && apk del --purge .build-deps

WORKDIR /malware

ENTRYPOINT ["su-exec","malice","/sbin/tini","--","pescan"]
CMD ["--help"]
