FROM gliderlabs/alpine:3.3

MAINTAINER blacktop, https://github.com/blacktop

COPY . /go/src/github.com/maliceio/malice-pe
RUN apk-install python
RUN apk-install -t build-deps go git mercurial python-dev \
  && set -x \
  && echo "Building info Go binary..." \
  && cd /go/src/github.com/maliceio/malice-pe \
  && export GOPATH=/go \
  && go version \
  && go get \
  && go build -ldflags "-X main.Version=$(cat VERSION) -X main.BuildTime=$(date -u +%Y%m%d)" -o /bin/scan \
  && rm -rf /go \
  && apk del --purge build-deps

WORKDIR /malware

ENTRYPOINT ["/bin/scan"]

CMD ["--help"]
