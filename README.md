malice-pe
=========

[![Circle CI](https://circleci.com/gh/maliceio/malice-pe.png?style=shield)](https://circleci.com/gh/maliceio/malice-pe) [![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org) [![Docker Stars](https://img.shields.io/docker/stars/malice/pe.svg)](https://hub.docker.com/r/malice/pe/) [![Docker Pulls](https://img.shields.io/docker/pulls/malice/pe.svg)](https://hub.docker.com/r/malice/pe/) [![Docker Image](https://img.shields.io/badge/docker image-60.7 MB-blue.svg)](https://hub.docker.com/r/malice/pe/)

Malice PExecutable Plugin

This repository contains a **Dockerfile** of **malice/pe** for [Docker](https://www.docker.io/)'s [trusted build](https://index.docker.io/u/malice/pe/) published to the public [DockerHub](https://index.docker.io/).

### Dependencies

-	[malice/alpine](https://hub.docker.com/r/malice/alpine/)

### Installation

1.	Install [Docker](https://www.docker.io/).
2.	Download [trusted build](https://hub.docker.com/r/malice/pe/) from public [DockerHub](https://hub.docker.com): `docker pull malice/pe`

### Usage

```
docker run --rm malice/pe FILE
```

```bash

```

This will output to stdout and POST to malice results API webhook endpoint.

### Sample Output **sandbox** JSON:

```json
{
  "pe": {
  }
}
```

### Sample Output **sandbox** (Markdown Table):

---

#### pe

---

Documentation
-------------

-	[To write results to ElasticSearch](https://github.com/maliceio/malice-pe/blob/master/docs/elasticsearch.md)
-	[To create a pe scan micro-service](https://github.com/maliceio/malice-pe/blob/master/docs/web.md)
-	[To post results to a webhook](https://github.com/maliceio/malice-pe/blob/master/docs/callback.md)

### Issues

Find a bug? Want more features? Find something missing in the documentation? Let me know! Please don't hesitate to [file an issue](https://github.com/maliceio/malice-pe/issues/new)

### CHANGELOG

See [`CHANGELOG.md`](https://github.com/maliceio/malice-pe/blob/master/CHANGELOG.md)

### Contributing

[See all contributors on GitHub](https://github.com/maliceio/malice-pe/graphs/contributors).

Please update the [CHANGELOG.md](https://github.com/maliceio/malice-pe/blob/master/CHANGELOG

### Credits

Heavily (if not entirely) influenced by https://github.com/viper-framework/viper/blob/master/viper/modules/pe.py

### License

MIT Copyright (c) 2016-2017 **blacktop**
