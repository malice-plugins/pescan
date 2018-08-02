exe
===

[![Circle CI](https://circleci.com/gh/malice-plugins/exe.png?style=shield)](https://circleci.com/gh/malice-plugins/exe) [![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org) [![Docker Stars](https://img.shields.io/docker/stars/malice/exe.svg)](https://hub.docker.com/r/malice/exe/) [![Docker Pulls](https://img.shields.io/docker/pulls/malice/exe.svg)](https://hub.docker.com/r/malice/exe/) [![Docker Image](https://img.shields.io/badge/docker%20image-73.2MB-blue.svg)](https://hub.docker.com/r/malice/exe/)

Malice PExecutable Plugin

> This repository contains a **Dockerfile** of **malice/exe**.

---

Dependencies
------------

-	[malice/alpine](https://hub.docker.com/r/malice/alpine/)

Installation
------------

1.	Install [Docker](https://www.docker.io/).
2.	Download [trusted build](https://hub.docker.com/r/malice/exe/) from public [DockerHub](https://hub.docker.com): `docker pull malice/exe`

Usage
-----

```
docker run --rm -v /path/to/malware:/malware malice/exe EXE
```

```bash

```

This will output to stdout and POST to malice results API webhook endpoint.

Sample Output
-------------

### [JSON](https://github.com/malice-plugins/exe/blob/master/docs/results.json)

```json
{
  "exe": {
  }
}
```

### [Markdown](https://github.com/malice-plugins/exe/blob/master/docs/SAMPLE.md)

---

#### exe

---

Documentation
-------------

-	[To write results to ElasticSearch](https://github.com/malice-plugins/exe/blob/master/docs/elasticsearch.md)
-	[To create a pe scan micro-service](https://github.com/malice-plugins/exe/blob/master/docs/web.md)
-	[To post results to a webhook](https://github.com/malice-plugins/exe/blob/master/docs/callback.md)

Issues
------

Find a bug? Want more features? Find something missing in the documentation? Let me know! Please don't hesitate to [file an issue](https://github.com/malice-plugins/exe/issues/new)

CHANGELOG
---------

See [`CHANGELOG.md`](https://github.com/malice-plugins/exe/blob/master/CHANGELOG.md)

Contributing
------------

[See all contributors on GitHub](https://github.com/malice-plugins/exe/graphs/contributors).

Please update the [CHANGELOG.md](https://github.com/malice-plugins/exe/blob/master/CHANGELOG)

Credits
-------

Heavily (if not entirely) influenced by the [viper PE module](https://github.com/viper-framework/viper/blob/master/viper/modules/pe.py)

TODO
----

-	[ ] add other's LICENSEs

License
-------

MIT Copyright (c) 2016 **blacktop**
