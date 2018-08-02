# -*- coding: utf-8 -*-
# This file is part of MaliceIO - https://github.com/malice-plugins/pdf
# See the file 'LICENSE' for copying permission.

__description__ = "Malice PDF Plugin Elasticsearch Interface"
__author__ = "blacktop - <https://github.com/blacktop>"

import time
from datetime import datetime

import elasticsearch

from . import mapping


class Elastic(object):

    def __init__(self, elastic_host, timeout=0):
        self.es = elasticsearch.Elasticsearch(elastic_host)

        # wait for elasticsearch to finish starting
        for _ in range(timeout):
            if self.es.ping():
                break
            time.sleep(1)

        if not self.es.ping():
            raise elasticsearch.ElasticsearchException("[PING] cannot connect to host: {}".format(elastic_host))

        # create malice index
        self.es.indices.create(index="malice", ignore=400)
        # self.es.indices.create(index="malice", ignore=400, body=mapping)

    def write(self, results):
        """Write malice plugin results to Elasticsearch database."""

        # sample already in malice DB (update sample with plugin results)
        if self.es.exists(index="malice", doc_type="samples", id=results['id']):
            update_scan = {
                'scan_date': datetime.now(),
                'plugins': {
                    results['category']: {
                        results['name']: results['results']
                    }
                }
            }
            resp = self.es.update(index="malice", doc_type="samples", id=results['id'], body=dict(doc=update_scan))
            if not resp.get("result"):
                raise elasticsearch.ElasticsearchException("[UPDATE] failed to update doc with id: {}".format(
                    results['id']))
            return

        scan = {'scan_date': datetime.now(), 'plugins': {results['category']: {results['name']: results['results']}}}
        resp = self.es.index(index="malice", doc_type="samples", id=results['id'], body=scan)
        if not resp.get("result"):
            raise elasticsearch.ElasticsearchException("[INDEX] failed to write doc with id: {}".format(results['id']))
