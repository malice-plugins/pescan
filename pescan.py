#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of MaliceIO - https://github.com/malice-plugins/pescan
# See the file 'LICENSE' for copying permission.

__description__ = 'Malice PExecutable Plugin'
__author__ = 'blacktop - <https://github.com/blacktop>'
__version__ = '0.1.0'
__date__ = '2018/08/01'

import json
import logging
import os
from sys import path

import click
import requests
from flask import Flask, abort, jsonify, redirect, request
from werkzeug.utils import secure_filename

from elastic import Elastic
from malice import MalPEFile
from utils import json2markdown, sha256_checksum
from utils.constants import ROOT

log = logging.getLogger(__name__)


def init_logging(verbose):
    # create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(verbose)
    ch.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    # add ch to logger
    log.addHandler(ch)

    malpefile = logging.getLogger('malice')
    malpefile.propagate = False
    malpefile.setLevel(verbose)
    malpefile.addHandler(ch)

    # get elasticsearch logger
    es_logger = logging.getLogger('elasticsearch')
    es_logger.propagate = False
    es_logger.setLevel(verbose)
    es_logger.addHandler(ch)


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo('v{}'.format(__version__))
    ctx.exit()


@click.group(context_settings=dict(help_option_names=['-h', '--help']))
@click.option(
    '--version', is_flag=True, callback=print_version, expose_value=False, is_eager=True, help='print the version')
def exe():
    """Malice PExecutable Plugin

    Author: blacktop <https://github.com/blacktop>
    """


@exe.command('scan', short_help='scan a file')
@click.argument('file_path', type=click.Path(exists=True))
@click.option('-v', '--verbose', count=True, help='verbose output')
@click.option('-t', '--table', is_flag=True, help='output as Markdown table')
@click.option(
    '-x',
    '--proxy',
    default=lambda: os.environ.get('MALICE_PROXY', ''),
    help='proxy settings for Malice webhook endpoint [$MALICE_PROXY]',
    metavar='PROXY')
@click.option(
    '-c',
    '--callback',
    default=lambda: os.environ.get('MALICE_ENDPOINT', ''),
    help='POST results back to Malice webhook [$MALICE_ENDPOINT]',
    metavar='ENDPOINT')
@click.option(
    'eshost',
    '--elasticsearch',
    default=lambda: os.environ.get('MALICE_ELASTICSEARCH_URL', ''),
    help='elasticsearch address for Malice to store results [$MALICE_ELASTICSEARCH_URL]',
    metavar='HOST')
@click.option(
    '--timeout',
    default=lambda: os.environ.get('MALICE_TIMEOUT', 10),
    help='malice plugin timeout (default: 10) [$MALICE_TIMEOUT]',
    type=click.INT,
    metavar='SECS')
@click.option('-d', '--dump', is_flag=True, help='dump possibly embedded binaries')
@click.option(
    '--output',
    default=lambda: os.environ.get('MALICE_EXTRACT_PATH', '/malware'),
    help='where to extract the embedded objects to (default: /malware) [$MALICE_EXTRACT_PATH]',
    metavar='PATH')
@click.option(
    '--peid',
    default=lambda: os.environ.get('MALICE_PEID_PATH', os.path.join(ROOT, 'peid/UserDB.TXT')),
    help='path to the PEiD database file (default: peid/UserDB.TXT) [$MALICE_PEID_PATH]',
    metavar='PATH')
def scan(file_path, verbose, table, proxy, callback, eshost, timeout, dump, output, peid):
    """Malice PExecutable Scanner"""

    try:
        # set up logging
        init_logging(verbose)

        # TODO: check if EXE is too big (max size 3000000 ??)
        pe_results = MalPEFile(file_path, peid_db_path=peid, should_dump=dump, dump_path=output).run()

        malice_scan = {
            'id': os.environ.get('MALICE_SCANID', sha256_checksum(file_path)),
            'name': 'pescan',
            'category': 'exe',
            'results': pe_results
        }
        try:
            malice_scan['results']['markdown'] = json2markdown(pe_results)
        except Exception as e:
            log.exception("failed to render jinja template")
            malice_scan['results']['markdown'] = e.message

        # write to elasticsearch
        if eshost:
            try:
                e = Elastic(eshost, timeout=timeout)
                e.write(results=malice_scan)
            except Exception as e:
                log.exception("failed to index malice/pescan results into elasticsearch")

        if table:
            print(malice_scan['results']['markdown'])
        else:
            pe_results.pop('markdown')
            print(json.dumps(pe_results, indent=True))

        # POST dropped files as a JSON blob back to malice server/daemon
        if callback:
            proxies = None
            if proxy:
                proxies = {
                    'http': proxy,
                    'https': proxy,
                }
            malice_scan['parent'] = os.environ.get('MALICE_SCANID', sha256_checksum(file_path))
            requests.post(callback, json=malice_scan, proxies=proxies)

    except Exception as e:
        log.exception("failed to run malice plugin: pescan")
        return


@exe.command('web', short_help='start web service')
def web():
    """Malice PExecutable Web Service"""

    # set up logging
    init_logging(logging.ERROR)

    app = Flask(__name__)
    app.config['UPLOAD_FOLDER'] = '/malware'
    app.config['OUTPUT_FOLDER'] = '/malware/dump'
    app.config['PEID_PATH'] = os.path.join(path[0], 'peid/UserDB.TXT')
    # app.config['UPLOAD_FOLDER'] = 'test/web'
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

    @app.errorhandler(400)
    def bad_request(error):
        return 'Bad requests: you must upload a malware', 400

    @app.errorhandler(500)
    def server_error(exception):
        return 'Internal Server Error: \n{}'.format(exception), 500

    @app.route('/scan', methods=['GET', 'POST'])
    def upload():
        if request.method == 'POST':
            # check if the post request has the file part
            if 'malware' not in request.files:
                return redirect(request.url)
            upload_file = request.files['malware']
            # if user does not select file, browser also
            # submit an empty part without filename
            if upload_file.filename == '':
                abort(400)
            if upload_file:
                filename = secure_filename(upload_file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                upload_file.save(file_path)
                try:
                    pe_results = MalPEFile(file_path, peid_db_path=app.config['PEID_PATH']).run()
                    # pe_results['markdown'] = json2markdown(pe_results)
                    return jsonify(pe_results), 200
                except Exception as e:
                    log.exception("failed to run malice plugin: {}".format('pescan'))
                    return e, 500
                finally:
                    try:
                        os.remove(file_path)
                    except OSError as e:
                        log.exception("failed to remove file {} - {}".format(e.filename, e.strerror))

        return "Please upload malware to me... I thirst."

    # start web service
    app.run(host='0.0.0.0', port=3993)


if __name__ == '__main__':
    exe()
