# -*- coding: utf-8 -*-
# This file is part of MaliceIO - https://github.com/malice-plugins/pdf
# See the file 'LICENSE' for copying permission.

import hashlib

import magic
from jinja2 import BaseLoader, Environment


def get_type(data):
    try:
        ms = magic.open(magic.MAGIC_NONE)
        ms.load()
        file_type = ms.buffer(data)
    except Exception:
        try:
            file_type = magic.from_buffer(data)
        except Exception:
            return ''
    finally:
        try:
            ms.close()
        except Exception:
            pass

    return file_type


def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()


def get_md5(data):
    md5 = hashlib.md5()
    md5.update(data)
    return md5.hexdigest()


def json2markdown(json_data):
    """Convert JSON output to MarkDown table"""

    markdown = '''
### exe
{% if pdfid is not none -%}
{%- endif %}
'''

    return Environment(loader=BaseLoader()).from_string(markdown).render(
        pdfid=json_data.get('pdfid'), streams=json_data.get('streams'))

