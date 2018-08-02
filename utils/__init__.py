# -*- coding: utf-8 -*-
# This file is part of MaliceIO - https://github.com/malice-plugins/pdf
# See the file 'LICENSE' for copying permission.

import hashlib

from jinja2 import BaseLoader, Environment


def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()


def json2markdown(json_data):
    """Convert JSON output to MarkDown table"""

    markdown = '''
### exe
{% if pdfid is not none -%}
{%- endif %}
'''

    return Environment(loader=BaseLoader()).from_string(markdown).render(
        pdfid=json_data.get('pdfid'), streams=json_data.get('streams'))
