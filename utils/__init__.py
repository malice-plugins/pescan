# -*- coding: utf-8 -*-
# This file is part of MaliceIO - https://github.com/malice-plugins/pdf
# See the file 'LICENSE' for copying permission.

import sys
reload(sys)
sys.setdefaultencoding("utf-8")

import hashlib
import math
from collections import Counter
from os import path

import magic
from jinja2 import Template

from constants import ROOT


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


def get_entropy(data):
    """Calculate the entropy of a chunk of data."""

    if len(data) == 0:
        return 0.0

    occurences = Counter(bytearray(data))

    entropy = 0
    for x in occurences.values():
        p_x = float(x) / len(data)
        entropy -= p_x * math.log(p_x, 2)

    return entropy


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


def get_sha256(data):
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()


def json2markdown(json_data):
    """Convert JSON output to MarkDown table"""
    with open(path.join(ROOT, 'utils/markdown.jinja2')) as f:
        return Template(f.read()).render(exe=json_data).encode('utf-8')
