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
### pdf
{% if pdfid is not none -%}
#### [PDFiD]
 - **PDF Header:** `{{ pdfid['header'] }}`
 - **Total Entropy:** `{{ pdfid['totalEntropy'] }}`
 - **Entropy In Streams:** `{{ pdfid['streamEntropy'] }}`
 - **Entropy Out Streams:** `{{ pdfid['nonStreamEntropy'] }}`
 - **Count %% EOF:** `{{ pdfid['countEof'] }}`
 - **Data After EOF:** `{{ pdfid['countChatAfterLastEof'] }}`

| Keyword     | Count     |
|-------------|-----------|
{% for keyword in pdfid['keywords'].get('keyword') -%}
| {{ keyword.get('name') }}      | {{ keyword.get('count') }}        |
{% endfor -%}
{% if pdfid['heuristics']['embeddedfile'].get('score') > 0 %}
##### Embedded File
> **Score:** `{{ pdfid['heuristics']['embeddedfile'].get('score') }}`
 - {{ pdfid['heuristics']['embeddedfile'].get('reason') }}
{%- endif %}
{% if pdfid['heuristics']['nameobfuscation'].get('score') > 0 -%}
##### Name Obfuscation
> **Score:** `{{ pdfid['heuristics']['nameobfuscation'].get('score') }}`
 - {{ pdfid['heuristics']['nameobfuscation'].get('reason') }}
{%- endif %}
{% if pdfid['heuristics']['triage'].get('score') > 0 -%}
##### Triage
> **Score:** `{{ pdfid['heuristics']['triage'].get('score') }}`
{% for reason in pdfid['heuristics']['triage'].get('reasons') -%}
 - {{ reason }}
{% endfor -%}
{%- endif %}
{% if pdfid['heuristics']['suspicious'].get('score') > 0 -%}
##### Suspicious Properties
> **Score:** `{{ pdfid['heuristics']['suspicious'].get('score') }}`
{% for reason in pdfid['heuristics']['suspicious'].get('reasons') -%}
 - {{ reason }}
{% endfor -%}
{%- endif %}
{%- endif %}
{% if streams is not none -%}
#### [pdf-parser]

##### Stats
{% for stat in streams.get('stats') -%}
 - `{{ stat }}`
{% endfor -%}

{% if streams.get('tags') %}
##### TAGS
{% for key, values in streams.get('tags').items() -%}
**{{ key }}:**
{% for v in values -%}
 - `{{ v }}`
{% endfor %}
{% endfor -%}
{%- endif %}
{% if streams.get('embedded') -%}
##### Embedded Files
| Object      | Sha256   |
|-------------|----------|
{% for embedded in streams.get('embedded') -%}
| {{ embedded.get('object') }} | {{ embedded.get('sha256') }} |
{% endfor -%}
{%- endif %}
{% if streams.get('objstm') -%}
##### Object Streams
| Object      | Sha256   |
|-------------|----------|
{% for objstm in streams.get('objstm') -%}
| {{ objstm.get('object') }} | {{ objstm.get('sha256') }} |
{% endfor -%}
{%- endif %}
{% if streams.get('carved') -%}
{% if streams['carved'].get('files') -%}
##### Carved Files
| Object     | Content  | Sha256 |
|------------|----------|--------|
{% for cfile in streams['carved'].get('files') -%}
| {{ cfile.get('object') }} | {{ cfile.get('keyword') }} | {{ cfile.get('sha256') }} |
{% endfor -%}
{%- endif %}
{% if streams['carved'].get('contents') -%}
##### Carved Content
{% for content in streams['carved'].get('contents') -%}
**{{ content.get('key') }}:**
```{% if 'JS' in content.get('key') %}javascript{% endif %}
{{ content.get('content') }}
```
{% endfor -%}
{%- endif %}
{%- endif %}
{%- endif %}
'''

    return Environment(loader=BaseLoader()).from_string(markdown).render(
        pdfid=json_data.get('pdfid'), streams=json_data.get('streams'))
