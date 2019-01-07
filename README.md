![pescan logo](https://github.com/malice-plugins/pescan/blob/master/docs/exe.png)

# pescan

[![Circle CI](https://circleci.com/gh/malice-plugins/pescan.png?style=shield)](https://circleci.com/gh/malice-plugins/pescan) [![License](http://img.shields.io/:license-mit-blue.svg)](http://doge.mit-license.org) [![Docker Stars](https://img.shields.io/docker/stars/malice/pescan.svg)](https://hub.docker.com/r/malice/pescan/) [![Docker Pulls](https://img.shields.io/docker/pulls/malice/pescan.svg)](https://hub.docker.com/r/malice/pescan/) [![Docker Image](https://img.shields.io/badge/docker%20image-81.7MB-blue.svg)](https://hub.docker.com/r/malice/pescan/)

Malice PExecutable Plugin

> This repository contains a **Dockerfile** of **malice/pescan**.

---

## Dependencies

- [malice/alpine](https://hub.docker.com/r/malice/alpine/)

## Installation

1. Install [Docker](https://www.docker.io/).
2. Download [trusted build](https://hub.docker.com/r/malice/pescan/) from public [DockerHub](https://hub.docker.com): `docker pull malice/pescan`

## Usage

```bash
$ docker run --rm -v /path/to/malware:/malware malice/pescan --help

Usage: pescan [OPTIONS] COMMAND [ARGS]...

  Malice PExecutable Plugin

  Author: blacktop <https://github.com/blacktop>

Options:
  --version   print the version
  -h, --help  Show this message and exit.

Commands:
  scan  scan a file
  web   start web service
```

### Scanning

```bash
$ docker run --rm -v /path/to/malware:/malware malice/pescan scan --help

Usage: pescan.py scan [OPTIONS] FILE_PATH

  Malice PExecutable Scanner

Options:
  -v, --verbose            verbose output
  -t, --table              output as Markdown table
  -x, --proxy PROXY        proxy settings for Malice webhook endpoint [$MALICE_PROXY]
  -c, --callback ENDPOINT  POST results back to Malice webhook [$MALICE_ENDPOINT]
  --elasticsearch HOST     elasticsearch address for Malice to store results [$MALICE_ELASTICSEARCH]
  --timeout SECS           malice plugin timeout (default: 10) [$MALICE_TIMEOUT]
  -d, --dump               dump possibly embedded binaries
  --output PATH            where to extract the embedded objects to (default: /malware)
                           [$MALICE_EXTRACT_PATH]
  --peid PATH              path to the PEiD database file (default:peid/UserDB.TXT)
                           [$MALICE_PEID_PATH]
  -h, --help               Show this message and exit.
```

This will output to stdout and POST to malice results API webhook endpoint.

## Sample Output

### [JSON](https://github.com/malice-plugins/pescan/blob/master/docs/results.json)

```json
{
  "linker_version": "06.00",
  "compiletime": {
    "unix": 1164878434,
    "datetime": "2006-11-30 09:20:34"
  },
  "imports": [
    {
      "name": "GetStartupInfoA",
      "address": "0x406044"
    },
    {
      "name": "GetModuleHandleA",
      "address": "0x406048"
    },
    {
      "name": "CreatePipe",
      "address": "0x40604c"
    },
    {
      "name": "PeekNamedPipe",
      "address": "0x406050"
    },
    {
      "name": "ReadFile",
      "address": "0x406054"
    },
    {
      "name": "CreateProcessA",
      "address": "0x406058"
    },
    ...SNIP...
    {
      "name": "WSACleanup",
      "address": "0x406210"
    },
    {
      "name": "ioctlsocket",
      "address": "0x406214"
    }
  ],
  "resource_versioninfo": {
    "legalcopyright": "(C) Microsoft Corporation. All rights reserved.",
    "internalname": "iexplore",
    "fileversion": "6.00.2900.2180 (xpsp_sp2_rtm.040803-2158)",
    "companyname": "Microsoft Corporation",
    "productname": "Microsoft(R) Windows(R) Operating System",
    "productversion": "6.00.2900.2180",
    "original_filename": "IEXPLORE.EXE",
    "file_description": "Internet Explorer"
  },
  "rich_header_info": [
    {
      "tool_id": 12,
      "version": 7291,
      "times used": 1
    },
    ...SNIP...
    {
      "tool_id": 6,
      "version": 1720,
      "times used": 1
    }
  ],
  "os_version": "04.00",
  "is_packed": false,
  "entrypoint": "0x5a46",
  "sections": [
    {
      "raw_data_size": 20480,
      "name": ".text",
      "rva": "0x1000",
      "pointer_to_raw_data": 4096,
      "entropy": 5.988944574755928,
      "virtual_size": "0x4bfe"
    },
    {
      "raw_data_size": 4096,
      "name": ".rdata",
      "rva": "0x6000",
      "pointer_to_raw_data": 24576,
      "entropy": 3.291179369026711,
      "virtual_size": "0xc44"
    },
    {
      "raw_data_size": 4096,
      "name": ".data",
      "rva": "0x7000",
      "pointer_to_raw_data": 28672,
      "entropy": 4.04448531075933,
      "virtual_size": "0x17b0"
    },
    {
      "raw_data_size": 8192,
      "name": ".rsrc",
      "rva": "0x9000",
      "pointer_to_raw_data": 32768,
      "entropy": 4.49716326553469,
      "virtual_size": "0x15d0"
    }
  ],
  "resources": [
    {
      "language_desc": "Chinese-People's Republic of China",
      "sublanguage": "SUBLANG_CHINESE_SIMPLIFIED",
      "name": "RT_ICON",
      "language": "LANG_CHINESE",
      "offset": "0x90f0",
      "size": "0x10a8",
      "type": "data",
      "id": 1,
      "md5": "14bf7c82dcfb7e41243f5b87d0c79538"
    },
    {
      "language_desc": "Chinese-People's Republic of China",
      "sublanguage": "SUBLANG_CHINESE_SIMPLIFIED",
      "name": "RT_GROUP_ICON",
      "language": "LANG_CHINESE",
      "offset": "0xa198",
      "size": "0x14",
      "type": "data",
      "id": 2,
      "md5": "3c68f77c35c26ff079a1c410ee44fa62"
    },
    {
      "language_desc": "Chinese-People's Republic of China",
      "sublanguage": "SUBLANG_CHINESE_SIMPLIFIED",
      "name": "RT_VERSION",
      "language": "LANG_CHINESE",
      "offset": "0xa1b0",
      "size": "0x41c",
      "type": "data",
      "id": 3,
      "md5": "9a12ece86a71c3499df0fb0ebe6ea33e"
    }
  ],
  "peid": [
    "Armadillo v1.71",
    "Microsoft Visual C++ v5.0/v6.0 (MFC)",
    "Microsoft Visual C++"
  ],
  "calculated_file_size": 42448,
  "imphash": "a2cee99c7e42d671d47e3fb71c71bda4",
  "number_of_sections": 4,
  "pehash": "884bf0684addc269d641efb74e0fcb88267211da",
  "machine_type": "0x14c (IMAGE_FILE_MACHINE_I386)",
  "image_base": 4194304,
  "language": "C",
  "size_of_image": 45056,
  "signature": {
    "heuristic": "No file signature data found"
  }
}
```

### [Markdown](https://github.com/malice-plugins/pescan/blob/master/docs/SAMPLE.md)

---

### pescan

#### Header

- **Target Machine:** `0x14c (IMAGE_FILE_MACHINE_I386)`
- **Compilation Timestamp:** `2006-11-30 09:20:34`
- **Entry Point:** `0x5a46`
- **Contained Sections:** `4`

#### Sections

| Name   | Virtual Address | Virtual Size | Raw Size | Entropy | MD5                              |
| ------ | --------------- | ------------ | -------- | ------- | -------------------------------- |
| .text  | 0x1000          | 0x4bfe       | 20480    | 5.99    | 9062ff3acdff9ac80cd9f97a0df42383 |
| .rdata | 0x6000          | 0xc44        | 4096     | 3.29    | 28c9e7872eb9d0a20a1d953382722735 |
| .data  | 0x7000          | 0x17b0       | 4096     | 4.04    | c38a0453ad319c9cd8b1760baf57a528 |
| .rsrc  | 0x9000          | 0x15d0       | 8192     | 4.50    | 0d4522a26417d45c33759d2a6375a55f |

#### Imports

##### `KERNEL32.DLL`

- GetStartupInfoA
- GetModuleHandleA
- CreatePipe
- PeekNamedPipe
- ReadFile
- CreateProcessA

...SNIP...

##### `ADVAPI32.dll`

- RegCloseKey
- RegSetValueExA
- RegQueryValueExA

...SNIP...

##### `MPR.dll`

- WNetCloseEnum
- WNetOpenEnumA
- WNetEnumResourceA

##### `MSVCRT.dll`

- \_except_handler3
- \_\_set_app_type
- **p**fmode

...SNIP...

##### `SHLWAPI.dll`

- SHDeleteKeyA

##### `WS2_32.dll`

- gethostname
- gethostbyname

  ...SNIP...

#### Resources

| SHA-256                                                          | Size   | Entropy | File Type | Type          | Language                           |
| ---------------------------------------------------------------- | ------ | ------- | --------- | ------------- | ---------------------------------- |
| 52a955550acda3b566c9fa9eda164853df4135dfa5eb7b173b3c5453a12f85a3 | 0x10a8 | 6.52    | None      | RT_ICON       | Chinese-People's Republic of China |
| a14e70ed824f3f17d3a51136aa08839954d6d3ccadaa067415c7bfc08e6636b0 | 0x14   | 1.78    | None      | RT_GROUP_ICON | Chinese-People's Republic of China |
| 934b13844893dc0438a47aadc20d4873f806000c761249795c7f265ccca48bc9 | 0x41c  | 3.47    | None      | RT_VERSION    | Chinese-People's Republic of China |

#### File Version Information

- **Copyright:** `(C) Microsoft Corporation. All rights reserved.`
- **Product:** `Microsoft(R) Windows(R) Operating System`
- **Description:** `Internet Explorer`
- **Original Name:** `IEXPLORE.EXE`
- **Internal Name:** `iexplore`
- **File Version:** `6.00.2900.2180 (xpsp_sp2_rtm.040803-2158)`

#### Signature Info

##### Signature Verification

> No file signature data found

#### PEiD

- `Armadillo v1.71`
- `Microsoft Visual C++ v5.0/v6.0 (MFC)`
- `Microsoft Visual C++`

---

## Documentation

- [To write results to ElasticSearch](https://github.com/malice-plugins/pescan/blob/master/docs/elasticsearch.md)
- [To create a pe scan micro-service](https://github.com/malice-plugins/pescan/blob/master/docs/web.md)
- [To post results to a webhook](https://github.com/malice-plugins/pescan/blob/master/docs/callback.md)

## Issues

Find a bug? Want more features? Find something missing in the documentation? Let me know! Please don't hesitate to [file an issue](https://github.com/malice-plugins/pescan/issues/new)

## CHANGELOG

See [`CHANGELOG.md`](https://github.com/malice-plugins/pescan/blob/master/CHANGELOG.md)

## Contributing

[See all contributors on GitHub](https://github.com/malice-plugins/pescan/graphs/contributors).

Please update the [CHANGELOG.md](https://github.com/malice-plugins/pescan/blob/master/CHANGELOG)

## Credits

Heavily (if not entirely) influenced by the [viper PE module](https://github.com/viper-framework/viper/blob/master/viper/modules/pe.py) and by CSE's [alsvc_pefile](https://bitbucket.org/cse-assemblyline/alsvc_pefile)

## TODO

- [x] activate dumping functionality
- [ ] add timeout protection
- [ ] revisit security/signature stuff
- [ ] add proxy settings for callback POST

## License

MIT Copyright (c) 2016 **blacktop**
