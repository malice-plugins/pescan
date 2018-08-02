# -*- coding: utf-8 -*-
# This file is part of MaliceIO - https://github.com/malice-plugins/pdf
# See the file 'LICENSE' for copying permission.

mapping = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
    },
    "mappings": {
        "_default_": {
            "_all": {
                "enabled": True
            }
        },
        "samples": {
            "properties": {
                "file": {
                    "properties": {
                        "md5": {
                            "type": "string"
                        },
                        "mime": {
                            "type": "string"
                        },
                        "name": {
                            "type": "string"
                        },
                        "path": {
                            "type": "string"
                        },
                        "sha1": {
                            "type": "string"
                        },
                        "sha256": {
                            "type": "string"
                        },
                        "sha512": {
                            "type": "string"
                        },
                        "size": {
                            "type": "string"
                        }
                    }
                },
                "plugins": {
                    "properties": {
                        "archive": {
                            "type": "object"
                        },
                        "av": {
                            "type": "object"
                        },
                        "document": {
                            "type": "object"
                        },
                        "exe": {
                            "type": "object"
                        },
                        "intel": {
                            "type": "object",
                            "properties": {
                                "virustotal": {
                                    "dynamic": False,
                                    "type": "object"
                                }
                            }
                        },
                        "metadata": {
                            "type": "object"
                        }
                    }
                },
                "scan_date": {
                    "type": "date"
                }
            }
        }
    }
}
