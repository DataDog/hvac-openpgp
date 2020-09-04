#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Constants related to the Transit-Secrets-like-Engine."""

from hvac.constants.transit import ALLOWED_HASH_DATA_ALGORITHMS

ALLOWED_KEY_TYPES = {
    'rsa-2048',
    'rsa-3072',
    'rsa-4096',
}

ALLOWED_MARSHALING_ALGORITHMS = {
    'ascii-armor',
    'base64',
}

ALLOWED_SIGNATURE_ALGORITHMS = {
        'pkcs1v15',
}
