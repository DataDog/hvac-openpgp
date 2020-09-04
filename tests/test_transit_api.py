  #!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Transit-Secrets-Engine-like API test module."""

import base64
import os
import sys
import unittest
import uuid

from hvac.exceptions import (
  InvalidPath,
  InvalidRequest,
  ParamValidationError
)

from hvac_openpgp import Client
from hvac_openpgp.constants import (
  ALLOWED_HASH_DATA_ALGORITHMS,
  ALLOWED_KEY_TYPES,
  ALLOWED_MARSHALING_ALGORITHMS,
  ALLOWED_SIGNATURE_ALGORITHMS,
)
from hvac_openpgp.exceptions import UnsupportedParam

class TestOpenPGP(unittest.TestCase):

  def setUp(self):
    # Useful test constants.
    self.EXPORTABLE = (None, False, True)

    # The only part of the API we care about.
    self.__client = Client(os.environ['VAULT_ADDR'], os.environ['VAULT_TOKEN'])
    self.openpgp = self.__client.secrets.openpgp

  def random_name(self):
    return str(uuid.uuid4())

  def test_create_key(self):
    # Unsupported parameters.
    unsupported_parameters = (
      {'allow_plaintext_backup': True},
      {'convergent_encryption': True},
      {'derived': True},
    )
    for parameter in unsupported_parameters:
      with self.assertRaises(UnsupportedParam,
                             msg=f'Unsupported parameter: {parameter}!'):
        self.openpgp.create_key(self.random_name(), **parameter)

    # No key type.
    with self.assertRaises(ParamValidationError, msg='No key type!'):
      self.openpgp.create_key(self.random_name())

    # Duplicate keys.
    for key_type in ALLOWED_KEY_TYPES:
      fixed_name = self.random_name()
      self.openpgp.create_key(fixed_name, key_type=key_type)
      with self.assertRaises(InvalidRequest, msg='Duplicate key created!'):
        self.openpgp.create_key(fixed_name, key_type=key_type)

    # Allowed key types, exportable values, real names, and email addresses.
    for key_type in ALLOWED_KEY_TYPES:
      for exportable in self.EXPORTABLE:
        for real_name in (None, 'John Doe'):
          for email in (None, 'john.doe@datadoghq.com'):
            r = self.openpgp.create_key(self.random_name(),
                                        key_type=key_type,
                                        exportable=exportable,
                                        real_name=real_name,
                                        email=email)
            r.raise_for_status()

  def test_read_key(self):
    # Read non-existent key.
    with self.assertRaises(InvalidPath, msg='Read non-existent key!'):
      self.openpgp.read_key(self.random_name())

    # Read existing keys.
    for key_type in ALLOWED_KEY_TYPES:
      for exportable in self.EXPORTABLE:
        name = self.random_name()
        r = self.openpgp.create_key(name, key_type=key_type,
                                    exportable=exportable)
        r.raise_for_status()

        r = self.openpgp.read_key(name)
        data = r['data']

        # Public information.
        self.assertIn("fingerprint", data)
        self.assertIn("public_key", data)
        self.assertIn("exportable", data)

        # Private information.
        self.assertNotIn("name", data)
        self.assertNotIn("key", data)

  # https://hvac.readthedocs.io/en/stable/usage/secrets_engines/transit.html#sign-data
  def base64ify(self, bytes_or_str):
      """Helper method to perform base64 encoding across Python 2.7 and Python 3.X"""

      if sys.version_info[0] >= 3 and isinstance(bytes_or_str, str):
          input_bytes = bytes_or_str.encode('utf8')
      else:
          input_bytes = bytes_or_str

      output_bytes = base64.urlsafe_b64encode(input_bytes)
      if sys.version_info[0] >= 3:
          return output_bytes.decode('ascii')
      else:
          return output_bytes

  def test_sign_key(self):

    for key_type in ALLOWED_KEY_TYPES:
      fixed_name = self.random_name()
      fixed_input = 'Hello, world!'
      base64_input = self.base64ify(fixed_input)

      # Sign w/o creating.
      with self.assertRaises(InvalidRequest,
                             msg=f'Nonexistent key: {fixed_name}!'):
        self.openpgp.sign_data(fixed_name, base64_input)

      # Create key.
      self.openpgp.create_key(fixed_name, key_type=key_type)

      # Unsupported parameters.
      unsupported_parameters = (
        {'key_version': 2},
        {'context': ''},
        {'prehashed': True},
      )
      for parameter in unsupported_parameters:
        with self.assertRaises(UnsupportedParam,
                              msg=f'Unsupported parameter: {parameter}!'):
          self.openpgp.sign_data(fixed_name, base64_input, **parameter)

      # Not base64 hash input.
      with self.assertRaises(InvalidRequest, msg='Not base64 hash input!'):
        self.openpgp.sign_data(fixed_name, fixed_input)

      # Default hash, marshaling, and signature algorithms.
      r = self.openpgp.sign_data(fixed_name, base64_input)
      data = r['data']
      self.assertIn("signature", data)

      # All supported hash, marshaling, and signature algorithms.
      for hash_algorithm in ALLOWED_HASH_DATA_ALGORITHMS:
        for marshaling_algorithm in ALLOWED_MARSHALING_ALGORITHMS:
          for signature_algorithm in ALLOWED_SIGNATURE_ALGORITHMS:
            r = self.openpgp.sign_data(fixed_name, base64_input,
                                      hash_algorithm=hash_algorithm,
                                      marshaling_algorithm=marshaling_algorithm,
                                      signature_algorithm=signature_algorithm)
            data = r['data']
            self.assertIn("signature", data)

  def tearDown(self):
    pass

if __name__ == '__main__':
  unittest.main()