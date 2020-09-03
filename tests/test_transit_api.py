  #!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Transit-Secrets-Engine-like API test module."""

import os
import unittest
import uuid

from hvac.exceptions import (
  InvalidPath,
  InvalidRequest,
  ParamValidationError
)

from hvac_openpgp import Client
from hvac_openpgp.constants import ALLOWED_KEY_TYPES
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

        # Public information.
        data = r['data']
        self.assertIn("fingerprint", data)
        self.assertIn("public_key", data)
        self.assertIn("exportable", data)

        # Private information.
        self.assertNotIn("name", data)
        self.assertNotIn("key", data)

  def tearDown(self):
    pass

if __name__ == '__main__':
  unittest.main()