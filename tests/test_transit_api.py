  #!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Transit-Secrets-Engine-like API test module."""

import os
import unittest
import uuid

from hvac.exceptions import (
  InvalidRequest,
  ParamValidationError
)

from hvac_openpgp import Client
from hvac_openpgp.constants import ALLOWED_KEY_TYPES
from hvac_openpgp.exceptions import UnsupportedParam

class TestOpenPGP(unittest.TestCase):

  def setUp(self):
    self.client = Client(os.environ['VAULT_ADDR'], os.environ['VAULT_TOKEN'])
    self.openpgp = self.client.secrets.openpgp

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
      for exportable in (None, False, True):
        for real_name in (None, 'John Doe'):
          for email in (None, 'john.doe@datadoghq.com'):
            r = self.openpgp.create_key(self.random_name(),
                                        key_type=key_type,
                                        exportable=exportable,
                                        real_name=real_name,
                                        email=email)
            r.raise_for_status()

  def test_read_key(self):
    # Create a key.
    for key_type in ALLOWED_KEY_TYPES:
      for exportable in (None, False, True):
        name = self.random_name()
        r = self.openpgp.create_key(name, key_type=key_type,
                                    exportable=exportable)
        r.raise_for_status()
        # Now read it.
        k = self.openpgp.read_key(name)
        print(k)

  def tearDown(self):
    pass

if __name__ == '__main__':
  unittest.main()