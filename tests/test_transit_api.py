  #!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Transit-Secrets-Engine-like API test module."""

import os
import unittest

from hvac.exceptions import ParamValidationError
from hvac_openpgp import Client
from hvac_openpgp.constants import ALLOWED_KEY_TYPES
from hvac_openpgp.exceptions import UnsupportedParam

class TestOpenPGP(unittest.TestCase):

  def setUp(self):
    self.client = Client(os.environ['VAULT_ADDR'], os.environ['VAULT_TOKEN'])
    self.openpgp = self.client.secrets.openpgp

  def test_create_key(self):
    name = 'create-key'

    # Unsupported parameters.
    self.assertRaises(UnsupportedParam, self.openpgp.create_key,
                      name, allow_plaintext_backup=True)
    self.assertRaises(UnsupportedParam, self.openpgp.create_key,
                      name, convergent_encryption=True)
    self.assertRaises(UnsupportedParam, self.openpgp.create_key,
                      name, derived=True)

    # No key type.
    self.assertRaises(ParamValidationError, self.openpgp.create_key, name)

    # Allowed key types, exportable values, real names, and email addresses.
    for key_type in ALLOWED_KEY_TYPES:
      for exportable in (None, False, True):
        for real_name in (None, 'John Doe'):
          for email in (None, 'john.doe@datadoghq.com'):
            r = self.openpgp.create_key(name, key_type=key_type,
                                        exportable=exportable,
                                        real_name=real_name,
                                        email=email)
            r.raise_for_status()

  def test_read_key(self):
    name = 'read-key'

    # Create a key.
    for key_type in ALLOWED_KEY_TYPES:
      for exportable in (None, False, True):
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