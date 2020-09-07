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

  def test_1_list_keys(self):
    # List keys when there are none.
    # TODO: Should this raise an exception in the first place?
    with self.assertRaises(InvalidPath, msg='Listed keys when there are none!'):
      self.openpgp.list_keys()

    # Create and list keys.
    keys = []
    for key_type in ALLOWED_KEY_TYPES:
      name = self.random_name()
      self.openpgp.create_key(name, key_type=key_type)
      keys.append(name)

    r = self.openpgp.list_keys()
    assert sorted(r['data']['keys']) == sorted(keys)

  def test_2_read_key(self):
      # Read non-existent key.
      # TODO: Should this raise an exception in the first place?
      with self.assertRaises(InvalidPath, msg='Read non-existent key!'):
        self.openpgp.read_key(self.random_name())

  def test_3_create_read_and_delete_key(self):
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

    # Allowed key types, exportable values, real names, and email addresses.
    for key_type in ALLOWED_KEY_TYPES:
      for exportable in self.EXPORTABLE:
        for real_name in (None, 'John Doe'):
          for email in (None, 'john.doe@datadoghq.com'):
            fixed_name = self.random_name()
            r = self.openpgp.create_key(fixed_name,
                                        key_type=key_type,
                                        exportable=exportable,
                                        real_name=real_name,
                                        email=email)
            r.raise_for_status()

            r = self.openpgp.read_key(fixed_name)
            data = r['data']

            # Public information.
            self.assertIn('fingerprint', data)
            self.assertIn('public_key', data)
            self.assertIn('exportable', data)

            # Private information.
            self.assertNotIn('name', data)
            self.assertNotIn('key', data)

            # Delete.
            r = self.openpgp.delete_key(fixed_name)
            r.raise_for_status()

    # Duplicate keys.
    for key_type in ALLOWED_KEY_TYPES:
      fixed_name = self.random_name()
      self.openpgp.create_key(fixed_name, key_type=key_type)
      # https://github.com/LeSuisse/vault-gpg-plugin/pull/51
      with self.assertRaises(InvalidRequest, msg='Duplicate key created!'):
        self.openpgp.create_key(fixed_name, key_type=key_type)

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

  def test_4_sign_and_verify_data(self):
    for key_type in ALLOWED_KEY_TYPES:
      fixed_name = self.random_name()
      fixed_input = 'Hello, world!'
      base64_input = self.base64ify(fixed_input)
      base64_bad_input = self.base64ify(fixed_input+'!!')

      # Sign w/o creating.
      with self.assertRaises(InvalidRequest,
                             msg=f'Nonexistent key: {fixed_name}!'):
        self.openpgp.sign_data(fixed_name, base64_input)

      # Verify w/o creating.
      with self.assertRaises(InvalidRequest,
                             msg=f'Nonexistent key: {fixed_name}!'):
        self.openpgp.verify_signed_data(fixed_name, base64_input, signature='')

      # Create key.
      self.openpgp.create_key(fixed_name, key_type=key_type)

      # Unsupported parameters for signing.
      unsupported_parameters = (
        {'key_version': 2},
        {'context': ''},
        {'prehashed': True},
      )
      for parameter in unsupported_parameters:
        with self.assertRaises(UnsupportedParam,
                              msg=f'Unsupported parameter: {parameter}!'):
          self.openpgp.sign_data(fixed_name, base64_input, **parameter)

      # Unsupported parameters for verification.
      unsupported_parameters = (
        {'context': ''},
        {'hmac': ''},
        {'prehashed': True},
      )
      for parameter in unsupported_parameters:
        with self.assertRaises(UnsupportedParam,
                              msg=f'Unsupported parameter: {parameter}!'):
          self.openpgp.verify_signed_data(fixed_name, base64_input,
                                          signature='', **parameter)

      # Not base64 hash input for signing.
      with self.assertRaises(InvalidRequest, msg='Not base64 hash input!'):
        self.openpgp.sign_data(fixed_name, fixed_input)

      # Not base64 hash input for verification.
      with self.assertRaises(InvalidRequest, msg='Not base64 hash input!'):
        self.openpgp.verify_signed_data(fixed_name, fixed_input, signature='')

      # All supported as well as default hash, marshaling, and signature algorithms.
      for hash_algorithm in ALLOWED_HASH_DATA_ALGORITHMS | {None}:
        for marshaling_algorithm in ALLOWED_MARSHALING_ALGORITHMS | {None}:
          for signature_algorithm in ALLOWED_SIGNATURE_ALGORITHMS | {None}:
            # Make a signature.
            r = self.openpgp.sign_data(fixed_name, base64_input,
                                       hash_algorithm=hash_algorithm,
                                       marshaling_algorithm=marshaling_algorithm,
                                       signature_algorithm=signature_algorithm)
            signature = r['data']['signature']

            # Forget to pass signature for verification.
            with self.assertRaises(ParamValidationError, msg='No "signature"!'):
              self.openpgp.verify_signed_data(fixed_name, base64_input,
                                                hash_algorithm=hash_algorithm,
                                                marshaling_algorithm=marshaling_algorithm,
                                                signature_algorithm=signature_algorithm)

            # Original input.
            r = self.openpgp.verify_signed_data(fixed_name, base64_input,
                                                hash_algorithm=hash_algorithm,
                                                marshaling_algorithm=marshaling_algorithm,
                                                signature=signature,
                                                signature_algorithm=signature_algorithm)
            self.assertTrue(r['data']['valid'])

            # Bad input.
            r = self.openpgp.verify_signed_data(fixed_name, base64_bad_input,
                                                hash_algorithm=hash_algorithm,
                                                marshaling_algorithm=marshaling_algorithm,
                                                signature=signature,
                                                signature_algorithm=signature_algorithm)
            self.assertFalse(r['data']['valid'])

            # Bad signature.
            mid_len = len(signature) // 2
            bad_signature = signature[:mid_len] + '!!' + signature[mid_len:]
            r = self.openpgp.verify_signed_data(fixed_name, base64_input,
                                                hash_algorithm=hash_algorithm,
                                                marshaling_algorithm=marshaling_algorithm,
                                                signature=bad_signature,
                                                signature_algorithm=signature_algorithm)
            self.assertFalse(r['data']['valid'])

  def test_5_delete_key(self):
      # Deleting a non-existent key does not raise an exception.
      # TODO: inconsistent behaviour compared to list/read keys.
      r = self.openpgp.delete_key(self.random_name())
      r.raise_for_status()

  def tearDown(self):
    pass

if __name__ == '__main__':
  unittest.main()