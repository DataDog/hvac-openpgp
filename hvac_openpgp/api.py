  #!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Transit-Secrets-Engine-like API module."""

from hvac import exceptions, utils
from hvac.api.secrets_engines.transit import Transit
from .constants import ALLOWED_KEY_TYPES
from .exceptions import UnsupportedParam

DEFAULT_MOUNT_POINT = 'vault-gpg-plugin'

# https://github.com/hvac/hvac/blob/183051f4cf6eeec7c3c813f5f4eb20f01ba611f1/hvac/api/secrets_engines/transit.py
class OpenPGP(Transit):
    """Transit-Secrets-Engine-like (API).
    Reference: https://hvac.readthedocs.io/en/stable/usage/secrets_engines/transit.html
    """

    # TODO: Name, comment, email.
    def create_key(self, name, convergent_encryption=None, derived=None, exportable=None, allow_plaintext_backup=None,
                   key_type=None, real_name=None, email=None, comment=None, mount_point=DEFAULT_MOUNT_POINT):
        """Create a new named encryption key of the specified type.

        The values set here cannot be changed after key creation.

        Supported methods:
            POST: /{mount_point}/keys/{name}. Produces: 204 (empty body)

        :param name: Specifies the name of the encryption key to create. This is specified as part of the URL.
        :type name: str | unicode

        :param convergent_encryption: If enabled, the key will support convergent encryption, where the same plaintext
            creates the same ciphertext. This requires derived to be set to true. When enabled, each
            encryption(/decryption/rewrap/datakey) operation will derive a nonce value rather than randomly generate it.
            Not supported at the time of writing.
        :type convergent_encryption: bool

        :param derived: Specifies if key derivation is to be used. If enabled, all encrypt/decrypt requests to this
            named key must provide a context which is used for key derivation. Not supported at the time of writing.
        :type derived: bool

        :param exportable: Enables keys to be exportable. This allows for all the valid keys in the key ring to be
            exported. Once set, this cannot be disabled.
        :type exportable: bool

        :param allow_plaintext_backup: If set, enables taking backup of named key in the plaintext format. Once set,
            this cannot be disabled.
        :type allow_plaintext_backup: bool

        :param key_type: Specifies the type of key to create. The currently-supported types are:
            * **rsa-2048**: RSA with bit size of 2048 (asymmetric)
            * **rsa-3072**: RSA with bit size of 3072 (asymmetric)
            * **rsa-4096**: RSA with bit size of 4096 (asymmetric)
        :type key_type: str | unicode

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode

        :return: The response of the request.
        :rtype: requests.Response
        """
        # Unsupported parameters.
        if convergent_encryption:
            raise UnsupportedParam('convergent encryption not supported')
        if derived:
            raise UnsupportedParam('key derivation not supported')
        if allow_plaintext_backup:
            raise UnsupportedParam('plaintext key backups not supported')

        # Allowed key types: only particular sizes of RSA.
        if key_type is None or key_type not in ALLOWED_KEY_TYPES:
            error_msg = 'invalid key_type argument provided "{arg}", supported types: "{allowed_types}"'
            raise exceptions.ParamValidationError(error_msg.format(
                arg=key_type,
                allowed_types=', '.join(ALLOWED_KEY_TYPES),
            ))

        # JSON parameters to the plugin.
        # Note: we ignore the key-type, as we assume only RSA keys.
        _, key_bits = key_type.split('-')
        params = utils.remove_nones({
            'comment': comment,
            'email': email,
            'exportable': exportable,
            'generate': True,
            'key_bits': key_bits,
            'name': name,
            'real_name': real_name,
        })

        # The actual call to the plugin.
        api_path = utils.format_url(
            '/v1/{mount_point}/keys/{name}',
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def read_key(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """Read information about a named encryption key.

        The keys object shows the creation time of each key version; the values are not the keys themselves. Depending
        on the type of key, different information may be returned, e.g. an asymmetric key will return its public key in
        a standard format for the type.

        Supported methods:
            GET: /{mount_point}/keys/{name}. Produces: 200 application/json

        :param name: Specifies the name of the encryption key to read. This is specified as part of the URL.
        :type name: str | unicode

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode

        :return: The JSON response of the read_key request.
        :rtype: dict
        """
        api_path = utils.format_url(
            '/v1/{mount_point}/keys/{name}',
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.get(
            url=api_path,
        )

    def list_keys(self, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def delete_key(self, name, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def update_key_configuration(self, name, min_decryption_version=None, min_encryption_version=None, deletion_allowed=None,
                                 exportable=None, allow_plaintext_backup=None, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def rotate_key(self, name, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def export_key(self, name, key_type, version=None, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def encrypt_data(self, name, plaintext, context=None, key_version=None, nonce=None, batch_input=None, type=None,
                     convergent_encryption=None, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def decrypt_data(self, name, ciphertext, context=None, nonce=None, batch_input=None, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def rewrap_data(self, name, ciphertext, context=None, key_version=None, nonce=None, batch_input=None,
                    mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def generate_data_key(self, name, key_type, context=None, nonce=None, bits=None, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def generate_random_bytes(self, n_bytes=None, output_format=None, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def hash_data(self, hash_input, algorithm=None, output_format=None, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def generate_hmac(self, name, hash_input, key_version=None, algorithm=None, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def sign_data(self, name, hash_input, key_version=None, hash_algorithm=None, context=None, prehashed=None,
                  signature_algorithm=None, marshaling_algorithm=None, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def verify_signed_data(self, name, hash_input, signature=None, hmac=None, hash_algorithm=None, context=None,
                           prehashed=None, signature_algorithm=None, marshaling_algorithm=None, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def backup_key(self, name, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def restore_key(self, backup, name=None, force=None, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def trim_key(self, name, min_version, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError
