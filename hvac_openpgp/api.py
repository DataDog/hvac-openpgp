  #!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Transit-Secrets-Engine-like API module."""

from hvac.api.secrets_engines.transit import Transit
from hvac.exceptions import ParamValidationError
from hvac.utils import (
    format_url,
    remove_nones,
)

from .constants import (
    ALLOWED_EXPORT_KEY_TYPES,
    ALLOWED_HASH_DATA_ALGORITHMS,
    ALLOWED_KEY_TYPES,
    ALLOWED_MARSHALING_ALGORITHMS,
    ALLOWED_SIGNATURE_ALGORITHMS,
)
from .exceptions import UnsupportedParam

DEFAULT_MOUNT_POINT = 'vault-gpg-plugin'

# https://github.com/hvac/hvac/blob/183051f4cf6eeec7c3c813f5f4eb20f01ba611f1/hvac/api/secrets_engines/transit.py
class OpenPGP(Transit):
    """Transit-Secrets-Engine-like (API).
    Reference: https://hvac.readthedocs.io/en/stable/usage/secrets_engines/transit.html
    """

    def create_key(self, name, convergent_encryption=None, derived=None, exportable=None, allow_plaintext_backup=None,
                   key_type='rsa-4096', real_name=None, email=None, comment=None, expires=365*24*60*60,
                   mount_point=DEFAULT_MOUNT_POINT):
        """Create a new named encryption key of the specified type.

        The values set here cannot be changed after key creation.

        Supported methods:
            POST: /{mount_point}/keys/{name}. Produces: 204 (empty body)

        :param name: Specifies the name of the encryption key to create. This is specified as part of the URL.
        :type name: str | unicode

        :param email: Specifies the email of the identity associated with the generated GPG key.
        :type email: str | unicode

        :param comment: Specifies the comment of the identity associated with the generated GPG key.
        :type comment: str | unicode

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

        :param expires: Specifies the number of seconds from the creation time (now) after which the master key and encryption subkey expire. If the number is zero, then they never expire.
        :type expires: int

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode

        :return: The response of the request.
        :rtype: requests.Response
        """

        # Unsupported parameters.
        if convergent_encryption is not None:
            raise UnsupportedParam('convergent encryption not supported')
        if derived is not None:
            raise UnsupportedParam('key derivation not supported')
        if allow_plaintext_backup is not None:
            raise UnsupportedParam('plaintext key backups not supported')

        # Allowed key types: only particular sizes of RSA.
        if key_type is None or key_type not in ALLOWED_KEY_TYPES:
            error_msg = 'invalid key_type argument provided "{arg}", supported types: "{allowed_types}"'
            raise ParamValidationError(error_msg.format(
                arg=key_type,
                allowed_types=', '.join(ALLOWED_KEY_TYPES),
            ))

        # JSON parameters to the plugin.
        # Note: we ignore the key-type, as we assume only RSA keys.
        _, key_bits = key_type.split('-')
        params = remove_nones({
            'comment': comment,
            'email': email,
            'expires': expires,
            'exportable': exportable,
            'generate': True,
            'key_bits': key_bits,
            'name': name,
            'real_name': real_name,
        })

        # The actual call to the plugin.
        api_path = format_url(
            '/v1/{mount_point}/keys/{name}',
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def create_subkey(self, name, key_type='rsa-4096', capabilities=['sign'], expires=365*24*60*60,
                      mount_point=DEFAULT_MOUNT_POINT):
        """Create a new subkey of the specified type under the specified master key.

        The values set here cannot be changed after subkey creation.

        Supported methods:
            POST: /{mount_point}/keys/{name}/subkeys. Produces: 204 (empty body)

        :param name: Specifies the name of the master key with which to associate the new subkey. This is specified as part of the URL.
        :type name: str | unicode

        :param key_type: Specifies the type of the subkey to create. The currently-supported types are:

            * **rsa-2048**: RSA with bit size of 2048 (asymmetric)
            * **rsa-3072**: RSA with bit size of 3072 (asymmetric)
            * **rsa-4096**: RSA with bit size of 4096 (asymmetric)
        :type key_type: str | unicode

        :param capabilities: Specifies the capabilities of the subkey.
            Currently-supported capabilities are: sign
        :type capabilities: list[str] | list[unicode]

        :param expires: Specifies the number of seconds from the creation time (now) after which the subkey expires. If the number is zero, then the subkey never expires.
        :type expires: int

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode

        :return: The response of the request.
        :rtype: requests.Response
        """

        # Allowed key types: only particular sizes of RSA.
        if key_type is None or key_type not in ALLOWED_KEY_TYPES:
            error_msg = 'invalid key_type argument provided "{arg}", supported types: "{allowed_types}"'
            raise ParamValidationError(error_msg.format(
                arg=key_type,
                allowed_types=', '.join(ALLOWED_KEY_TYPES),
            ))

        # JSON parameters to the plugin.
        # Note: we ignore the key-type, as we assume only RSA keys.
        key_type, key_bits = key_type.split('-')
        params = remove_nones({
            'name': name,
            'key_type': key_type,
            'key_bits': key_bits,
            'capabilities': capabilities,
            'expires': expires,
        })

        # The actual call to the plugin.
        api_path = format_url(
            '/v1/{mount_point}/keys/{name}/subkeys',
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

        # The actual call to the plugin.
        api_path = format_url(
            '/v1/{mount_point}/keys/{name}',
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.get(
            url=api_path,
        )

    def read_subkey(self, name, key_id, mount_point=DEFAULT_MOUNT_POINT):
        """Read information, such as the key type, capabilities, and size, about the given subkey associated with the
        given master key.

        Supported methods:
            GET: /{mount_point}/keys/{name}/subkeys/{key_id}. Produces: 200 application/json

        :param name: Specifies the name of the master key with which the subkey is associated. This is specified as part of the URL.
        :type name: str | unicode

        :param key_id: Specifies Specifies the Key ID of the subkey. This is specified as part of the URL.
        :type key_id: str | unicode

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode

        :return: The JSON response of the read_subkey request.
        :rtype: dict
        """

        # The actual call to the plugin.
        api_path = format_url(
            '/v1/{mount_point}/keys/{name}/subkeys/{key_id}',
            mount_point=mount_point,
            name=name,
            key_id=key_id,
        )
        return self._adapter.get(
            url=api_path,
        )

    def list_keys(self, mount_point=DEFAULT_MOUNT_POINT):
        """List keys (if there are any).

        Only the key names are returned (not the actual keys themselves).
        An exception is thrown if there are no keys.

        Supported methods:
            LIST: /{mount_point}/keys. Produces: 200 application/json

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode

        :return: The JSON response of the request.
        :rtype: dict
        """

        # The actual call to the plugin.
        api_path = format_url('/v1/{mount_point}/keys', mount_point=mount_point)
        return self._adapter.list(
            url=api_path
        )

    def list_subkeys(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """List subkeys (if there are any) associated with the GPG master key with the given name.

        Only Key IDs of public keys of subkeys are returned.

        Supported methods:
            LIST: /{mount_point}/keys/{name}/subkeys. Produces: 200 application/json

        :param name: Specifies the name of the master key with which the subkey is associated. This is specified as part of the URL.
        :type name: str | unicode

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode

        :return: The JSON response of the request.
        :rtype: dict
        """

        # The actual call to the plugin.
        api_path = format_url(
            '/v1/{mount_point}/keys/{name}/subkeys',
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.list(
            url=api_path
        )

    def delete_key(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """Delete a named encryption key.

        It will no longer be possible to decrypt any data encrypted with the named key. Because this is a potentially
        catastrophic operation, the deletion_allowed tunable must be set in the key's /config endpoint.
        Not supported at the time of writing; use Vault policies instead to control who can delete which keys.

        Supported methods:
            DELETE: /{mount_point}/keys/{name}. Produces: 204 (empty body)

        :param name: Specifies the name of the encryption key to delete. This is specified as part of the URL.
        :type name: str | unicode

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode

        :return: The response of the request.
        :rtype: requests.Response
        """

        # JSON parameters to the plugin.
        api_path = format_url(
            '/v1/{mount_point}/keys/{name}',
            mount_point=mount_point,
            name=name,
        )

        # The actual call to the plugin.
        return self._adapter.delete(
            url=api_path,
        )

    def delete_subkey(self, name, key_id, mount_point=DEFAULT_MOUNT_POINT):
        """Delete the given subkey associated with the given master key.

        Because this is a potentially catastrophic operation, use Vault policies instead to control who can
        delete which keys.

        Supported methods:
            DELETE: /{mount_point}/keys/{name}/subkeys/{key_id}. Produces: 204 (empty body)

        :param name: Specifies the name of the master key with which the subkey is associated. This is specified as part of the URL.
        :type name: str | unicode

        :param key_id: Specifies Specifies the Key ID of the subkey. This is specified as part of the URL.
        :type key_id: str | unicode

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode

        :return: The response of the request.
        :rtype: requests.Response
        """

        # JSON parameters to the plugin.
        api_path = format_url(
            '/v1/{mount_point}/keys/{name}/subkeys/{key_id}',
            mount_point=mount_point,
            name=name,
            key_id=key_id,
        )

        # The actual call to the plugin.
        return self._adapter.delete(
            url=api_path,
        )

    def update_key_configuration(self, name, min_decryption_version=None, min_encryption_version=None, deletion_allowed=None,
                                 exportable=None, allow_plaintext_backup=None, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def rotate_key(self, name, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def export_key(self, name, key_type=None, version=None, mount_point=DEFAULT_MOUNT_POINT):
        """Return the named key.

        The keys object shows the value of the key for each version. If version is specified, the specific version will
        be returned. If latest is provided as the version, the current key will be provided. Depending on the type of
        key, different information may be returned. The key must be exportable to support this operation and the version
        must still be valid.

        Supported methods:
            GET: /{mount_point}/export/{key_type}/{name}(/{version}). Produces: 200 application/json

        :param name: Specifies the name of the key to read information about. This is specified as part of the URL.
        :type name: str | unicode

        :param key_type: Specifies the type of the key to export. This is specified as part of the URL. Valid values are:
            encryption-key
            signing-key
        Validated but ignored at the time of writing, so it has no effect.
        :type key_type: str | unicode

        :param version: Specifies the version of the key to read. If omitted, all versions of the key will be returned.
            If the version is set to latest, the current key will be returned. Not supported at the time of writing.
        :type version: str | unicode

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode

        :return: The JSON response of the request.
        :rtype: dict
        """

        # Unsupported parameters.
        if version is not None:
            raise UnsupportedParam('key versions not supported')

        # Validated but ignored for now.
        if key_type is not None and key_type not in ALLOWED_EXPORT_KEY_TYPES:
            error_msg = 'invalid key_type argument provided "{arg}", supported types: "{allowed_types}"'
            raise ParamValidationError(error_msg.format(
                arg=key_type,
                allowed_types=', '.join(ALLOWED_EXPORT_KEY_TYPES),
            ))

        # JSON parameters to the plugin.
        # NOTE: {key_type} is NOT part of the URL, unlike with Transit Secrets Engine.
        api_path = format_url(
            '/v1/{mount_point}/export/{name}',
            mount_point=mount_point,
            key_type=key_type,
            name=name,
        )

        # The actual call to the plugin.
        if version is not None:
            api_path = self._adapter.urljoin(api_path, version)
        return self._adapter.get(
            url=api_path,
        )

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

    def sign_data(self, name, hash_input, key_version=None, hash_algorithm='sha2-512', context=None, prehashed=None,
                  signature_algorithm=None, marshaling_algorithm='ascii-armor', expires=365*24*60*60,
                  mount_point=DEFAULT_MOUNT_POINT):
        """Return the cryptographic signature of the given data using the named key and the specified hash algorithm.

        The key must be of a type that supports signing. Either the first available signing subkey, or the master
        key (which should support signing), is chosen.

        Supported methods:
            POST: /{mount_point}/sign/{name}(/{hash_algorithm}). Produces: 200 application/json

        :param name: Specifies the name of the encryption key to use for signing. This is specified as part of the URL.
        :type name: str | unicode

        :param hash_input: Specifies the base64 encoded input data.
        :type hash_input: str | unicode

        :param key_version: Specifies the version of the key to use for signing. If not set, uses the latest version.
            Must be greater than or equal to the key's min_encryption_version, if set.
            Not supported at the time of writing.
        :type key_version: int

        :param hash_algorithm: Specifies the hash algorithm to use for supporting key types (notably, not including
            ed25519 which specifies its own hash algorithm). This can also be specified as part of the URL.
            Currently-supported algorithms are: sha2-224, sha2-256, sha2-384, sha2-512
        :type hash_algorithm: str | unicode

        :param context: Base64 encoded context for key derivation. Required if key derivation is enabled; currently only
            available with ed25519 keys. Not supported at the time of writing.
        :type context: str | unicode

        :param prehashed: Set to true when the input is already hashed. If the key type is rsa-2048 or rsa-4096, then
            the algorithm used to hash the input should be indicated by the hash_algorithm parameter. Just as the value
            to sign should be the base64-encoded representation of the exact binary data you want signed, when set, input
            is expected to be base64-encoded binary hashed data, not hex-formatted. (As an example, on the command line,
            you could generate a suitable input via openssl dgst -sha256 -binary | base64.)
            Not supported at the time of writing.
        :type prehashed: bool

        :param signature_algorithm: When using a RSA key, specifies the RSA signature algorithm to use for signing.
            Supported signature types are: pkcs1v15
        :type signature_algorithm: str | unicode

        :param marshaling_algorithm: Specifies the way in which the signature should be marshaled.
            Supported types are: ascii-armor, base64
        :type marshaling_algorithm: str | unicode

        :param expires: Specifies the number of seconds from the creation time (now) after which the signature expires.
        If the number is zero, then the signature never expires. By default, signatures expire in a year.
        :type expires: int

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode

        :return: The JSON response of the request.
        :rtype: dict
        """

        # Unsupported parameters.
        if key_version is not None:
            raise UnsupportedParam('key versions not supported')
        if context is not None:
            raise UnsupportedParam('context for key derivation not supported')
        if prehashed is not None:
            raise UnsupportedParam('prehashed input not supported')

        if hash_algorithm is not None and hash_algorithm not in ALLOWED_HASH_DATA_ALGORITHMS:
            error_msg = 'invalid hash_algorithm argument provided "{arg}", supported types: "{allowed_types}"'
            raise ParamValidationError(error_msg.format(
                arg=hash_algorithm,
                allowed_types=', '.join(ALLOWED_HASH_DATA_ALGORITHMS),
            ))

        # Validated but ignored for now.
        if signature_algorithm is not None and signature_algorithm not in ALLOWED_SIGNATURE_ALGORITHMS:
            error_msg = 'invalid signature_algorithm argument provided "{arg}", supported types: "{allowed_types}"'
            raise ParamValidationError(error_msg.format(
                arg=signature_algorithm,
                allowed_types=', '.join(ALLOWED_SIGNATURE_ALGORITHMS),
            ))

        if marshaling_algorithm is not None and marshaling_algorithm not in ALLOWED_MARSHALING_ALGORITHMS:
            error_msg = 'invalid marshaling_algorithm argument provided "{arg}", supported types: "{allowed_types}"'
            raise ParamValidationError(error_msg.format(
                arg=marshaling_algorithm,
                allowed_types=', '.join(ALLOWED_MARSHALING_ALGORITHMS),
            ))

        # JSON parameters to the plugin.
        params = {
            'input': hash_input,
        }
        params.update(
            remove_nones({
                'algorithm': hash_algorithm,
                'format': marshaling_algorithm,
                'expires': expires,
            })
        )

        # The actual call to the plugin.
        api_path = format_url(
            '/v1/{mount_point}/sign/{name}',
            mount_point=mount_point,
            name=name,
        )
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def verify_signed_data(self, name, hash_input, signature=None, hmac=None, hash_algorithm=None, context=None,
                           prehashed=None, signature_algorithm=None, marshaling_algorithm='ascii-armor',
                           mount_point=DEFAULT_MOUNT_POINT):
        """Return whether the provided signature is valid for the given data.

        Supported methods:
            POST: /{mount_point}/verify/{name}(/{hash_algorithm}). Produces: 200 application/json

        :param name: Specifies the name of the encryption key that was used to generate the signature or HMAC.
        :type name: str | unicode

        :param hash_input: Specifies the base64 encoded input data.
        :type input: str | unicode

        :param signature: Specifies the signature output from the /transit/sign function. Either this must be supplied
            or hmac must be supplied.
        :type signature: str | unicode

        :param hmac: Specifies the signature output from the /transit/hmac function. Either this must be supplied or
            signature must be supplied.
        :type hmac: str | unicode

        :param hash_algorithm: Specifies the hash algorithm to use. This can also be specified as part of the URL.
            Currently-supported algorithms are: sha2-224, sha2-256, sha2-384, sha2-512
        :type hash_algorithm: str | unicode

        :param context: Base64 encoded context for key derivation. Required if key derivation is enabled; currently only
            available with ed25519 keys.
        :type context: str | unicode

        :param prehashed: Set to true when the input is already hashed. If the key type is rsa-2048 or rsa-4096, then
            the algorithm used to hash the input should be indicated by the hash_algorithm parameter.
        :type prehashed: bool

        :param signature_algorithm: When using a RSA key, specifies the RSA signature algorithm to use for signature
            verification. Supported signature types are: pss, pkcs1v15
        :type signature_algorithm: str | unicode

        :param marshaling_algorithm: Specifies the way in which the signature should be marshaled. This currently only applies to ECDSA keys.
            Supported types are: asn1, jws
        :type marshaling_algorithm: str | unicode

        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode

        :return: The JSON response of the request.
        :rtype: dict
        """

        # Unsupported parameters.
        if hmac is not None:
            raise UnsupportedParam('hmac not supported')
        if context is not None:
            raise UnsupportedParam('context for key derivation not supported')
        if prehashed is not None:
            raise UnsupportedParam('prehashed input not supported')

        if signature is None:
            error_msg = '"signature" must be provided to verify signature'
            raise ParamValidationError(error_msg)

        # Validated but ignored for now.
        if hash_algorithm is not None and hash_algorithm not in ALLOWED_HASH_DATA_ALGORITHMS:
            error_msg = 'invalid hash_algorithm argument provided "{arg}", supported types: "{allowed_types}"'
            raise ParamValidationError(error_msg.format(
                arg=hash_algorithm,
                allowed_types=', '.join(ALLOWED_HASH_DATA_ALGORITHMS),
            ))

        # Validated but ignored for now.
        if signature_algorithm is not None and signature_algorithm not in ALLOWED_SIGNATURE_ALGORITHMS:
            error_msg = 'invalid signature_algorithm argument provided "{arg}", supported types: "{allowed_types}"'
            raise ParamValidationError(error_msg.format(
                arg=signature_algorithm,
                allowed_types=', '.join(ALLOWED_SIGNATURE_ALGORITHMS),
            ))

        if marshaling_algorithm is not None and marshaling_algorithm not in ALLOWED_MARSHALING_ALGORITHMS:
            error_msg = 'invalid marshaling_algorithm argument provided "{arg}", supported types: "{allowed_types}"'
            raise ParamValidationError(error_msg.format(
                arg=marshaling_algorithm,
                allowed_types=', '.join(ALLOWED_MARSHALING_ALGORITHMS),
            ))

        # JSON parameters to the plugin.
        params = {
            'name': name,
            'input': hash_input,
        }
        params.update(
            remove_nones({
                'format': marshaling_algorithm,
                'signature': signature,
            })
        )

        # The actual call to the plugin.
        api_path = format_url('/v1/{mount_point}/verify/{name}', mount_point=mount_point, name=name)
        return self._adapter.post(
            url=api_path,
            json=params,
        )

    def backup_key(self, name, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def restore_key(self, backup, name=None, force=None, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError

    def trim_key(self, name, min_version, mount_point=DEFAULT_MOUNT_POINT):
        raise NotImplementedError
