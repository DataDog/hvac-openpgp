API
===

How to import and use the library:

.. code-block:: python

    import os
    import hvac_openpgp

    c = hvac_openpgp.Client(os.environ['VAULT_ADDR'],
                            os.environ['VAULT_TOKEN'])
    c.secrets.openpgp.create_key('key-name', key_type='rsa-4096')

Methods
-------

.. automodule:: hvac_openpgp.api
    :members:
