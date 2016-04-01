Microsecrets, a lightweight secrets manager powered by S3 + KMS
===============================================================

.. image:: https://img.shields.io/pypi/v/microsecrets.svg
    :target: https://pypi.python.org/pypi/microsecrets

**Microsecrets** is a secrets distribution tool powered by Amazon S3 and Amazon
KMS. It provides a bare-bones approach to passing credentials securely in an
Amazon Web Services environment. Credentials are uploaded to S3 and encrypted
at rest by KMS. They can then be passed to programs through environment
variables.

Installation
------------

.. code-block:: bash

    $ pip install microsecrets

Usage
-----

1. Create the S3 bucket you'll use for secrets storage. You may want one bucket
   per organization, such as ``example.com-microsecrets``.

2. Create one KMS master key for each service that will be using microsecrets.
   The key should by default be named ``microsecrets-myservice`` for a service
   called myservice. Users uploading the credentials and systems downloading
   the credentials will need privileges to encrypt/decrypt data using this key.
   None of the normal users need key administration privileges.

3. Upload an environment file. Environment variables may be passed as ``=``
   separated pairs on stdin or in a file. *NB: whitespace is stripped and all
   other characters are treated literally.* Or pass them as a JSON dict with
   the ``--json`` flag.

   .. code-block:: bash

        $ microsecrets-upload -b example-microsecrets -s myservice <<EOM
        DB_URL=db://user:pass@example.com:123
        PASSWORD=hunter2
        EOM

4. Run a program with the credentials in the environment. To verify the
   integrity of data in S3, you must specify the checksum of the environment
   file (output by the upload tool) or whitelist specific environment
   variables. Or, if integrity is not a concern, whitelist all environment
   variables. The whitelist is designed to avoid accidentally allowing code
   execution through ``LD_PRELOAD`` or similar, which may or may not be a
   concern in your system layout.

   .. code-block:: bash

        $ microsecrets-with-env -b example-microsecrets -s myservice -w 'DB_URL PASSWORD' -- /bin/myserver

See also
--------

There is a variety of other recent work in this space that may be of interest:

* Confidant — https://github.com/lyft/confidant
* Sops — https://github.com/mozilla/sops
* Sneaker — https://github.com/codahale/sneaker
* Credstash — https://github.com/fugue/credstash
* Vault — https://github.com/hashicorp/vault
* Keywhiz — https://github.com/square/keywhiz

License
-------

MIT License
