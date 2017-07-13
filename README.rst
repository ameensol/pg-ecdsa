``pguecc`` - Postgres Bindings for the ``micro-ecc`` Elliptic Curve Cryptography library
========================================================================================

``pguecc`` exposes the elliptic curve cryptographic primitives from
`micro-ecc`__ to Postgres.

Note: currently only key generation and signing is supported.

__ https://github.com/kmackay/micro-ecc

Installation
============

Install with::

    $ make install

Note that the Postgres development tools and a C compiler must be installed
(the postgresql-dev or similar package) and the ``pgcrypto`` extension must
be included in the Postgres distribution (it's generally included by default;
if not, the error will mention "could not open extension control file
".../pgcrypto.control").


Usage
=====

Use with::

    > CREATE EXTENSION pgcrypto;
    CREATE EXTENSION;
    > CREATE EXTENSION pguecc;
    CREATE EXTENSION;
    > SELECT ecdsa_sign('000000000000000000000000000000000000000000', '1234', 'sha256', 'secp160r1');
                     ecdsa_sign
    --------------------------------------------
     \xea2eae6ccfee78f0ac8d2d8775e3853f7ac50def
    (1 row)


API
===

Public API
----------

``ecdsa_sign(private_key text|bytea, input_data bytea, hash_func text, curve_name text)``
.........................................................................................

Signs ``hash_func(input_data)``  using ``private_key``.

If ``private_key`` is ``text``, then it's assumed to be a hex string (ie,
``decode(private_key, 'hex')`` is called).

Throws an error if ``curve_name`` is not valid (see ``ecdsa_is_valid_curve(curve_name)``).

Throws an error if ``private_key`` is not valid (see ``ecdsa_is_valid_public_key(public_key)``).

The ``input_data`` are hashed using ``hash_func`` (ex, ``sha1`` or
``sha256``) before being passed to ``ecdsa_sign_raw``.

Equivalent to::

    ecdsa_sign_raw(
        decode(private_key, 'hex'),
        digest(input_data, hash_func),
        curve_name
    )

For example::

    postgres=# select ecdsa_sign('000000000000000000000000000000000000000000', '1234', 'sha256', 'secp160r1');
                                        ecdsa_sign                                    
    ----------------------------------------------------------------------------------
     6d77e8c3bf860f7cbe485a970972d4ae7899af090d81b6e7e14fb547950608ff56cbe2e3f6a38c57
    (1 row)

``ecdsa_verify(public_key text|bytea, input_data bytea, signature text|bytea, hash_func text, curve_name text)``
................................................................................................................

Verifies that ``public_key`` signed ``hash_func(input_data)`` with
``signature`` using ``curve_name``.

If ``public_key`` is ``text`` then it's assumed to be a hex string.

If ``signature`` is ``text`` then it's assumed to be a hex string.

Throws an error if ``curve_name`` is not valid (see ``ecdsa_is_valid_curve(curve_name)``).

Throws an error if ``public_key`` is not valid (see ``ecdsa_is_valid_public_key(public_key)``).

Equivalent to::

    ecdsa_verify_raw(
        decode(public_key, 'hex'),
        digest(input_data, hash_func),
        decode(private_key, 'hex'),
        curve_name
    );

For example::

    postgres=# select ecdsa_verify(
    postgres-#     '696e6d4ab9411031b0b5d4237e6388c910b063c4e87d67acda388b32934446ac6cf41a8fe2a9572543dcefb1469c25fe640790b3926cde705cf2829a5c8d17a7',
    postgres-#     'hello, world',
    postgres-#     'db649d01ce8c8791eca671f95dbf228daeeaf37940148fe0e335511a376f3ca4bad32268ea3cbd069009a8605127003b2c0228d4ec63546d1425454664b25502',
    postgres-#     'sha256',
    postgres-#     'secp256k1'
    postgres-# );
     ecdsa_verify
    --------------
     t
    (1 row)


``ecdsa_is_valid_public_key(public_key text|bytea, curve_name text)``
.....................................................................

Returns ``true`` if ``public_key`` is a valid public key for
``curve_name`` otherwise ``false``.

If ``public_key`` is ``text`` then it's assumed to be a hex string.


``ecdsa_is_valid_private_key(private_key text|bytea, curve_name text)``
.......................................................................

Returns ``true`` if ``private_key`` is a valid private key for
``curve_name`` otherwise ``false``.

If ``private_key`` is ``text`` then it's assumed to be a hex string.


``ecdsa_is_valid_curve(curve_name text)``
.........................................

Returns ``true`` if ``curve_name`` is a valid curve, otherwise ``false``.

Valid curves (as supported by uECC) are: ``'secp160r1'``, ``'secp192r1'``,
``'secp224r1'``, ``'secp256r1'``, and ``'secp256k1'``.


``ecdsa_make_key(curve_name text) -> (public_key_hex text, private_key_hex text)``
----------------------------------------------------------------------------------

Returns a row containing a new public and private key.

For example::

    postgres=# select ecdsa_make_key('secp256k1');
          ecdsa_make_key
    --------------------------
     (0554...8094,ebb...bbc1)
    (1 row)


Raw APIs
--------

These APIs should only be used if you're quite certain that you want to call
the ``ecdsa`` primitives directly without hashing the input data first.

``ecdsa_sign_raw(private_key bytea, hash bytea, curve_name text)``
..................................................................

Signs ``hash`` with ``private_key`` using ``curve_name``.

Throws an error if ``curve_name`` is not valid (see ``ecdsa_is_valid_curve(curve_name)``).

Throws an error if ``private_key`` is not valid (see ``ecdsa_is_valid_public_key(public_key)``).

**Note**: this function should almost certainly never be used directly, as it
signs ``hash`` directly, and there can be cryptographic-security-related
consequences if ``hash`` is not a hashed value. See ``ecdsa_sign``, which
accepts and hashes arbitrary input data before passing it to
``ecdsa_sign_raw``.


``ecdsa_verify_raw(public_key bytea, input_hash bytea, signature bytea, curve_name text)``
..........................................................................................

Verifies that ``public_key`` signed ``input_hash`` with ``signature`` using
``curve_name``.

Throws an error if ``curve_name`` is not valid (see ``ecdsa_is_valid_curve(curve_name)``).

Throws an error if ``public_key`` is not valid (see ``ecdsa_is_valid_public_key(public_key)``).

**Note**: this function should almost certainly never be used directly, as it
verifies ``input_hash`` directly, which is generally only used when
``input_hash`` is a hashed value. See ``ecdsa_verify``, which accepts and
hashes arbitrary data before passing it to ``ecdsa_verify_raw``.

``ecdsa_make_key_raw(curve_name text) -> bytea[2]``
...................................................

Returns an ``ARRAY[public_key, private_key]``.

**Note**: ``ecdsa_make_key`` presents a more friendly interface to this
function.


Cryptographic Security
======================

When necessary, random numbers are generated using ``CryptGenRandom`` on
Windows, and either ``/dev/urandom`` or ``/dev/random`` on Unix. Routines
requiring entropy will fail if these resources are unavailable.

The ``*_raw`` functions should only be used if the caller is fully aware of the
context they are being used in and the potential consequences of passing
arbitrary values directly into ECC signing and unsigning functions. In almost
every case, the non ``_raw`` versions of the functions should be used (the
exception is ``ecdsa_make_key_raw``, which can be used directly if the result
-- a ``bytea[2]`` -- is desired).


Testing
=======

Test with::

    $ make install
    $ make installcheck

Verifying Against OpenSSL
-------------------------

The correctness of signing and unsigning can verified using OpenSSL:

1. Generate a keypair::

    $ openssl ecparam -genkey -name 'secp256k1' -out /tmp/secp256k1-key.pem
    $ openssl ec -in /tmp/secp256k1-key.pem -noout -text
    read EC key
    Private-Key: (256 bit)
    priv:
        4f:47:9f:a3:52:20:3e:63:fa:cb:e0:ba:19:bf:38:
        85:75:c3:f9:b0:65:10:c8:ca:ad:71:32:7a:33:95:
        f7:a9
    pub:
        04:ec:0a:f7:f7:bc:48:eb:0e:e1:fb:84:5d:24:54:
        27:ec:4a:d4:15:c6:d9:51:34:08:a5:98:29:eb:9d:
        9e:ce:46:97:7f:d9:dd:af:4a:fc:f0:d7:d1:13:03:
        d9:1f:4f:ef:04:bf:f0:be:94:72:4f:da:63:86:e1:
        ca:3c:07:75:f3
    ASN1 OID: secp256k1

   Join the 'pub' key together and strip the first byte (``04``) to create the pubkey::

    ec0af7f7bc48eb0ee1fb845d245427ec4ad415c6d9513408a59829eb9d9ece46977fd9ddaf4afcf0d7d11303d91f4fef04bff0be94724fda6386e1ca3c0775f3

   Join the 'priv' key together to create the private key::

    4f479fa352203e63facbe0ba19bf388575c3f9b06510c8caad71327a3395f7a9

2. Sign some data::

    $ echo -n 'hello, world' | openssl dgst -ecdsa-with-SHA1 -sign /tmp/secp256k1-key.pem | openssl asn1parse -inform der
        0:d=0  hl=2 l=  69 cons: SEQUENCE
        2:d=1  hl=2 l=  33 prim: INTEGER           :DFE4353007324D2980F70EC5B437CBAD382EECDDC2B8D891848ACFBDD4797740
       37:d=1  hl=2 l=  32 prim: INTEGER           :359874015A4E559E9520AE5A9544D45174F0A5F6B8FED74ECDA392B096BACDB3

   And concatenate the last two lines to create the signature::

    DFE4353007324D2980F70EC5B437CBAD382EECDDC2B8D891848ACFBDD4797740359874015A4E559E9520AE5A9544D45174F0A5F6B8FED74ECDA392B096BACDB3

3. Verify that the signature is valid::

    $ psql
    postgres=# create extension pguecc;
    postgres=# select ecdsa_verify(
    postgres-#   'ec0af7f7bc48eb0ee1fb845d245427ec4ad415c6d9513408a59829eb9d9ece46977fd9ddaf4afcf0d7d11303d91f4fef04bff0be94724fda6386e1ca3c0775f3', -- the pubkey from step 1
    postgres-#   'hello, world', -- the input from step 2
    postgres-#   'DFE4353007324D2980F70EC5B437CBAD382EECDDC2B8D891848ACFBDD4797740359874015A4E559E9520AE5A9544D45174F0A5F6B8FED74ECDA392B096BACDB3', -- the signature from step 2
    postgres-#   'sha1',
    postgres-#   'secp256k1'
    postgres-# );
     ecdsa_verify
    --------------
     t
    (1 row)

4. Use the private key to sign some data::

    postgres=# select ecdsa_sign(
    postgres-#   '4f479fa352203e63facbe0ba19bf388575c3f9b06510c8caad71327a3395f7a9', -- the private key from step 1
    postgres-#   'hello, world',
    postgres-#   'sha1',
    postgres-#   'secp256k1'
    postgres-# );
                                                                ecdsa_sign
    ----------------------------------------------------------------------------------------------------------------------------------
     12412067a8dc2cf87586e7d31e91de828eb3f4281b4c04982cd4c906ea7c06693a53a9369d51207328cf0c20863bec259561103e89310f2d48bcaf12550e560b
    (1 row)

5. Encode the signature in DER format and save it to a file::

    $ echo -n 'hello, world' > /tmp/to-verify.txt
    $ sig='12412067a8dc2cf87586e7d31e91de828eb3f4281b4c04982cd4c906ea7c06693a53a9369d51207328cf0c20863bec259561103e89310f2d48bcaf12550e560b'
    $ halfsiglen=$(( ${#sig} / 2 ))
    $ r="${sig:0:$halfsiglen}"
    $ s="${sig:$halfsiglen}"
    $ totlen="$(printf "%x" $(( 2 + 2 + $halfsiglen )))"
    $ partlen="$(printf "%x" $(( $halfsiglen / 2 )))"
    $ echo -n "30${totlen}02${partlen}${r}02${partlen}${s}" | xxd -r -p > /tmp/signature.bin
    $ # Verify the DER encoding
    $ openssl asn1parse -inform der -in /tmp/signature.bin
        0:d=0  hl=2 l=  68 cons: SEQUENCE
        2:d=1  hl=2 l=  32 prim: INTEGER           :12412067A8DC2CF87586E7D31E91DE828EB3F4281B4C04982CD4C906EA7C0669
       37:d=1  hl=2 l=  32 prim: INTEGER           :3A53A9369D51207328CF0C20863BEC259561103E89310F2D48BCAF12550E560B

   (Note: because this is very poor-man's-DER-encoding, 3/4 of the time one of
   the two INTEGER numbers will be negative and the signature will fail to
   verify. The correct solution is to prefix the byte string with ``00`` if the
   first byte is ``>= 0xF7``; see: https://crypto.stackexchange.com/a/1797)

6. Save the public key to a file::

    $ openssl ec -in /tmp/secp256k1-key.pem -pubout -out /tmp/secp256k1-pub.pem

7. Verify the signature::

    $ openssl dgst -ecdsa-with-SHA1 -verify /tmp/secp256k1-pub.pem -signature /tmp/signature.bin /tmp/to-verify.txt
    Verified OK

Author
======

Authored by David Wolever: https://github.com/wolever / https://twitter.com/wolever
