create extension pgcrypto;
create extension pguecc;

-- sensible input types
select length(ecdsa_sign('000000000000000000000000000000000000000000', '1234', 'sha256', 'secp160r1'));
select length(ecdsa_sign('000000000000000000000000000000000000000000', '1234'::text, 'sha256', 'secp160r1'));
select length(ecdsa_sign('000000000000000000000000000000000000000000', '1234'::bytea, 'sha256', 'secp160r1'));

-- error on invalid hash function
select length(ecdsa_sign('000000000000000000000000000000000000000000', '1234', 'bad', 'secp160r1'));

-- ecdsa_is_valid_public_key
select ecdsa_is_valid_public_key(E'\\xDCB01EA59807D6B8F07E685A9AF369D70554586EF982B35AB2087F3DEABE5065D5130A53175377EB'::bytea, 'secp160r1');
select ecdsa_is_valid_public_key('DCB01EA59807D6B8F07E685A9AF369D70554586EF982B35AB2087F3DEABE5065D5130A53175377EB', 'secp160r1');
select ecdsa_is_valid_public_key('1234', 'secp160r1');
select ecdsa_is_valid_public_key('00000000000000000000000000000000000000000000000000000000000000000000000000000000', 'secp160r1');

-- ecdsa_is_valid_private_key
select ecdsa_is_valid_private_key(E'\\x0001997CBE1B9E90DAB23322F557E0A2510DA101FA'::bytea, 'secp160r1');
select ecdsa_is_valid_private_key(E'\\x000000000000000000000000000000000000000001'::bytea, 'secp160r1');
select ecdsa_is_valid_private_key('000000000000000000000000000000000000000001', 'secp160r1');
select ecdsa_is_valid_private_key('1234', 'secp160r1');
select ecdsa_is_valid_private_key('000000000000000000000000000000000000000000', 'secp160r1');

-- ecdsa_is_valid_curve
select ecdsa_is_valid_curve('secp256k1');
select ecdsa_is_valid_curve('invalid-curve');

-- ecdsa_make_key
select length((ecdsa_make_key('secp160r1')).public_key);
select ecdsa_is_valid_public_key((ecdsa_make_key('secp160r1')).public_key, 'secp160r1');

select length((ecdsa_make_key('secp160r1')).private_key);
select ecdsa_is_valid_private_key((ecdsa_make_key('secp160r1')).public_key, 'secp160r1');

with key as (select * from ecdsa_make_key('secp160r1'))
select
    ecdsa_verify(
        key.public_key, 'hello, world',
        ecdsa_sign(key.private_key, 'hello, world', 'sha256', 'secp160r1'),
        'sha256', 'secp160r1'
    )
from key;

with key as (select * from ecdsa_make_key('secp256k1'))
select
    ecdsa_verify(
        key.public_key, 'hello, world',
        ecdsa_sign(key.private_key, 'hello, world', 'sha256', 'secp256k1'),
        'sha256', 'secp256k1'
    )
from key;
