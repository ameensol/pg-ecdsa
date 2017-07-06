create extension pgcrypto;
create extension pguecc;

--
-- ecdsa_sign_raw
---

-- invalid curve
select ecdsa_sign_raw(E'\\x1234', E'\\x1234', 'baz');

-- invalid key size
select ecdsa_sign_raw(E'\\x1234', E'\\x1234', 'secp256k1');

-- valid key size (output is non-deterministic so just check the length)
select length(ecdsa_sign_raw(E'\\x000000000000000000000000000000000000000000', E'\\x1234', 'secp160r1'));

-- null values
select ecdsa_sign_raw(NULL, '1234', 'secp160r1');
select ecdsa_sign_raw(E'\\x00', NULL, 'secp160r1');
select ecdsa_sign_raw(E'\\x00', '1234', NULL);

--
-- ecdsa_verify_raw
---

-- invalid curve
select ecdsa_verify_raw(E'\\x1234', E'\\x1234', E'\\x1234', 'baz');

-- invalid pubkey
select ecdsa_verify_raw(E'\\x1234', E'\\x1234', E'\\x1234', 'secp256k1');

-- valid signatures (keys generated with OpenSSL)
select ecdsa_verify_raw(
    E'\\xDCB01EA59807D6B8F07E685A9AF369D70554586EF982B35AB2087F3DEABE5065D5130A53175377EB',
    E'\x1234',
    ecdsa_sign_raw(E'\\x0001997CBE1B9E90DAB23322F557E0A2510DA101FA', E'\x1234', 'secp160r1'),
    'secp160r1'
);
