\echo Use "CREATE EXTENSION pgcrypto" to load this file. \quit


--
-- ecdsa_sign
--

CREATE FUNCTION ecdsa_sign_raw(bytea, bytea, text)
RETURNS bytea
AS 'MODULE_PATHNAME', 'pg_ecdsa_sign_raw'
LANGUAGE C STRICT;

CREATE FUNCTION ecdsa_sign(private_key_hex text, input_data bytea, hash_func text, curve_name text) RETURNS text AS $$
    SELECT encode(ecdsa_sign_raw(
        decode(private_key_hex, 'hex'),
        digest(input_data, hash_func),
        curve_name
    ), 'hex');
$$ LANGUAGE SQL STRICT;

CREATE FUNCTION ecdsa_sign(private_key bytea, input_data bytea, hash_func text, curve_name text) RETURNS text AS $$
    SELECT encode(ecdsa_sign_raw(
        private_key,
        digest(input_data, hash_func),
        curve_name
    ), 'hex');
$$ LANGUAGE SQL STRICT;


--
-- ecdsa_verify
--

CREATE FUNCTION ecdsa_verify_raw(bytea, bytea, bytea, text)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_ecdsa_verify_raw'
LANGUAGE C STRICT;

CREATE FUNCTION ecdsa_verify(public_key_hex text, input_data bytea, signature_hex text, hash_func text, curve_name text) RETURNS boolean AS $$
    SELECT ecdsa_verify_raw(
        decode(public_key_hex, 'hex'),
        digest(input_data, hash_func),
        decode(signature_hex, 'hex'),
        curve_name
    );
$$ LANGUAGE SQL STRICT;

CREATE FUNCTION ecdsa_verify(public_key_hex text, input_data bytea, signature bytea, hash_func text, curve_name text) RETURNS boolean AS $$
    SELECT ecdsa_verify_raw(
        decode(public_key_hex, 'hex'),
        digest(input_data, hash_func),
        signature,
        curve_name
    );
$$ LANGUAGE SQL STRICT;

CREATE FUNCTION ecdsa_verify(public_key bytea, input_data bytea, signature_hex text, hash_func text, curve_name text) RETURNS boolean AS $$
    SELECT ecdsa_verify_raw(
        public_key,
        digest(input_data, hash_func),
        decode(signature_hex, 'hex'),
        curve_name
    );
$$ LANGUAGE SQL STRICT;

CREATE FUNCTION ecdsa_verify(public_key bytea, input_data bytea, signature bytea, hash_func text, curve_name text) RETURNS boolean AS $$
    SELECT ecdsa_verify_raw(
        public_key,
        digest(input_data, hash_func),
        signature,
        curve_name
    );
$$ LANGUAGE SQL STRICT;

--
-- ecdsa_is_valid_public_key
--

CREATE FUNCTION ecdsa_is_valid_public_key(bytea, text)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_ecdsa_is_valid_public_key'
LANGUAGE C STRICT;

CREATE FUNCTION ecdsa_is_valid_public_key(public_key_hex text, curve_name text) RETURNS boolean AS $$
    SELECT ecdsa_is_valid_public_key(
        decode(public_key_hex, 'hex'),
        curve_name
    );
$$ LANGUAGE SQL STRICT;


--
-- ecdsa_is_valid_private_key
--

CREATE FUNCTION ecdsa_is_valid_private_key(bytea, text)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_ecdsa_is_valid_private_key'
LANGUAGE C STRICT;

CREATE FUNCTION ecdsa_is_valid_private_key(private_key_hex text, curve_name text) RETURNS boolean AS $$
    SELECT ecdsa_is_valid_private_key(
        decode(private_key_hex, 'hex'),
        curve_name
    );
$$ LANGUAGE SQL STRICT;


--
-- ecdsa_is_valid_public_key
--

CREATE FUNCTION ecdsa_is_valid_curve(text)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_ecdsa_is_valid_curve'
LANGUAGE C STRICT;


--
-- ecdsa_make_key
--

CREATE FUNCTION ecdsa_make_key_raw(text)
RETURNS bytea[]
AS 'MODULE_PATHNAME', 'pg_ecdsa_make_key_raw'
LANGUAGE C STRICT;

CREATE FUNCTION ecdsa_make_key(curve text, OUT public_key text, OUT private_key text) AS $$
    DECLARE
        key_raw bytea[] := ecdsa_make_key_raw(curve);
    BEGIN
        public_key := encode(key_raw[1], 'hex');
        private_key := encode(key_raw[2], 'hex');
    END
$$ LANGUAGE plpgsql STRICT;
