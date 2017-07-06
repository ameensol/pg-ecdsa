#include "postgres.h"
#include "fmgr.h"
#include "catalog/pg_type.h"
#include "utils/lsyscache.h"
#include "utils/builtins.h"
#include "utils/array.h"

#include "micro-ecc-601bd1/uECC.h"
#include "micro-ecc-601bd1/types.h"

PG_MODULE_MAGIC;

#define VARSIZE_data(x) (VARSIZE(x) - VARHDRSZ)
#define VARDATA_char(x) ((char *)VARDATA(x))
#define VARDATA_uint8(x) ((uint8_t *)VARDATA(x))

static const struct uECC_Curve_t *
get_curve_by_name(const char *name, size_t name_len) {
	if (strncmp(name, "secp160r1", name_len) == 0)
		return uECC_secp160r1();
	if (strncmp(name, "secp192r1", name_len) == 0)
		return uECC_secp192r1();
	if (strncmp(name, "secp224r1", name_len) == 0)
		return uECC_secp224r1();
	if (strncmp(name, "secp256r1", name_len) == 0)
		return uECC_secp256r1();
	if (strncmp(name, "secp256k1", name_len) == 0)
		return uECC_secp256k1();
	return NULL;
}

static const struct uECC_Curve_t *
x_get_curve_by_name(const char *name, int name_len) {
	const struct uECC_Curve_t *curve = get_curve_by_name(name, name_len);
	if (curve != NULL)
		return curve;
	ereport(ERROR, (
		errcode(ERRCODE_INVALID_PARAMETER_VALUE),
		errmsg("Invalid curve: %.*s", name_len, name)
	));
}

static bool
is_private_key_valid(const char *key, size_t key_size, const struct uECC_Curve_t *curve) {
	if (key_size != uECC_curve_private_key_size(curve)) {
		return false;
	}

	// private keys must be non-zero
	for (int i = 0; i < key_size; i += 1) {
		char byte = VARDATA_char(key)[i];
		if (byte != 0) {
			return true;
		}
	}

	return false;
}

/* SQL function: ecdsa_sign_raw(private_key:bytea, data:bytea, curve:text) returns bytea */
PG_FUNCTION_INFO_V1(pg_ecdsa_sign_raw);
Datum
pg_ecdsa_sign_raw(PG_FUNCTION_ARGS)
{
	bytea *key        = PG_GETARG_BYTEA_P(0);
	bytea *data       = PG_GETARG_BYTEA_P(1);
	text  *curve_name = PG_GETARG_TEXT_P(2);

	//elog(WARNING, "curve: %.*s", VARSIZE_data(curve_name), VARDATA_char(curve_name));
	const struct uECC_Curve_t *curve = x_get_curve_by_name(
			VARDATA_char(curve_name), VARSIZE_data(curve_name));

	int expected_key_size = uECC_curve_private_key_size(curve);
	if (VARSIZE_data(key) != expected_key_size) {
		ereport(ERROR, (
			errcode(ERRCODE_INVALID_PARAMETER_VALUE),
			errmsg("Invalid private key size for curve %.*s: %d (should be %d)",
				VARSIZE_data(curve_name), VARDATA_char(curve_name),
				VARSIZE_data(key),
				expected_key_size
			)
		));
	}

	size_t res_size = uECC_curve_public_key_size(curve) + VARHDRSZ;
	bytea *res = (bytea *)palloc(res_size);

	SET_VARSIZE(res, res_size);

	uECC_sign(
		VARDATA_uint8(key),
		VARDATA_uint8(data), VARSIZE_data(data),
		VARDATA_uint8(res),
		curve
	);

	PG_FREE_IF_COPY(key, 0);
	PG_FREE_IF_COPY(data, 1);
	PG_FREE_IF_COPY(curve_name, 2);
	PG_RETURN_BYTEA_P(res);
}

/* SQL function: ecdsa_verify_raw(public_key:bytea, data:bytea, signature:bytea, curve:text) returns boolean */
PG_FUNCTION_INFO_V1(pg_ecdsa_verify_raw);
Datum
pg_ecdsa_verify_raw(PG_FUNCTION_ARGS)
{
	bytea *key        = PG_GETARG_BYTEA_P(0);
	bytea *data       = PG_GETARG_BYTEA_P(1);
	bytea *signature  = PG_GETARG_BYTEA_P(2);
	text  *curve_name = PG_GETARG_TEXT_P(3);

	const struct uECC_Curve_t *curve = x_get_curve_by_name(
			VARDATA_char(curve_name), VARSIZE_data(curve_name));

	int expected_key_size = uECC_curve_public_key_size(curve);
	if (VARSIZE_data(key) != expected_key_size) {
		ereport(ERROR, (
			errcode(ERRCODE_INVALID_PARAMETER_VALUE),
			errmsg("Invalid public key size for curve %.*s: %d (should be %d)",
				VARSIZE_data(curve_name), VARDATA_char(curve_name),
				VARSIZE_data(key),
				expected_key_size
			)
		));
	}

	int res = uECC_verify(
		VARDATA_uint8(key),
		VARDATA_uint8(data), VARSIZE_data(data),
		VARDATA_uint8(signature),
		curve
	);

	PG_FREE_IF_COPY(key, 0);
	PG_FREE_IF_COPY(data, 1);
	PG_FREE_IF_COPY(signature, 2);
	PG_FREE_IF_COPY(curve_name, 3);
	PG_RETURN_BOOL(res);
}

/* SQL function: ecdsa_is_valid_public_key(public_key:bytea, curve:text) returns boolean */
PG_FUNCTION_INFO_V1(pg_ecdsa_is_valid_public_key);
Datum
pg_ecdsa_is_valid_public_key(PG_FUNCTION_ARGS)
{
	bytea *key        = PG_GETARG_BYTEA_P(0);
	text  *curve_name = PG_GETARG_TEXT_P(1);

	const struct uECC_Curve_t *curve = x_get_curve_by_name(
			VARDATA_char(curve_name), VARSIZE_data(curve_name));

	int res = (
		VARSIZE_data(key) == uECC_curve_public_key_size(curve) &&
		uECC_valid_public_key(VARDATA_uint8(key), curve)
	);

	PG_FREE_IF_COPY(key, 0);
	PG_FREE_IF_COPY(curve_name, 1);
	PG_RETURN_BOOL(res);
}

/* SQL function: ecdsa_is_valid_private_key(private_key:bytea, curve:text) returns boolean */
PG_FUNCTION_INFO_V1(pg_ecdsa_is_valid_private_key);
Datum
pg_ecdsa_is_valid_private_key(PG_FUNCTION_ARGS)
{
	bytea *key        = PG_GETARG_BYTEA_P(0);
	text  *curve_name = PG_GETARG_TEXT_P(1);

	const struct uECC_Curve_t *curve = x_get_curve_by_name(
			VARDATA_char(curve_name), VARSIZE_data(curve_name));

	bool res = is_private_key_valid(VARDATA_char(key), VARSIZE_data(key), curve);

	PG_FREE_IF_COPY(key, 0);
	PG_FREE_IF_COPY(curve_name, 1);
	PG_RETURN_BOOL(res);
}

/* SQL function: ecdsa_is_valid_curve(curve:text) returns boolean */
PG_FUNCTION_INFO_V1(pg_ecdsa_is_valid_curve);
Datum
pg_ecdsa_is_valid_curve(PG_FUNCTION_ARGS)
{
	text  *curve_name = PG_GETARG_TEXT_P(0);

	void *curve = (void *)get_curve_by_name(VARDATA_char(curve_name), VARSIZE_data(curve_name));

	PG_FREE_IF_COPY(curve_name, 0);
	PG_RETURN_BOOL(curve != NULL);
}

/* SQL function: ecdsa_make_key_raw(curve:text) returns bytea[2] */
PG_FUNCTION_INFO_V1(pg_ecdsa_make_key_raw);
Datum
pg_ecdsa_make_key_raw(PG_FUNCTION_ARGS)
{
	text  *curve_name = PG_GETARG_TEXT_P(0);

	void *curve = (void *)get_curve_by_name(VARDATA_char(curve_name), VARSIZE_data(curve_name));

	// nb: these can be stack-allocated because construct_md_array will copy
	//	   them into the result.
	char pub_key[uECC_curve_public_key_size(curve) + VARHDRSZ];
	char prv_key[uECC_curve_private_key_size(curve) + VARHDRSZ];
	bytea *keys[2] = { (bytea *)&pub_key, (bytea *)&prv_key };

	int ok = uECC_make_key(VARDATA_uint8(pub_key), VARDATA_uint8(prv_key), curve);
	if (!ok) {
		ereport(ERROR, (
			errcode(ERRCODE_INTERNAL_ERROR),
			errmsg("uECC_make_key() returned an unspecified error.")
		));
	}

	SET_VARSIZE(pub_key, uECC_curve_public_key_size(curve) + VARHDRSZ);
	SET_VARSIZE(prv_key, uECC_curve_private_key_size(curve) + VARHDRSZ);

    int dims[1] = { 2 };
    int  lbs[1] = { 1 };

    int16 typlen;
    bool  typbyval;
    char  typalign;
    get_typlenbyvalalign(BYTEAOID, &typlen, &typbyval, &typalign);

    ArrayType *result = construct_md_array(
		(Datum *)&keys, NULL, 1, dims, lbs,
		BYTEAOID, typlen, typbyval, typalign
	);

	PG_FREE_IF_COPY(curve_name, 0);
    PG_RETURN_ARRAYTYPE_P(result);
}

/* vim: set shiftwidth=4 tabstop=4 softtabstop=4 noexpandtab : */
