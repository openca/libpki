/* crypto_types.h */

#ifndef _LIBPKI_SYSTEM_H
# include <libpki/libconf/system.h>
#endif

#ifdef ENABLE_OQS
# include <oqs/oqsconfig.h>
#endif

#ifdef _LIBPKI_UTILS_TYPES_H
#include <libpki/utils/types.h>
#endif

#ifndef _LIBPKI_HSM_TYPES_H
#include <libpki/crypto/hsm/types.h>
#endif

#ifndef CRYTO_NO_OPENSSL
#ifndef _LIBPKI_OPENSSL_TYPES_H
#include <libpki/crypto/hsm/openssl/types.h>
#endif
#endif

#ifndef _LIBPKI_CRYPTO_TYPES_H
#define _LIBPKI_CRYPTO_TYPES_H	

BEGIN_C_DECLS

#define CRYPTO_BUFFER_TINY_SZ		128
#define CRYPTO_BUFFER_SMALL_SZ		1024
#define CRYPTO_BUFFER_MEDIUM_SZ		2048
#define CRYPTO_BUFFER_LARGE_SZ		8192
#define CRYPTO_BUFFER_DEF_SZ		CRYPTO_BUFFER_MEDIUM_SZ
#define CRYPTO_BUFFER_MAX_SZ		CRYPTO_BUFFER_LARGE_SZ

typedef enum c_key_min_enum {
	CRYPTO_RSA_KEY_MIN_SIZE		= 1024,
	CRYPTO_DSA_KEY_MIN_SIZE		= 2048,
	CRYPTO_EC_KEY_MIN_SIZE		= 256,
} CRYPTO_MIN_SZ;

typedef enum c_key_default_enum {
	CRYPTO_RSA_DEFAULT_SZ	= 2048,
	CRYPTO_DSA_DEFAULT_SZ	= 2048,
	CRYPTO_EC_DEFAULT_SZ	= 256
} CRYPTO_DEFAULT_SZ;

typedef enum crypto_type_enum {
	/* Signature - Traditional */
	CRYPTO_TYPE_RSA = 1,
	CRYPTO_TYPE_RSAPSS,
	CRYPTO_TYPE_ECDSA,
	CRYPTO_TYPE_ED25519,
	CRYPTO_TYPE_ED448,
	/* Signature - quantum-safe */
	CRYPTO_TYPE_MLDSA44,
	CRYPTO_TYPE_MLDSA65,
	CRYPTO_TYPE_MLDSA87,
	/* Signature - Composite */
	CRYPTO_TYPE_MLDSA44_P256,
	CRYPTO_TYPE_MLDSA44_ED25519,
	/* Key Exchange - quantum-safe */
	CRYPTO_TYPE_MLKEM512,
	CRYPTO_TYPE_MLKEM768,
	CRYPTO_TYPE_MLKEM1024,
	/* Key Exchange - Composite */
	CRYPTO_TYPE_MLKEM768_P256,
	CRYPTO_TYPE_MLKEM768_CURVE25519,
	CRYPTO_TYPE_MLKEM1024_CURVE448,
	/* Hash Types */
	CRYPTO_TYPE_SHA1,
	CRYPTO_TYPE_SHA224,
	CRYPTO_TYPE_SHA256,
	CRYPTO_TYPE_SHA384,
	CRYPTO_TYPE_SHA512,
	CRYPTO_TYPE_SHA512_224,
	CRYPTO_TYPE_SHA512_256,
	CRYPTO_TYPE_SHA3_224,
	CRYPTO_TYPE_SHA3_256,
	CRYPTO_TYPE_SHA3_384,
	CRYPTO_TYPE_SHA3_512,
	CRYPTO_TYPE_SHAKE128,
	CRYPTO_TYPE_SHAKE256,
	/* HMAC */
	CRYPTO_TYPE_HMAC_SHA1,
	CRYPTO_TYPE_HMAC_SHA224,
	CRYPTO_TYPE_HMAC_SHA256,
	CRYPTO_TYPE_HMAC_SHA384,
	CRYPTO_TYPE_HMAC_SHA512,
	CRYPTO_TYPE_HMAC_SHA512_224,
	CRYPTO_TYPE_HMAC_SHA512_256,
	CRYPTO_TYPE_HMAC_SHA3_224,
	CRYPTO_TYPE_HMAC_SHA3_256,
	CRYPTO_TYPE_HMAC_SHA3_384,
	CRYPTO_TYPE_HMAC_SHA3_512,
	CRYPTO_TYPE_HMAC_SHAKE128,
	CRYPTO_TYPE_HMAC_SHAKE256,
	
	/* Password Based Encryption */
	CRYPTO_TYPE_PBKDF2,
	CRYPTO_TYPE_PKCS5_PBES2,
	CRYPTO_TYPE_PKCS5_PBKDF2,

	/* Symmetric Encryption */
	CRYPTO_TYPE_AES128,
	CRYPTO_TYPE_AES192,
	CRYPTO_TYPE_AES256,
	CRYPTO_TYPE_AES128_GCM,
	CRYPTO_TYPE_AES192_GCM,
	CRYPTO_TYPE_AES256_GCM,
	CRYPTO_TYPE_AES128_CCM,
	CRYPTO_TYPE_AES192_CCM,
	CRYPTO_TYPE_AES256_CCM,
	CRYPTO_TYPE_AES128_CFB,
	CRYPTO_TYPE_AES192_CFB,
	CRYPTO_TYPE_AES256_CFB,
	CRYPTO_TYPE_AES128_OFB,
	CRYPTO_TYPE_AES192_OFB,
	CRYPTO_TYPE_AES256_OFB,
	CRYPTO_TYPE_AES128_CTR,
	CRYPTO_TYPE_AES192_CTR,
	CRYPTO_TYPE_AES256_CTR,
	CRYPTO_TYPE_AES128_CBC,
	CRYPTO_TYPE_AES192_CBC,
	CRYPTO_TYPE_AES256_CBC,
	CRYPTO_TYPE_AES128_XTS,
	CRYPTO_TYPE_AES256_XTS,

	/* Symmetric Encryption - Quantum Safe */
	CRYPTO_TYPE_KYBER512,
	CRYPTO_TYPE_KYBER768,
	CRYPTO_TYPE_KYBER1024,

	/* Symmetric Encryption - Composite */

} CRYPTO_TYPE;

typedef struct c_keyparams_st {

	int pkey_type;
	int is_postquantum;
	int is_deprecated;

#ifndef CRYPTO_NO_RSA
	struct {
		int exponent;
		int bits;
	} rsa;

	struct {
		int exponent;
		int bits;
		int mfg1;
	} rsapss;
#endif

#ifndef CRYPTO_NO_EDDSA
	struct {
		const char * curve;
	} eddsa;
#endif

#ifndef CRYTPO_NO_DSA
	// DSA scheme parameters
	struct {
		int bits;
	} dsa;
#endif

#ifndef CRYPTO_NO_ECDSA
	struct {
		const char * curve;
		CRYPTO_EC_FORM form;
		int asn1flags;
	} ec;
#endif 

#if defined(ENABLE_OQS) || defined(ENABLE_OQSPROV)
	struct {
		const char * alg;
	} oqs;
#endif // ENABLE_OQS

#ifdef ENABLE_COMPOSITE
	struct {
		const char * alg;
		int k_of_n;
	} comp;
#endif

} CRYPTO_KEYPARAMS;

typedef struct c_keypair_st {
	CRYPTO_TYPE type;
	CRYPTO_KEYPARAMS params;
	void * crypto_lib_value;
} CRYPTO_KEYPAIR;

typedef struct c_pw_cb_st {
	const void *password;
	const char *prompt_info;
} CRYPRO_PW_CB_DATA;

typedef struct c_buffer_tiny_st {
	size_t size;
	byte data[CRYPTO_BUFFER_TINY_SZ];
} CRYPTO_BUFFER_TINY;

typedef struct c_buffer_small_st {
	size_t size;
	byte data[CRYPTO_BUFFER_SMALL_SZ];
} CRYPTO_BUFFER_SMALL;

typedef struct c_buffer_medium_st {
	size_t size;
	byte data[CRYPTO_BUFFER_MEDIUM_SZ];
} CRYPTO_BUFFER_MEDIUM;

typedef struct c_buffer_large_st {
	size_t size;
	byte data[CRYPTO_BUFFER_LARGE_SZ];
} CRYPTO_BUFFER_LARGE;

typedef struct c_digest_st {
	CRYPTO_TYPE type;
	CRYPTO_BUFFER_TINY digest;
} CRYPTO_DIGEST;

typedef struct crypto_hmac_st {
	// Digest Algoritm to use. Default is SHA-1
	CRYPTO_TYPE type;
	CRYPTO_BUFFER_TINY key;
} CRYPTO_HMAC;

END_C_DECLS

/* End of _LIBPKI_HEADER_DATA_ST_H */
#endif
