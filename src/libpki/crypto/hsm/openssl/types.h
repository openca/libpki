/* crypto_types.h */

#ifndef _LIBPKI_SYSTEM_H
# include <libpki/libconf/system.h>
#endif

#ifdef _LIBPKI_UTILS_TYPES_H
# include <libpki/utils/types.h>
#endif

#ifdef ENABLE_OQS
# include <oqs/oqsconfig.h>
#endif

#ifndef _LIBPKI_CRYPTO_HSM_OPENSSL_TYPES_H
#define _LIBPKI_CRYPTO_HSM_OPENSSL_TYPES_H

# ifndef CRYPTO_NO_OPENSSL

#  include <openssl/evp.h>
#  include <openssl/x509.h>
#  include <openssl/x509v3.h>
#  include <openssl/rsa.h>
#  include <openssl/dsa.h>
#  include <openssl/pkcs12.h>
#  include <openssl/safestack.h>
#  include <openssl/ocsp.h>
#  include <openssl/objects.h>
#  include <openssl/obj_mac.h>
#  include <openssl/hmac.h>

#  include <openssl/ec.h>

#  include <openssl/asn1.h>
#  include <openssl/asn1t.h>

#  include <openssl/cms.h>

#  ifdef ENABLE_ECDSA
#   include <openssl/ec.h>
#  endif

#  ifdef ENABLE_OQS
#   include <oqs/oqs.h>
#  endif

BEGIN_C_DECLS

/* Crypto Library Asymmetric Key */
typedef struct evp_pkey_st CRYPTO_PKEY; // Replace 'EVP_PKEY' with 'evp_pkey_st'

/* Crypto Library Hash Type */
typedef struct evp_md_st CRYPTO_HASH;

/* Crypto Library General Cipher Type */
typedef struct evp_cipher_st CRYPTO_CIPHER;

/* Some useful Key definitions */
#  ifndef CRYPTO_NO_RSA
#   define CRYPTO_RSA			RSA
#   ifndef CRYPTO_NO_RSAPSS
#    define CRYPTO_RSAPSS		RSA
#   endif
#  endif

#  ifdef ENABLE_ECDSA
#   define CRYPTO_EC			EC_KEY
#  endif

// Typedef for EC Form
typedef point_conversion_form_t CRYPTO_EC_FORM;

// Defines for supported EC Form
#define CRYPTO_EC_FORM_UNKNOWN        0
#define CRYPTO_EC_FORM_COMPRESSED     POINT_CONVERSION_COMPRESSED
#define CRYPTO_EC_FORM_UNCOMPRESSED   POINT_CONVERSION_UNCOMPRESSED
#define CRYPTO_EC_FORM_HYBRID         POINT_CONVERSION_HYBRID

// Default Value
#define CRYPTO_EC_FORM_DEFAULT		   CRYPTO_EC_FORM_UNCOMPRESSED

// ASN1 flags for EC keys
typedef enum {
	CRYPTO_EC_ASN1_EXPLICIT_CURVE  = OPENSSL_EC_EXPLICIT_CURVE,
	CRYPTO_EC_ASN1_NAMED_CURVE     = OPENSSL_EC_NAMED_CURVE,
	CRYPTO_EC_ASN1_IMPLICIT_CURVE  = -1
} CRYPTO_EC_KEY_ASN1;

// Default for ASN1 flag
#define CRYPTO_EC_KEY_ASN1_DEFAULT			CRYPTO_EC_KEY_ASN1_NAMED_CURVE

#  if defined(ENABLE_OQS) || defined(ENABLE_OQSPROV)

typedef enum {
	PKI_ALGOR_OQS_PARAM_UNKNOWN       = 0,
	PKI_ALGOR_OQS_PARAM_DILITHIUM_AES,
	PKI_ALGOR_OQS_PARAM_SPHINCS_SHAKE
} PKI_ALGOR_OQS_PARAM;

#  endif /* ENABLE_OQS */

END_C_DECLS

#  endif /* CRYPTO_NO_OPENSSL */
# endif /* _LIBPKI_OPENSSL_TYPES_H */
