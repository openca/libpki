/* OID management for libpki */

// Brings in default defs
#include <stdlib.h>
#include <string.h>

#ifndef HEADER_OBJECTS_H
# include <openssl/objects.h>
#endif

#ifndef HEADER_ERR_H
#include <openssl/err.h>
#endif

#ifndef HEADER_OBJECTS_MAC_H
# define HEADER_OBJECTS_MAC_H
# include <openssl/obj_mac.h>
#endif

#ifndef _LIBPKI_LOG_H
# include <libpki/pki_log.h>
#endif

#ifndef _LIBPKI_OID_DEFS_H
# include <libpki/openssl/pki_oid_defs.h>
#endif

#ifndef _LIBPKI_ERRORS_H
#include <libpki/pki_err.h>
#endif

#ifndef _LIBPKI_OID_H
# include <libpki/pki_oid.h>
#endif

#ifndef _LIBPKI_HSM_MAIN_H
# include <libpki/drivers/hsm_main.h>
#endif

// Default
#define PKI_OK		1
#define PKI_ERR		0

// ==========================
// Data Structure Definitions
// ==========================

typedef struct oid_init_table_st {
	int nid;
	const char * oid;
	const char * name;
	const char * desc;
} OID_INIT_OBJ;

typedef struct sigs_init_table_st {
	int nid;
	const char * oid;
	const char * name;
	const char * desc;
	int hash_nid;
	int pkey_nid;
	int sig_nid;
} OID_INIT_SIG;

typedef struct libpki_obj_alias_st {
	int nid;
	const char *name;
	const char *oid;
} LIBPKI_OBJ_ALIAS;

typedef struct obj_alias_st {
	char * oid_new;
	char * oid_current;
} OID_ALIAS;

// =============================
// Objects and Signatures Tables
// =============================

#ifdef ENABLE_ECDSA
static LIBPKI_OBJ_ALIAS nist_curves_alias[] = {
	/* prime field curves */
	{ NID_P192, "P192", "1.2.840.10045.3.1.1" },
	{ NID_P224, "P224", "1.3.132.0.33" },
	{ NID_P256, "P256", "1.2.840.10045.3.1.7" },
	{ NID_P384, "P384", "1.3.132.0.34" },
	{ NID_P521, "P521", "1.3.132.0.35" },

	/* characteristic two field curves */
	{ NID_K163, "K163", "1.3.132.0.1" },
	{ NID_K233, "K233", "1.3.132.0.26" },
	{ NID_K283, "K283", "1.3.132.0.16" },
	{ NID_K409, "K409", "1.3.132.0.36" },
	{ NID_K571, "K571", "1.3.132.0.38" },

	{ NID_B163, "B163", "1.3.132.0.15" },
	{ NID_B233, "B233", "1.3.132.0.27" },
	{ NID_B283, "B283", "1.3.132.0.17" },
	{ NID_B409, "B409", "1.3.132.0.37" },
	{ NID_B571, "B571", "1.3.132.0.39" },

	{ -1, NULL, NULL },
};
#endif

OID_INIT_OBJ oids_table[] = {
	{ 0, OPENCA_OID, OPENCA_NAME, OPENCA_DESC},
	{ 0, CERTIFICATE_TEMPLATE_OID, CERTIFICATE_TEMPLATE_NAME, CERTIFICATE_TEMPLATE_DESC},
	{ 0, LEVEL_OF_ASSURANCE_OID, LEVEL_OF_ASSURANCE_NAME, LEVEL_OF_ASSURANCE_DESC},
	{ 0, CERTIFICATE_USAGE_OID, CERTIFICATE_USAGE_NAME, CERTIFICATE_USAGE_DESC},
#ifdef ENABLE_COMPOSITE
	// Composite Key - OpenCA OID
	{ 0, OPENCA_ALG_PKEY_EXP_COMP_OID, OPENCA_ALG_PKEY_EXP_COMP_NAME, OPENCA_ALG_PKEY_EXP_COMP_DESC},
	// Composite Key Explicit
	{ 0, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ECDSA_P256_OID, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ECDSA_P256_NAME, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ECDSA_P256_DESC},
	{ 0, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_OID, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_NAME, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_DESC },
	{ 0, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ECDSA_P256_OID, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ECDSA_P256_NAME, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ECDSA_P256_DESC},
	{ 0, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_OID, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_NAME, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_DESC},
	{ 0, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON1024_ECDSA_P521_OID, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON1024_ECDSA_P521_NAME, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON1024_ECDSA_P521_DESC},
	{ 0, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON1024_RSA_OID, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON1024_RSA_NAME, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON1024_RSA_DESC},
	{ 0, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256R_ECDSA_P256_OID, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256R_ECDSA_P256_NAME, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256R_ECDSA_P256_DESC},
	{ 0, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256F_RSA_OID, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256F_RSA_NAME, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256F_RSA_DESC},
	// Composite Key Alias - Entrust
	{ 0, OPENCA_ALG_PKEY_EXP_COMP_OID_ENTRUST, OPENCA_ALG_PKEY_EXP_COMP_NAME_ENTRUST, OPENCA_ALG_PKEY_EXP_COMP_DESC_ENTRUST},
#endif
#ifdef ENABLE_COMBINED
	// Alt Key
	{ 0, OPENCA_ALG_PKEY_EXP_ALT_OID, OPENCA_ALG_PKEY_EXP_ALT_NAME, OPENCA_ALG_PKEY_EXP_ALT_DESC},
#endif
#ifdef ENABLE_OQS
	// Experimental
	{ 0, OPENCA_ALG_PKEY_EXP_DILITHIUMX_OID, OPENCA_ALG_PKEY_EXP_DILITHIUMX_NAME, OPENCA_ALG_PKEY_EXP_DILITHIUMX_DESC},
#endif
	{ 0, NULL, NULL, NULL }
};

OID_INIT_SIG sigs_table[] = {

#ifdef ENABLE_COMPOSITE
	// Composite Signatures
	{ 0, OPENCA_ALG_SIGS_COMP_OID, OPENCA_ALG_SIGS_COMP_NAME, OPENCA_ALG_SIGS_COMP_DESC, 0, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_COMP_SHA1_OID, OPENCA_ALG_SIGS_COMP_SHA1_NAME, OPENCA_ALG_SIGS_COMP_SHA1_DESC, NID_sha1, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_COMP_SHA256_OID, OPENCA_ALG_SIGS_COMP_SHA256_NAME, OPENCA_ALG_SIGS_COMP_SHA256_DESC, NID_sha256, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_COMP_SHA384_OID, OPENCA_ALG_SIGS_COMP_SHA384_NAME, OPENCA_ALG_SIGS_COMP_SHA384_DESC, NID_sha384, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_COMP_SHA512_OID, OPENCA_ALG_SIGS_COMP_SHA512_NAME, OPENCA_ALG_SIGS_COMP_SHA512_DESC, NID_sha512, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_COMP_SHA3_256_OID, OPENCA_ALG_SIGS_COMP_SHA3_256_NAME, OPENCA_ALG_SIGS_COMP_SHA3_256_DESC, NID_sha3_256, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_COMP_SHA3_384_OID, OPENCA_ALG_SIGS_COMP_SHA3_384_NAME, OPENCA_ALG_SIGS_COMP_SHA3_384_DESC, NID_sha3_384, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_COMP_SHA3_512_OID, OPENCA_ALG_SIGS_COMP_SHA3_512_NAME, OPENCA_ALG_SIGS_COMP_SHA3_512_DESC, NID_sha3_512, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_COMP_SHAKE128_OID, OPENCA_ALG_SIGS_COMP_SHAKE128_NAME, OPENCA_ALG_SIGS_COMP_SHAKE128_DESC, NID_shake128, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_COMP_SHAKE256_OID, OPENCA_ALG_SIGS_COMP_SHAKE256_NAME, OPENCA_ALG_SIGS_COMP_SHAKE256_DESC, NID_shake128, 0, 0 },
#endif

#ifdef ENABLE_COMBINED
	// Alternative Signatures
	{ 0, OPENCA_ALG_SIGS_ALT_OID, OPENCA_ALG_SIGS_ALT_NAME, OPENCA_ALG_SIGS_ALT_DESC, 0, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_ALT_SHA1_OID, OPENCA_ALG_SIGS_ALT_SHA1_NAME, OPENCA_ALG_SIGS_ALT_SHA1_DESC, NID_sha1, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_ALT_SHA256_OID, OPENCA_ALG_SIGS_ALT_SHA256_NAME, OPENCA_ALG_SIGS_ALT_SHA256_DESC, NID_sha256, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_ALT_SHA384_OID, OPENCA_ALG_SIGS_ALT_SHA384_NAME, OPENCA_ALG_SIGS_ALT_SHA384_DESC, NID_sha384, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_ALT_SHA512_OID, OPENCA_ALG_SIGS_ALT_SHA512_NAME, OPENCA_ALG_SIGS_ALT_SHA512_DESC, NID_sha512, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_ALT_SHA3_256_OID, OPENCA_ALG_SIGS_ALT_SHA3_256_NAME, OPENCA_ALG_SIGS_ALT_SHA3_256_DESC, NID_sha3_256, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_ALT_SHA3_384_OID, OPENCA_ALG_SIGS_ALT_SHA3_384_NAME, OPENCA_ALG_SIGS_ALT_SHA3_384_DESC, NID_sha3_384, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_ALT_SHA3_512_OID, OPENCA_ALG_SIGS_ALT_SHA3_512_NAME, OPENCA_ALG_SIGS_ALT_SHA3_512_DESC, NID_sha3_512, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_ALT_SHAKE128_OID, OPENCA_ALG_SIGS_ALT_SHAKE128_NAME, OPENCA_ALG_SIGS_ALT_SHAKE128_DESC, NID_shake128, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_ALT_SHAKE256_OID, OPENCA_ALG_SIGS_ALT_SHAKE256_NAME, OPENCA_ALG_SIGS_ALT_SHAKE256_DESC, NID_shake128, 0, 0 },
#endif

#ifdef ENABLE_OQS
	// Dilithium3 and Dilithium5 Signatures
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM3_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM3_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM3_DESC, NID_undef, NID_dilithium3, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA256_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA256_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA256_DESC, NID_sha256, NID_dilithium3, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA384_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA384_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA384_DESC, NID_sha384, NID_dilithium3, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA512_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA512_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA512_DESC, NID_sha512, NID_dilithium3, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA3_256_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA3_256_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA3_256_DESC, NID_sha3_256, NID_dilithium3, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA3_384_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA3_384_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA3_384_DESC, NID_sha3_384, NID_dilithium3, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA3_512_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA3_512_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA3_512_DESC, NID_sha3_512, NID_dilithium3, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHAKE128_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHAKE128_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHAKE128_DESC, NID_shake128, NID_dilithium3, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHAKE256_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHAKE256_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHAKE256_DESC, NID_shake256, NID_dilithium3, 0 },

	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM5_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM5_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM5_DESC, NID_undef, NID_dilithium5, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA256_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA256_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA256_DESC, NID_sha256, NID_dilithium5, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA384_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA384_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA384_DESC, NID_sha384, NID_dilithium5, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA512_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA512_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA512_DESC, NID_sha512, NID_dilithium5, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA3_256_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA3_256_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA3_256_DESC, NID_sha3_256, NID_dilithium5, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA3_384_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA3_384_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA3_384_DESC, NID_sha3_384, NID_dilithium5, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA3_512_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA3_512_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA3_512_DESC, NID_sha3_512, NID_dilithium5, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHAKE128_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHAKE128_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHAKE128_DESC, NID_shake128, NID_dilithium5, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHAKE256_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHAKE256_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHAKE256_DESC, NID_shake256, NID_dilithium5, 0 },

	// Experimental
	{ 0, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_OID, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_NAME, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_DESC, NID_undef, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA256_OID, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA256_NAME, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA256_DESC, NID_sha256, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA384_OID, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA384_NAME, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA384_DESC, NID_sha384, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA512_OID, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA512_NAME, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA512_DESC, NID_sha512, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA3_256_OID, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA3_256_NAME, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA3_256_DESC, NID_sha3_256, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA3_384_OID, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA3_384_NAME, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA3_384_DESC, NID_sha3_384, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA3_512_OID, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA3_512_NAME, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHA3_512_DESC, NID_sha3_512, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHAKE128_OID, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHAKE128_NAME, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHAKE128_DESC, NID_shake128, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHAKE256_OID, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHAKE256_NAME, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_SHAKE256_DESC, NID_shake256, 0, 0 },

	// Falcon512 and Falcon1024
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON512_OID, OPENCA_ALG_SIGS_PQC_FALCON512_NAME, OPENCA_ALG_SIGS_PQC_FALCON512_DESC, NID_undef, NID_falcon512, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON512_SHA256_OID, OPENCA_ALG_SIGS_PQC_FALCON512_SHA256_NAME, OPENCA_ALG_SIGS_PQC_FALCON512_SHA256_DESC, NID_sha256, NID_falcon512, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON512_SHA384_OID, OPENCA_ALG_SIGS_PQC_FALCON512_SHA384_NAME, OPENCA_ALG_SIGS_PQC_FALCON512_SHA384_DESC, NID_sha384, NID_falcon512, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON512_SHA512_OID, OPENCA_ALG_SIGS_PQC_FALCON512_SHA512_NAME, OPENCA_ALG_SIGS_PQC_FALCON512_SHA512_DESC, NID_sha512, NID_falcon512, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON512_SHA3_256_OID, OPENCA_ALG_SIGS_PQC_FALCON512_SHA3_256_NAME, OPENCA_ALG_SIGS_PQC_FALCON512_SHA3_256_DESC, NID_sha3_256, NID_falcon512, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON512_SHA3_384_OID, OPENCA_ALG_SIGS_PQC_FALCON512_SHA3_384_NAME, OPENCA_ALG_SIGS_PQC_FALCON512_SHA3_384_DESC, NID_sha3_384, NID_falcon512, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON512_SHA3_512_OID, OPENCA_ALG_SIGS_PQC_FALCON512_SHA3_512_NAME, OPENCA_ALG_SIGS_PQC_FALCON512_SHA3_512_DESC, NID_sha3_512, NID_falcon512, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON512_SHAKE128_OID, OPENCA_ALG_SIGS_PQC_FALCON512_SHAKE128_NAME, OPENCA_ALG_SIGS_PQC_FALCON512_SHAKE128_DESC, NID_shake128, NID_falcon512, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON512_SHAKE256_OID, OPENCA_ALG_SIGS_PQC_FALCON512_SHAKE256_NAME, OPENCA_ALG_SIGS_PQC_FALCON512_SHAKE256_DESC, NID_shake256, NID_falcon512, 0 },

	{ 0, OPENCA_ALG_SIGS_PQC_FALCON1024_OID, OPENCA_ALG_SIGS_PQC_FALCON1024_NAME, OPENCA_ALG_SIGS_PQC_FALCON1024_DESC, NID_undef, NID_falcon512, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA256_OID, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA256_NAME, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA256_DESC, NID_sha256, NID_dilithium5, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA384_OID, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA384_NAME, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA384_DESC, NID_sha384, NID_dilithium5, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA512_OID, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA512_NAME, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA512_DESC, NID_sha512, NID_dilithium5, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA3_256_OID, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA3_256_NAME, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA3_256_DESC, NID_sha3_256, NID_dilithium5, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA3_384_OID, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA3_384_NAME, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA3_384_DESC, NID_sha3_384, NID_dilithium5, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA3_512_OID, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA3_512_NAME, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA3_512_DESC, NID_sha3_512, NID_dilithium5, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON1024_SHAKE128_OID, OPENCA_ALG_SIGS_PQC_FALCON1024_SHAKE128_NAME, OPENCA_ALG_SIGS_PQC_FALCON1024_SHAKE128_DESC, NID_shake128, NID_falcon1024, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON1024_SHAKE256_OID, OPENCA_ALG_SIGS_PQC_FALCON1024_SHAKE256_NAME, OPENCA_ALG_SIGS_PQC_FALCON1024_SHAKE256_DESC, NID_shake256, NID_falcon1024, 0 },
#endif
	{ 0, NULL, NULL, NULL, 0, 0, 0 }
};

OID_ALIAS alias_table[] = {
	// { nid, oid, alias_oid }
	// Entrust (to) <- LibPKI (from) 
	{ OPENCA_ALG_PKEY_EXP_COMP_OID_ENTRUST, OPENCA_ALG_PKEY_EXP_COMP_OID },
	// Explicit as Aliases to Generic Composite
	{ OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ECDSA_P256_OID, OPENCA_ALG_PKEY_EXP_COMP_OID },
	{ OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_OID, OPENCA_ALG_PKEY_EXP_COMP_OID },
	{ OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ECDSA_P256_OID, OPENCA_ALG_PKEY_EXP_COMP_OID },
	{ OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_OID, OPENCA_ALG_PKEY_EXP_COMP_OID },
	{ OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON1024_ECDSA_P521_OID, OPENCA_ALG_PKEY_EXP_COMP_OID },
	{ OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON1024_RSA_OID, OPENCA_ALG_PKEY_EXP_COMP_OID },
	{ OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256R_ECDSA_P256_OID, OPENCA_ALG_PKEY_EXP_COMP_OID },
	{ OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256F_RSA_OID, OPENCA_ALG_PKEY_EXP_COMP_OID  },
	{ NULL, NULL }
};

// ================
// Static Functions
// ================

static int __create_object_with_id (const char * oid, 
									const char * sn, 
									const char * ln,
									int 		 id) {
	int ret = PKI_OK;
	unsigned char *buf;
	int i;

	ASN1_OBJECT *obj=NULL;

	// Create a NEW ID
	if (id < 0) id = OBJ_new_nid(1);

	// Gets the allocation for the object
    if ((i = a2d_ASN1_OBJECT(NULL,0,oid,-1)) <= 0 )
		return PKI_ERR;

	// Allocates the needed buffer memory
    if ((buf=(unsigned char *)OPENSSL_malloc((size_t)i)) == NULL) 
		return PKI_ERR;

	// Generates the Object
    if ((i=a2d_ASN1_OBJECT(buf,i,oid,-1)) == 0 )
		goto err;

    if ((obj = (ASN1_OBJECT *)ASN1_OBJECT_create(id,buf,i,sn,ln)) == 0)
        goto err;

	// All Done, return the object
    ret = OBJ_add_object(obj);

err:
    ASN1_OBJECT_free(obj);
    OPENSSL_free(buf);

	if( ret == 0 ) return PKI_ERR;

	return PKI_OK;
}

// ==============
// Main Functions
// ==============

int PKI_X509_OID_init() {

	OID_INIT_OBJ * obj = oids_table;
	OID_INIT_SIG * sig = sigs_table;
	OID_ALIAS * alias = alias_table;
	int index = 0;

#ifdef ENABLE_ECDSA

	for (int i = 0; nist_curves_alias[i].name; i++ ) {
		PKI_OID *oid = NULL;
		char buf[2048];

		if( nist_curves_alias[i].oid ) {
			oid = PKI_OID_get( (char *) nist_curves_alias[i].oid );
		} else {
			oid = PKI_OID_new_id( nist_curves_alias[i].nid );
		}
		
		if (!oid) continue;

		OBJ_obj2txt(buf, sizeof(buf), oid, 1);
		PKI_OID_free ( oid );

		if( __create_object_with_id (buf,
									 nist_curves_alias[i].name, 
									 nist_curves_alias[i].name, 
									 nist_curves_alias[i].nid ) == 0 ) {
				// Error while adding "easy" names for NIST curves
				PKI_DEBUG("Cannot add NIST curve alias %s", nist_curves_alias[i].name);
		}
	}

#endif

	// Process all the objects/items
	while (obj != NULL && obj->oid != NULL) {

		// Checks if the OID already exists
		if (OBJ_txt2nid(obj->oid) != NID_undef) {
			PKI_DEBUG("OID value (%s) is already defined as %s (%s), skipping",
				obj->oid, OBJ_nid2sn(OBJ_txt2nid(obj->oid)), OBJ_nid2ln(OBJ_txt2nid(obj->oid)));
			obj = &oids_table[++index];
			continue;
		}

		// Checks if the OID already exists
		if (OBJ_txt2nid(obj->name) != NID_undef) {
			PKI_DEBUG("OID Name (%s) is already defined as %s (%s), skipping",
				obj->name, OBJ_nid2sn(OBJ_txt2nid(obj->name)), OBJ_nid2ln(OBJ_txt2nid(obj->name)));
			obj = &oids_table[++index];
			continue;
		}

		// Resets the Error
		ERR_clear_error();

		// Generate the object
		obj->nid = OBJ_create(obj->oid, obj->name, obj->desc);

		// Verify the results
		if (obj->nid == 0) {
			int err_number = HSM_get_errno(NULL);
			PKI_DEBUG("Cannot create NID for %s (%s) (Crypto Error: %s)", 
				obj->name, obj->oid, HSM_get_errdesc(err_number, NULL));
			fflush(stderr);
		}

		// Next Entry
		obj = &oids_table[++index];
	}

	// Resets the index
	index = 0;
	sig = sigs_table;

	// Process all the signatures
	while (sig != NULL && sig->oid != NULL) {

		// Checks if we need to get the OID of the PKEY
		if (sig->pkey_nid == NID_undef) {

			// Try the dynamic methods, matches the prefix of the
			// signature. For example, all COMPOSITE signatures are
			// captured by checking that the OID is under the
			// OPENCA_ALG_SIGS_COMP_OID arc.

			// Composite
			if (!strncmp(sig->oid, OPENCA_ALG_SIGS_COMP_OID, strlen(OPENCA_ALG_SIGS_COMP_OID))) {
				sig->pkey_nid = OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_OID);
			// Alternative
			} else if (!strncmp(sig->oid, OPENCA_ALG_SIGS_ALT_OID, strlen(OPENCA_ALG_SIGS_ALT_OID))) {
				sig->pkey_nid = OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_ALT_OID);
			// Dilithium3
			} else if (!strncmp(sig->oid, OPENCA_ALG_SIGS_PQC_DILITHIUM3_OID, strlen(OPENCA_ALG_SIGS_PQC_DILITHIUM3_OID))) {
				sig->pkey_nid = OBJ_txt2nid(OPENCA_ALG_SIGS_PQC_DILITHIUM3_OID);
			// Dilithium5
			} else if (!strncmp(sig->oid, OPENCA_ALG_SIGS_PQC_DILITHIUM5_OID, strlen(OPENCA_ALG_SIGS_PQC_DILITHIUM5_OID))) {
				sig->pkey_nid = OBJ_txt2nid(OPENCA_ALG_SIGS_PQC_DILITHIUM5_OID);
			// Experimental - Dilithium3X
			} else if (!strncmp(sig->oid, OPENCA_ALG_SIGS_EXP_DILITHIUMX3_OID, strlen(OPENCA_ALG_SIGS_EXP_DILITHIUMX3_OID))) {
				sig->pkey_nid = OBJ_txt2nid(OPENCA_ALG_SIGS_EXP_DILITHIUMX3_OID);
			// Falcon512
			} else if (!strncmp(sig->oid, OPENCA_ALG_SIGS_PQC_FALCON512_OID, strlen(OPENCA_ALG_SIGS_PQC_FALCON512_OID))) {
				sig->pkey_nid = OBJ_txt2nid(OPENCA_ALG_SIGS_PQC_FALCON512_OID);
			// Falcon1024
			} else if (!strncmp(sig->oid, OPENCA_ALG_SIGS_PQC_FALCON1024_OID, strlen(OPENCA_ALG_SIGS_PQC_FALCON1024_OID))) {
				sig->pkey_nid = OBJ_txt2nid(OPENCA_ALG_SIGS_PQC_FALCON1024_OID);
			}
			else
			{
				PKI_DEBUG("(%d) Cannot find the PKEY nid for signature type (%s)", index, sig->oid);
				sig = &sigs_table[++index];
				continue;
			}
		}

		// Generates the New Signature Object
		sig->sig_nid = OBJ_create(sig->oid, sig->name, sig->desc);
		if (sig->sig_nid == NID_undef) {
			PKI_DEBUG("ERROR: Cannot create Signature Object (%s - %s)\n", sig->name, sig->oid);
			// Error Condition, nothing to do here
			PKI_ERROR(PKI_ERR_ALGOR_SET, NULL);
		} else {
			// Adds the Signature NID to the OpenSSL's Index (and our table)
			if (!OBJ_add_sigid(sig->sig_nid, sig->hash_nid, sig->pkey_nid)) {
				fprintf(stderr, "ERROR: Cannot associate signature nid (%d) with hash nid (%d) and pkey nid (%d\n",
					sig->nid, sig->hash_nid, sig->pkey_nid);
			}
		}

		sig = &sigs_table[++index];
	}

	// Resets the index
	index = 0;
	alias = &alias_table[index];

	// Process all the aliases
	while (alias != NULL && alias->oid_new != NULL && alias->oid_current != NULL) {

		int from = -1, to = -1;
			// Identifiers for the OIDs

		// Resets the Crypto Layer Error
		ERR_clear_error();

		// Gets the NIDs we need
		from = OBJ_txt2nid(alias->oid_new);
		to = OBJ_txt2nid(alias->oid_current);

		// Checks the NIDs
		if (from == NID_undef || to == NID_undef) {
			PKI_DEBUG("(%d) Cannot add a new alias %s (%s) for the existing %s (%s). Either the new (%d) or the existing (%d) OIDs are not defined (Crypto Error: %s)", 
				index, OBJ_nid2sn(OBJ_txt2nid(alias->oid_new)), alias->oid_new, OBJ_nid2sn(OBJ_txt2nid(alias->oid_current)), alias->oid_current,
				from, to, HSM_get_errdesc(HSM_get_errno(NULL), NULL));
			alias = &alias_table[++index];
			continue;
		}

		// Creates the alias
		if (!EVP_PKEY_asn1_add_alias(to, from)) {
			PKI_DEBUG("(%d) Cannot add Alias (%s) for Algorithm (%s) (Crypto Error: %s)", 
				index, alias->oid_new, alias->oid_current, HSM_get_errdesc(HSM_get_errno(NULL), NULL));
			alias = &alias_table[++index];
			continue;
		}

		// PKI_DEBUG("(%d) Created New OID Alias (%s) %s -> %s (%s)", 
		// 	index, OBJ_nid2sn(OBJ_txt2nid(alias->oid_new)), alias->oid_new,
		// 	OBJ_nid2sn(OBJ_txt2nid(alias->oid_current)), alias->oid_current);

		// Advances the index
		alias = &alias_table[++index];
	}

	// All Done
	return 1;
}

