/* openssl/pki_algor.c */

#include <libpki/pki.h>
#include <libpki/openssl/data_st.h>

#ifdef max
#undef max
#endif

#ifndef max
#define max(a,b) \
	(((a) > (b)) ? (a) : (b))
#endif

/* List of supported digest algorithms grouped by scheme */
const PKI_ALGOR_ID PKI_ALGOR_ID_LIST_RSA[] = {
//	PKI_ALGOR_RSA_MD2,
#ifndef OPENSSL_FIPS
	PKI_ALGOR_ID_RSA_MD4,
	PKI_ALGOR_ID_RSA_MD5,
#endif
	PKI_ALGOR_ID_RSA_SHA1,
	PKI_ALGOR_ID_RSA_SHA224,
	PKI_ALGOR_ID_RSA_SHA256,
	PKI_ALGOR_ID_RSA_SHA384,
	PKI_ALGOR_ID_RSA_SHA512,
#ifdef ENABLE_RSA_RIPEMD128
	PKI_ALGOR_ID_RSA_RIPEMD128,
#endif
#ifdef ENABLE_RSA_RIPEMD160
	PKI_ALGOR_ID_RSA_RIPEMD160,
#endif
#ifdef ENABLE_SHA3_256
	PKI_ALGOR_ID_RSA_SHA3_256,
#endif
#ifdef ENABLE_SHA3_384
	PKI_ALGOR_ID_RSA_SHA3_384,
#endif
#ifdef ENABLE_SHA3_512
	PKI_ALGOR_ID_RSA_SHA3_512,
#endif
	PKI_ALGOR_ID_UNKNOWN
};

const PKI_ALGOR_ID PKI_ALGOR_ID_LIST_DSA[] = {
#ifdef PKI_ALGOR_ID_DSA_SHA1
	PKI_ALGOR_ID_DSA_SHA1,
#endif
#ifdef PKI_ALGOR_ID_DSA_SHA224
	PKI_ALGOR_ID_DSA_SHA224,
#endif
#ifdef PKI_ALGOR_ID_DSA_SHA256
	PKI_ALGOR_ID_DSA_SHA256,
#endif
#ifdef PKI_ALGOR_ID_DSA_SHA384
	PKI_ALGOR_ID_DSA_SHA384,
#endif
#ifdef PKI_ALGOR_ID_DSA_SHA512
	PKI_ALGOR_ID_DSA_SHA512,
#endif
	PKI_ALGOR_ID_UNKNOWN
};

#ifdef ENABLE_ECDSA
PKI_ALGOR_ID PKI_ALGOR_ID_LIST_ECDSA[] = {
# ifdef PKI_ALGOR_ECDSA_SHA1
	PKI_ALGOR_ID_ECDSA_SHA1,
# endif
# ifdef PKI_ALGORID_ECDSA_SHA224
	PKI_ALGOR_ID_ECDSA_SHA224,
# endif
# ifdef PKI_ALGOR_ID_ECDSA_SHA256
	PKI_ALGOR_ID_ECDSA_SHA256,
# endif
# ifdef PKI_ALGOR_ID_ECDSA_SHA384
	PKI_ALGOR_ID_ECDSA_SHA384,
# endif
# ifdef PKI_ALGOR_ID_ECDSA_SHA512
	PKI_ALGOR_ID_ECDSA_SHA512,
# endif
# ifdef PKI_ALGOR_ID_ECDSA_SHA3_256
	PKI_ALGOR_ID_ECDSA_SHA3_256,
# endif
# ifdef PKI_ALGOR_ID_ECDSA_SHA3_384
	PKI_ALGOR_ID_ECDSA_SHA3_384,
# endif
# ifdef PKI_ALGOR_ID_ECDSA_SHA3_512
	PKI_ALGOR_ID_ECDSA_SHA3_512,
# endif
	PKI_ALGOR_ID_UNKNOWN
};
#else
PKI_ALGOR_ID PKI_ALGOR_ID_LIST_ECDSA[] = {
	PKI_ALGOR_ID_UNKNOWN
};
#endif

#ifdef ENABLE_OQS

PKI_ALGOR_ID PKI_ALGOR_ID_LIST_FALCON[] = {
	PKI_ALGOR_ID_FALCON512,
	PKI_ALGOR_ID_FALCON1024
};

PKI_ALGOR_ID PKI_ALGOR_ID_LIST_DILITHIUM[] = {
	PKI_ALGOR_ID_DILITHIUM2,
	PKI_ALGOR_ID_DILITHIUM3,
	PKI_ALGOR_ID_DILITHIUM5,
};

PKI_ALGOR_ID PKI_ALGOR_ID_LIST_SPHINCS[] = {
#ifdef NID_sphincssha2128fsimple
	PKI_ALGOR_ID_SPHINCS_SHA2_128_F,
#endif
#ifdef NID_sphincssha2128ssimple
	PKI_ALGOR_ID_SPHINCS_SHA2_128_S,
#endif
#ifdef NID_sphincssha2192fsimple
	PKI_ALGOR_ID_SPHINCS_SHA2_192_F,
#endif
#ifdef NID_sphincssha2192ssimple
	PKI_ALGOR_ID_SPHINCS_SHA2_192_S
#endif
};

PKI_ALGOR_ID PKI_ALGOR_ID_LIST_CLASSIC_MCELIECE[] = {
	PKI_ALGOR_ID_CLASSIC_MCELIECE1,
	PKI_ALGOR_ID_CLASSIC_MCELIECE2,
	PKI_ALGOR_ID_CLASSIC_MCELIECE3,
	PKI_ALGOR_ID_CLASSIC_MCELIECE4,
	PKI_ALGOR_ID_CLASSIC_MCELIECE5
};

PKI_ALGOR_ID PKI_ALGOR_ID_LIST_COMPOSITE_RSA_FALCON[] = {
	PKI_ALGOR_ID_COMPOSITE_RSA_FALCON512
};

PKI_ALGOR_ID PKI_ALGOR_ID_LIST_COMPOSITE_ECDSA_FALCON[] = {
	PKI_ALGOR_ID_COMPOSITE_ECDSA_FALCON512,
	PKI_ALGOR_ID_COMPOSITE_ECDSA_FALCON1024
};

PKI_ALGOR_ID PKI_ALGOR_ID_LIST_COMPOSITE_RSA_DILITHIUM[] = {
	PKI_ALGOR_ID_COMPOSITE_RSA_DILITHIUM2,
	PKI_ALGOR_ID_COMPOSITE_RSA_DILITHIUM2_AES
};

PKI_ALGOR_ID PKI_ALGOR_ID_LIST_COMPOSITE_ECDSA_DILITHIUM[] = {
	PKI_ALGOR_ID_COMPOSITE_ECDSA_DILITHIUM2,
	PKI_ALGOR_ID_COMPOSITE_ECDSA_DILITHIUM3,
	PKI_ALGOR_ID_COMPOSITE_ECDSA_DILITHIUM5,
	PKI_ALGOR_ID_COMPOSITE_ECDSA_DILITHIUM2_AES,
	PKI_ALGOR_ID_COMPOSITE_ECDSA_DILITHIUM3_AES,
	PKI_ALGOR_ID_COMPOSITE_ECDSA_DILITHIUM5_AES
};

// PKI_ALGOR_ID PKI_ALGOR_ID_LIST_COMPOSITE[] = {
// 	PKI_ALGOR_ID_COMPOSITE,
// 	PKI_ALGOR_ID_COMPOSITE_OR
// };

#endif

/* List of supported digest algorithms */
PKI_ALGOR_ID PKI_DIGEST_ALG_ID_LIST[] = {
//	PKI_ALGOR_MD2,
#ifndef OPENSSL_FIPS
	PKI_ALGOR_ID_MD4,
	PKI_ALGOR_ID_MD5,
	PKI_ALGOR_ID_DSS1,
#endif
	PKI_ALGOR_ID_SHA1,
	PKI_ALGOR_ID_SHA224,
	PKI_ALGOR_ID_SHA256,
	PKI_ALGOR_ID_SHA384,
	PKI_ALGOR_ID_SHA512,
	PKI_ALGOR_ID_RIPEMD128,
	PKI_ALGOR_ID_RIPEMD160,
	PKI_ALGOR_ID_SHA3_256,
	PKI_ALGOR_ID_SHA3_384,
	PKI_ALGOR_ID_SHA3_512,
	PKI_ALGOR_ID_SHAKE128,
	PKI_ALGOR_ID_SHAKE256,
	PKI_ALGOR_ID_UNKNOWN
};

PKI_X509_ALGOR_VALUE * PKI_X509_ALGOR_VALUE_new () {

	PKI_X509_ALGOR_VALUE *ret = NULL;
		// Return value

	// Allocates a new X509_ALGOR
	if ((ret = X509_ALGOR_new()) == NULL) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
	}

	// Success
	return ret;
}


void PKI_X509_ALGOR_VALUE_free(PKI_X509_ALGOR_VALUE *a) {

	// Input check
	if ( !a ) return;

	// Free the memory
	X509_ALGOR_free(a);

	// All Done
	return;
}

PKI_X509_ALGOR_VALUE * PKI_X509_ALGOR_VALUE_new_type ( int type ) {

	PKI_X509_ALGOR_VALUE *ret = NULL;
	  // Return Value

	// Input checks
	if (type <= 0) {
		PKI_ERROR(PKI_ERR_PARAM_RANGE, NULL);
		return NULL;
	}

	if (( ret = X509_ALGOR_new()) == NULL ) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	if (!X509_ALGOR_set0(ret, OBJ_nid2obj(type), V_ASN1_UNDEF, NULL)) {
		PKI_ERROR(PKI_ERR_ALGOR_GET, NULL);
		return NULL;
	}

	// All Done
	return ret;
}

PKI_X509_ALGOR_VALUE * PKI_X509_ALGOR_VALUE_new_pkey(const PKI_X509_KEYPAIR_VALUE * pkey, 
													 const PKI_ID                   digest_id) {

	PKI_X509_ALGOR_VALUE *ret = NULL;
	  // Return Value

	// Input Checks
	if (!pkey) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	if (digest_id < 0) {
		PKI_ERROR(PKI_ERR_PARAM_RANGE, NULL);
		return NULL;
	}

	// Checks we have a good digest_id
	if (digest_id > 0 && EVP_get_digestbynid(digest_id) == NULL) {
		PKI_DEBUG("Cannot get digest by NID (%d)", digest_id);
		return NULL;
	}

	// Gets the PKEY type
	const int pkey_type = PKI_X509_KEYPAIR_VALUE_get_id(pkey);
	if (!pkey_type) {
		PKI_DEBUG("Cannot get PKEY identifier/type from the PKEY");
		return NULL;
	}

	// Looks up the algorithm identifier
	int algor_id;
	if (!OBJ_find_sigid_by_algs(&algor_id, digest_id, pkey_type)) {
		PKI_DEBUG("Cannot find the algorithm identifier for the PKEY (digest: %d, pkey: %d)", 
			digest_id, pkey_type);
		return NULL;
	}

	ret = PKI_X509_ALGOR_VALUE_new_type(algor_id);
	if (!ret) {
		PKI_DEBUG("Cannot create a new X509_ALGOR_VALUE from the algorithm identifier (%d)", algor_id);
		return NULL;
	}

	// All Done
	return ret;
}

// PKI_X509_ALGOR_VALUE * PKI_X509_ALGOR_VALUE_new_digest ( PKI_DIGEST_ALG *alg ) {

// 	PKI_X509_ALGOR_VALUE *ret = NULL;
// 		// Pointer for returned item

// 	PKI_ID id = PKI_ID_UNKNOWN;
// 		// Identifier for the algorithm

// 	// Input checks
// 	if (!alg) return NULL;

// 	// Checks for the MD identifier
// 	if ((id = EVP_MD_nid(alg)) == NID_undef) return NULL;

// 	// Creates a new empty X509_ALGOR
// 	if ((ret = X509_ALGOR_new()) == NULL) {
// 		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
// 		return NULL;
// 	}

// 	if (!X509_ALGOR_set0(ret, OBJ_nid2obj(id), V_ASN1_UNDEF, NULL)) {
// 		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
// 		goto err;
// 	}

// 	// Success
// 	return ret;

// err:
// 	// Freeing allocated memory
// 	if (ret) X509_ALGOR_free ( ret );

// 	// Error Condition
// 	return NULL;
// }


PKI_X509_ALGOR_VALUE * PKI_X509_ALGOR_VALUE_get_by_name ( const char *alg_s ) {

	char *pnt, *data, *tk;
	char buf[1024];
	int i;

	PKI_ALGOR_ID alg_nid = PKI_ALGOR_ID_UNKNOWN;

	/* Check the argument */
	if (!alg_s) return (NULL);

	if ((data = strdup(alg_s)) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	for (i = 0; i < strlen(data); i++)
	{
		data[i] = (char) toupper(data[i]);
	}

	if (( tk = strtok_r ( data, "-", &pnt )) == NULL ) {
		// No '-' found in the algoritm, an error!
		PKI_Free ( data );
		return NULL;
	}

	if( strncmp_nocase(tk, "ECDSA", 5 ) == 0 ) {
		snprintf(buf, sizeof(buf), "ecdsa-with");
	} else {
		snprintf(buf, sizeof(buf), "%s", tk );
	}

	for ( tk = strtok_r ( NULL, "-", &pnt ); tk;
					tk = strtok_r ( NULL, "\r\n", &pnt )) {

		if ( tk == NULL ) break;
		snprintf(buf+strlen(buf), sizeof(buf) - strlen(buf) - strlen(tk),
			"-%s", tk );
	}

	// Check if the object is a valid OID
	if ((alg_nid = OBJ_sn2nid( buf )) <= 0) {

		// Checks the long name database for the OID
		if ((alg_nid = OBJ_ln2nid( buf )) <= 0) {

			// The text does not correspond to any known OID strings
			// return a NULL pointer
			return PKI_ALGOR_NULL;
		}
	}

	// Returns the pointer to the PKI_X509_ALGOR_VALUE structure
	return PKI_X509_ALGOR_VALUE_get(alg_nid);
}

char * PKI_ALGOR_ID_txt ( PKI_ALGOR_ID algor ) {
	ASN1_OBJECT *a = NULL;

	if(( a = OBJ_nid2obj( algor )) == NULL ) {
		return("Undefined");
	}

	ASN1_OBJECT_free( a );

	return( (char *)OBJ_nid2sn( algor ));
}

const char * PKI_X509_ALGOR_VALUE_get_parsed (const PKI_X509_ALGOR_VALUE * algor ) {

	int id;

	// Input Check
	if (!algor || !algor->algorithm) {
		// Error: We are Missing the Algorithm
		return NULL;
	}

	// Gets the NID from the object
	if ((id = OBJ_obj2nid(algor->algorithm)) == PKI_ALGOR_ID_UNKNOWN) {
		// Returns Nothing
		return ( NULL );
	}

	// Returns the Text Representation of the OID for the Algorithm
	return OBJ_nid2ln( id );
}

int PKI_SCHEME_ID_supports_multiple_components(PKI_SCHEME_ID id) {

	// Input checks
	if (id <= 0) return PKI_ERR;

#ifdef ENABLE_COMPOSITE
	if (PKI_SCHEME_ID_is_composite(id) == PKI_OK) return PKI_OK;
	if (PKI_SCHEME_ID_is_explicit_composite(id) == PKI_OK) return PKI_OK;
#endif

	// No multiple components supported
	return PKI_ERR;
}

int PKI_SCHEME_ID_is_composite(PKI_SCHEME_ID id) {

	// Input checks
	if (id <= 0) return PKI_ERR;

#ifdef ENABLE_COMPOSITE
	// Generic or Explicit
	if (id == PKI_SCHEME_COMPOSITE) {
		return PKI_OK;
	}
#endif
	
	// Neither
	return PKI_ERR;
}

int PKI_SCHEME_ID_is_explicit_composite(PKI_SCHEME_ID id) {

	// Input Checks
	if (id <= 0) return PKI_ERR;

	// Checks for Explicit Composite OIDs
	switch(id) {

#ifdef ENABLE_COMPOSITE
# if defined(ENABLE_OQS) || defined(ENABLE_OQSPROV)
		// Post Quantum Cryptography - Composite Crypto
		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSA:
		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_P256:
		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_BRAINPOOL256:
		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_ED25519:
		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_P384:
		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_BRAINPOOL384:
		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_ED448:
		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_P256:
		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_BRAINPOOL256:
		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_ED25519:
		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSAPSS:
		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_RSA:
		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_P521:
		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_RSA: {
			// Explicit Composite Combinations, nothing to do
		} break;
# endif
#endif

		default: {
			// Non-Explicit Composite Scheme detected
			return PKI_ERR;
		}
	}

	// All done
	return PKI_OK;
}

int PKI_SCHEME_ID_is_post_quantum(PKI_SCHEME_ID id) {

	// Input checks
	if (id <= 0) return PKI_ERR;

	switch (id) {

#if defined(ENABLE_OQS) || defined(ENABLE_OQSPROV)

		// Signature
		case PKI_SCHEME_DILITHIUM:
		case PKI_SCHEME_FALCON:
		case PKI_SCHEME_SPHINCS: {
			// Nothing to do
		} break;

		// KEMs
		case PKI_SCHEME_CLASSIC_MCELIECE:
		case PKI_SCHEME_KYBER: {
			// Nothing to do
		} break;

		// Experimental
		case PKI_SCHEME_BIKE:
		case PKI_SCHEME_DILITHIUMX3: {
			// Nothing to do
		} break;

#endif // End of ENABLE_OQS || ENABLE_OQSPROV

		default:
			// Non-Post Quantum
			return PKI_ERR;
	}

	// All Done
	return PKI_OK;
}

int PKI_SCHEME_ID_requires_digest(PKI_SCHEME_ID id) {

	// Input checks
	if (id <= 0) return PKI_ERR;

	// Composite, Combined, and Post-Quantum
	if (!PKI_SCHEME_ID_is_post_quantum(id) &&
		!PKI_SCHEME_ID_supports_multiple_components(id)) {

		// Classical Territory
		switch (id) {

			case PKI_SCHEME_RSAPSS:
			case PKI_SCHEME_ED25519:
			case PKI_SCHEME_ED448: {
				// No digest required
			} break;

			default:
				// Digest is required for all remaining
				// classical algorithm
				return PKI_OK;
		}
	}

	// No Digest Required
	return PKI_ERR;
}

const char * PKI_SCHEME_ID_get_parsed ( PKI_SCHEME_ID id ) {

	const char *ret;

	switch ( id ) {

		// ========================
		// Classic or Modern Crypto
		// ========================

		case PKI_SCHEME_RSA: {
			ret = "RSA";
		} break;

		case PKI_SCHEME_RSAPSS: {
			ret = "RSA-PSS";
		} break;

#ifdef ENABLE_ECDSA
		case PKI_SCHEME_ECDSA: {
			ret = "ECDSA";
		} break;
#endif
		case PKI_SCHEME_ED25519: {
			ret = "ED25519";
		} break;

		case PKI_SCHEME_X25519: {
			ret = "X25519";
		} break;

		case PKI_SCHEME_ED448: {
			ret = "ED448";
		} break;

		case PKI_SCHEME_X448: {
			ret = "X448";
		} break;

		case PKI_SCHEME_DSA: {
			ret = "DSA";
		} break;

		// ===================
		// Post-Quantum Crypto
		// ===================

#if defined(ENABLE_OQS) || defined (ENABLE_OQSPROV)

		case PKI_SCHEME_FALCON: {
			ret = "FALCON";
		} break;

		case PKI_SCHEME_DILITHIUM: {
			ret = "DILITHIUM";
		} break;

		case PKI_SCHEME_SPHINCS: {
			ret = "SPHINCS";
		} break;

		case PKI_SCHEME_CLASSIC_MCELIECE: {
			ret = "MCELIECE";
		} break;

		// =========================
		// Post-Quantum Experimental
		// =========================

		case PKI_SCHEME_DILITHIUMX3: {
			ret = "DILITHIUMX3";
		} break;

#endif // End of ENABLE_OQS || ENABLE_OQSPROV

#ifdef ENABLE_COMPOSITE

		// =====================
		// Composite (PQ) Crypto
		// =====================

		case PKI_SCHEME_COMPOSITE: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_NAME;
		} break;

# if defined(ENABLE_OQS) || defined(ENABLE_OQSPROV)

		// =========================
		// Composite: Generic and PQ
		// =========================

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSA: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_SHA256_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_P256: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_P256_SHA256_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_BRAINPOOL256: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_BRAINPOOL256_SHA256_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_ED25519: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ED25519_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_P384: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_P384_SHA384_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_BRAINPOOL384: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_BRAINPOOL384_SHA384_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_ED448: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_ED448_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_P256: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_P256_SHA256_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_BRAINPOOL256: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_BRAINPOOL256_SHA256_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_ED25519: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_NAME;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSAPSS: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSAPSS_SHA256_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_RSA: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_RSA_SHA256_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_P521: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_P521_SHA512_NAME;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_RSA: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_RSA_SHA256_NAME;
		} break;

# endif

# ifdef ENABLE_COMBINED
		case PKI_SCHEME_COMPOSITE_OR: {
			ret = "MULTIKEY";
		} break;
# endif

#endif

		default: {
			ret = "Unknown";
		} break;
	};

	return ret;
}

int PKI_SCHEME_ID_get_bitsize(const PKI_SCHEME_ID scheme_id, const int sec_bits) {

	int ret = 0;
	int scheme_sec_bits = 0;
	  // Return value

	// Input checks
	if (scheme_id <= 0) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return -1;
	}

	// Let's get the default security bits for
	// the scheme. If we get a positive value,
	// the scheme only support that size and we
	// return that. 
	//
	// Otherwise we will return the/ bits value
	// from the combination of the input 
	// (scheme/sec_bits)
	if (PKI_ERR == PKI_SCHEME_ID_security_bits(scheme_id, &scheme_sec_bits, NULL)) {
		PKI_DEBUG("Can not get security bits for scheme %d", scheme_id);
		return -1;
	}
	
	// If the returned value is positive, it means the
	// scheme only supports a single value for the size,
	// we return that value.
	if (scheme_sec_bits > 0) {
		return scheme_sec_bits;
	}

	// If the scheme supports more than one value (i.e., -1),
	// it means that we need to look in the switch below.
	switch (scheme_id) {

		case PKI_SCHEME_DSA: {
			     if (sec_bits < 112) { ret = 1024; }
			else if (sec_bits < 128) { ret = 2048; }
			else if (sec_bits == 128) { ret = 3072; }
			else { 
				PKI_DEBUG("Security Bits value not supported (%d)", sec_bits);
				return -1;
			}
		} break;

		case PKI_SCHEME_RSA: {
			// Sec sec_bits Sizes
				 if (sec_bits < 50 ) { ret = 32; }
			else if (sec_bits < 80 ) { ret = 512; }
			else if (sec_bits < 96 ) { ret = 1024; }
			else if (sec_bits < 112 ) { ret = 1536; }
			// Acceptable bit sizes
			else if (sec_bits < 128 ) { ret = 2048; }
			else if (sec_bits < 140 ) { ret = 3072; }
			else if (sec_bits < 192 ) { ret = 4096; }
			// Over the top bit sizes
			else if (sec_bits < 256 ) { ret = 7680; }
			else if (sec_bits == 256 ) { ret = 15360; }
			else { 
				PKI_DEBUG("Security Bits value not supported (%d)", sec_bits);
				return -1;
			 }
		} break;

		case PKI_SCHEME_ECDSA: {
				 if (sec_bits < 128) { ret = 224; } 
			else if (sec_bits < 192) { ret = 256; } 
			else if (sec_bits < 256) { ret = 384; }
			else if (sec_bits == 256) { ret = 521; }
			else { 
				PKI_DEBUG("Security Bits value not supported (%d)", sec_bits);
				return -1;
			}
		} break;

		case PKI_SCHEME_ED448:
		case PKI_SCHEME_X448: {
			if (sec_bits <= 224) { ret = 448; }
			else { 
				PKI_DEBUG("Security Bits value not supported (%d)", sec_bits);
				return -1;
			}
		}

		case PKI_SCHEME_ED25519:
		case PKI_SCHEME_X25519: {
			if (sec_bits <= 128) { ret = 255; }
			else { 
				PKI_DEBUG("Security Bits value not supported (%d)", sec_bits);
				return -1;
			}
		}

#ifdef ENABLE_COMPOSITE

		// =============================
		// Native Composite Cryptography
		// =============================

		case PKI_SCHEME_COMPOSITE: {
			// No need to translate, same sec bits for
			// the generation of all components, if they
			// support it.
			ret = -1;
		} break;
#endif

#ifdef ENABLE_COMBINED
		case PKI_SCHEME_COMBINED: {
			// No need to translate, output the input
			ret = sec_bits;
		} break;
#endif

#if defined(ENABLE_OQS) || defined(ENABLE_OQSPROV)

		// =============================================
		// Post Quantum Cryptography: Digital Signatures
		// =============================================

		case PKI_SCHEME_FALCON: {
			     if (sec_bits <= 128) { ret = 897; }
			else if (sec_bits <= 256) { ret = 1793; }
			else { 
				PKI_DEBUG("Security Bits value not supported (%d)", sec_bits);
				return -1;
			}
		} break;
		
		case PKI_SCHEME_DILITHIUM: {
			     if (sec_bits <= 128) { ret = 1312; }
			else if (sec_bits <= 192) { ret = 1953; } 
			else if (sec_bits <= 256) {	ret = 2593; }
			else { 
				PKI_DEBUG("Security Bits value not supported (%d)", sec_bits);
				return -1;
			}
		} break;

		// TODO: We need to change from the robust to the
		//       fast implementations as the robust is not
		//       going to be standardized
		case PKI_SCHEME_SPHINCS: {
				 if (sec_bits <= 128) { ret = 32; } 
			else if (sec_bits <= 192) {	ret = 32; }
			else if (sec_bits <= 256) {	ret = 32; }
			else { 
				PKI_DEBUG("Security Bits value not supported (%d)", sec_bits);
				return -1;
			}
		} break;

		case PKI_SCHEME_KYBER: {
			     if (sec_bits <= 128) { ret = 800; } 
			else if (sec_bits <= 192) {	ret = 1184; }
			else if (sec_bits <= 256) {	ret = 1568; }
			else { 
				PKI_DEBUG("Security Bits value not supported (%d)", sec_bits);
				return -1;
			}
		} break;

#ifdef ENABLE_COMPOSITE

		// ===============================
		// Explicit Composite Combinations
		// ===============================

		// Explicit Composite Crypto Schemes
		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSA: {
			// kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_SHA256_NAME);
			ret = (1953 + 400) * 8;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSAPSS: {
			// kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSAPSS_SHA256_NAME);
			ret = (1953 + 400);
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_P256: {
			// kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_P256_SHA256_NAME);
			ret = (1953 + 32) * 8;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_BRAINPOOL256: {
			// kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_BRAINPOOL256_SHA256_NAME);
			ret = (1953 + 32) * 8;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_ED25519: {
			// kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ED25519_NAME);
			ret = (1953 + 32) * 8;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_P384: {
			// kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_P384_SHA384_NAME);
			ret = (2593 + 48) * 8;
		} break;
		
		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_BRAINPOOL384: {
			// kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_BRAINPOOL384_SHA384_NAME);
			ret = (2593 + 48) * 8;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_ED448: {
			// kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_ED448_NAME);
			ret = (2593 + 57) * 8;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_P256: {
			// kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_P256_SHA256_NAME);
			ret = (897 + 32) * 8;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_BRAINPOOL256: {
			// kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_BRAINPOOL256_SHA256_NAME);
			ret = (897 + 32) * 8;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_ED25519: {
			// kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_NAME);
			ret = (897 + 32) * 8;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_RSA: {
			// kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_RSA_SHA256_NAME);
			ret = (897 + 32) * 8;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_P521: {
			// kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_P521_SHA512_NAME);
			ret = (2593 + 64) * 8;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_RSA: {
			// kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_RSA_SHA256_NAME);
			ret = (2593 + 64 + 400) * 8;
		} break;

#endif // End of ENABLE_COMPOSITE
#endif // End of ENABLE_OQS || ENABLE_OQSPROV

		default: {
			// Sets the sec_bits
			PKI_ERROR(PKI_ERR_ALGOR_UNKNOWN, "Scheme not supported (%d)", scheme_id);
			return PKI_ERR;
		}
	}

	// All Done
	return ret;
}

int PKI_SCHEME_ID_security_bits(const PKI_SCHEME_ID   scheme_id, 
                                int                 * classic_sec_bits, 
                                int                 * quantum_sec_bits) {

	// Input Checks
	if (scheme_id <= 0) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_SCHEME_UNKNOWN;
	}

	// if (classic_sec_bits) *classic_sec_bits = 0;
	// if (quantum_sec_bits) *quantum_sec_bits = 0;

	// PKI_DEBUG("Getting Security Bits for Scheme %d", scheme_id);

	switch (scheme_id) {

		// Classic/Modern Cryptography
		case PKI_SCHEME_UNKNOWN: {
			if (classic_sec_bits) *classic_sec_bits = -1;
			if (quantum_sec_bits) *quantum_sec_bits = -1;
		} break;

		case PKI_SCHEME_RSA: {
			if (classic_sec_bits) *classic_sec_bits = -1;
			if (quantum_sec_bits) *quantum_sec_bits = -1;
		} break;

		case PKI_SCHEME_RSAPSS: {
			if (classic_sec_bits) *classic_sec_bits = -1;
			if (quantum_sec_bits) *quantum_sec_bits = -1;
		} break;

		case PKI_SCHEME_DSA: {
			if (classic_sec_bits) *classic_sec_bits = -1;
			if (quantum_sec_bits) *quantum_sec_bits = -1;
		} break;

#ifdef ENABLE_ECDSA
		// ECDSA signature scheme
		case PKI_SCHEME_ECDSA: {
			if (classic_sec_bits) *classic_sec_bits = -1;
			if (quantum_sec_bits) *quantum_sec_bits = -1;
		} break;

#endif

		// ED signature schemes
		case PKI_SCHEME_ED448: {
			if (classic_sec_bits) *classic_sec_bits = 224;
			if (quantum_sec_bits) *quantum_sec_bits = 0;
		} break;

		case PKI_SCHEME_ED25519: {
			if (classic_sec_bits) *classic_sec_bits = 128;
			if (quantum_sec_bits) *quantum_sec_bits = 0;
		} break;

		// Key-Exchange based on Diffie-Hellman
		case PKI_SCHEME_DH: {
			if (classic_sec_bits) *classic_sec_bits = -1;
			if (quantum_sec_bits) *quantum_sec_bits = -1;
		} break;

		// Key-Exchange based on ED
		case PKI_SCHEME_X448: {
			if (classic_sec_bits) *classic_sec_bits = 224;
			if (quantum_sec_bits) *quantum_sec_bits = 0;
		} break;

		case PKI_SCHEME_X25519: {
			if (classic_sec_bits) *classic_sec_bits = 128;
			if (quantum_sec_bits) *quantum_sec_bits = 0;
		} break;

#if defined(ENABLE_OQS) || defined(ENABLE_OQSPROV)

		// Post Quantum Cryptography - KEMS

		case PKI_SCHEME_BIKE: {
			if (classic_sec_bits) *classic_sec_bits = -1;
			if (quantum_sec_bits) *quantum_sec_bits = -1;
		} break;

		case PKI_SCHEME_FRODOKEM: {
			if (classic_sec_bits) *classic_sec_bits = -1;
			if (quantum_sec_bits) *quantum_sec_bits = -1;
		} break;

		case PKI_SCHEME_CLASSIC_MCELIECE: {
			if (classic_sec_bits) *classic_sec_bits = -1;
			if (quantum_sec_bits) *quantum_sec_bits = -1;
		} break;

		case PKI_SCHEME_KYBER: {
			if (classic_sec_bits) *classic_sec_bits = -1;
			if (quantum_sec_bits) *quantum_sec_bits = -1;
		} break;

		// Post Quantum Cryptography - Digital Signatures

		case PKI_SCHEME_FALCON: {
			if (classic_sec_bits) *classic_sec_bits = -1;
			if (quantum_sec_bits) *quantum_sec_bits = -1;
		} break;

		case PKI_SCHEME_SPHINCS: {
			if (classic_sec_bits) *classic_sec_bits = -1;
			if (quantum_sec_bits) *quantum_sec_bits = -1;
		} break;

		case PKI_SCHEME_DILITHIUM: {
			if (classic_sec_bits) *classic_sec_bits = -1;
			if (quantum_sec_bits) *quantum_sec_bits = -1;
		} break;

		// Experimental Only - To Be Removed (DilithiumX)
		case PKI_SCHEME_DILITHIUMX3:  {
			if (classic_sec_bits) *classic_sec_bits = 192;
			if (quantum_sec_bits) *quantum_sec_bits = 192;
		} break;

#endif // End of ENABLE_OQS || ENABLE_OQSPROV

#ifdef ENABLE_COMPOSITE
		// Composite Crypto Schemes
		case PKI_SCHEME_COMPOSITE:  {
			if (classic_sec_bits) *classic_sec_bits = -1;
			if (quantum_sec_bits) *quantum_sec_bits = -1;
		} break;

#if defined(ENABLE_OQS) || defined(ENABLE_OQSPROV)

		// Explicit Composite Crypto Schemes
		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSA:  {
			if (classic_sec_bits) *classic_sec_bits = max(192, 128);
			if (quantum_sec_bits) *quantum_sec_bits = max(192, 0);
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_P256:  {
			if (classic_sec_bits) *classic_sec_bits = max(192, 128);
			if (quantum_sec_bits) *quantum_sec_bits = max(192, 0);
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_BRAINPOOL256:  {
			if (classic_sec_bits) *classic_sec_bits = max(192, 256);
			if (quantum_sec_bits) *quantum_sec_bits = max(192, 0);
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_ED25519:  {
			if (classic_sec_bits) *classic_sec_bits = max(192, 128);
			if (quantum_sec_bits) *quantum_sec_bits = max(192, 0);
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_P384:  {
			if (classic_sec_bits) *classic_sec_bits = max(256, 384);
			if (quantum_sec_bits) *quantum_sec_bits = max(256, 0);
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_BRAINPOOL384:  {
			if (classic_sec_bits) *classic_sec_bits = max(256, 384);
			if (quantum_sec_bits) *quantum_sec_bits = max(256, 0);
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_ED448:  {
			if (classic_sec_bits) *classic_sec_bits = max(256, 224);
			if (quantum_sec_bits) *quantum_sec_bits = max(256, 0);
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_P256:  {
			if (classic_sec_bits) *classic_sec_bits = max(256, 256);
			if (quantum_sec_bits) *quantum_sec_bits = max(256, 0);
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_BRAINPOOL256:  {
			if (classic_sec_bits) *classic_sec_bits = max(256, 256);
			if (quantum_sec_bits) *quantum_sec_bits = max(256, 0);
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_ED25519:  {
			if (classic_sec_bits) *classic_sec_bits = max(256, 128);
			if (quantum_sec_bits) *quantum_sec_bits = max(256, 0);
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSAPSS:  {
			if (classic_sec_bits) *classic_sec_bits = max(192, 128);
			if (quantum_sec_bits) *quantum_sec_bits = max(192, 0);
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_RSA:  {
			if (classic_sec_bits) *classic_sec_bits = max(128, 128);
			if (quantum_sec_bits) *quantum_sec_bits = max(128, 0);
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_P521: {
			if (classic_sec_bits) *classic_sec_bits = max(max(256, 256), max(256, 521));
			if (quantum_sec_bits) *quantum_sec_bits = max(max(256, 256), max(256, 0));
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_RSA: {
			if (classic_sec_bits) *classic_sec_bits = max(max(256, 256), max(256, 128));
			if (quantum_sec_bits) *quantum_sec_bits = max(max(256, 256), max(256, 0));
		} break;

#endif // End of ENABLE_OQS || ENABLE_OQSPROV
#endif // End of ENABLE_COMPOSITE

#ifdef ENABLE_COMBINED
		// Combined Crypto Schemes
		case PKI_SCHEME_COMBINED:  {
			if (classic_sec_bits) *classic_sec_bits = -1;
			if (quantum_sec_bits) *quantum_sec_bits = -1;
		} break;

#endif

		default:
			PKI_DEBUG("ERROR, unknown scheme (%d)", scheme_id);
			return PKI_ERR;	
	}

	// All Done
	return PKI_OK;
}

PKI_SCHEME_ID PKI_SCHEME_ID_get_by_name(const char * data, int *classic_sec_bits, int *quantum_sec_bits) {

	PKI_SCHEME_ID ret = PKI_SCHEME_UNKNOWN;
		// Return value

	int default_sec_bits = 1;
		// If set to 1, the function will return the default
		// security bits for the given scheme

	// Input Checks
	if (!data) {
		if (classic_sec_bits) *classic_sec_bits = 0;
		if (quantum_sec_bits) *quantum_sec_bits = 0;
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_SCHEME_UNKNOWN;
	}

#ifdef ENABLE_COMPOSITE

	// Generic Composite
	if (ret == PKI_SCHEME_UNKNOWN) {
		if (str_cmp_ex(data, "COMPOSITE", 0, 1) == 0) {
			ret = PKI_SCHEME_COMPOSITE;
		}
	}

#if defined(ENABLE_OQS) || defined (ENABLE_OQSPROV)

	// Explicit Composite
	if (ret == PKI_SCHEME_UNKNOWN) {
		// Explicit Composite - DILITHIUM3-P256
		if (str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_P256_SHA256_OID, 0, 1) == 0 ||
			str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_P256_SHA256_NAME, 0, 1) == 0 ||
			str_cmp_ex(data, "DILITHIUM3-ECDSA", 0, 1) == 0 ||
			str_cmp_ex(data, "DILITHIUM3-EC", 0, 1) == 0 ||
			str_cmp_ex(data, "DILITHIUM3-P256", 0, 1) == 0 ||
			str_cmp_ex(data, "D3-P256", 0, 1) == 0 ||
			str_cmp_ex(data, "DILITHIUM-P256", 0, 1) == 0) {
			ret = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_P256;
		// Explicit Composite - DILITHIUM3-RSA
		} else if (str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_SHA256_OID, 0, 1) == 0 ||
					str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_SHA256_NAME, 0, 1) == 0 ||
					str_cmp_ex(data, "DILITHIUM-RSA", 0, 1) == 0 ||
					str_cmp_ex(data, "D3-RSA", 0, 1) == 0 ||
					str_cmp_ex(data, "DILITHIUM3-RSA", 0, 1) == 0) {
			ret = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSA;
		// Explicit Composite - DILITHIUM3-BRAINPOOL256
		} else if (str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_BRAINPOOL256_SHA256_OID, 0, 1) == 0 || 
					str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_BRAINPOOL256_SHA256_NAME, 0, 1) == 0 || 
					str_cmp_ex(data, "DILITHIUM-BRAINPOOL", 0, 1) == 0 ||
					str_cmp_ex(data, "DILITHIUM3-BRAINPOOL", 0, 1) == 0 ||
					str_cmp_ex(data, "D3-B256", 0, 1) == 0 ||
					str_cmp_ex(data, "DILITHIUM3-B256", 0, 1) == 0) {
			ret = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_BRAINPOOL256;
		} else if (str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ED25519_OID, 0, 1) == 0 || 
					str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ED25519_NAME, 0, 1) == 0 || 
					str_cmp_ex(data, "DILITHIUM-ED25519", 0, 1) == 0 ||
					str_cmp_ex(data, "DILITHIUM-25519", 0, 1) == 0 ||
					str_cmp_ex(data, "DILITHIUM3-ED25519", 0, 1) == 0 ||
					str_cmp_ex(data, "DILITHIUM3-25519", 0, 1) == 0 ||
					str_cmp_ex(data, "D3-ED25519", 0, 1) == 0 ||
					str_cmp_ex(data, "D3-25519", 0, 1) == 0 ||
					str_cmp_ex(data, "DILITHIUM3-25519", 0, 1) == 0) {
			ret = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_ED25519;
		} else if (str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_P384_SHA384_OID, 0, 1) == 0 || 
					str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_P384_SHA384_NAME, 0, 1) == 0 || 
					str_cmp_ex(data, "DILITHIUM5-ECDSA", 0, 1) == 0 ||
					str_cmp_ex(data, "DILITHIUM5-EC", 0, 1) == 0 ||
					str_cmp_ex(data, "DILITHIUM-P384", 0, 1) == 0 ||
					str_cmp_ex(data, "D5-P384", 0, 1) == 0 ||
					str_cmp_ex(data, "D5-ECDSA", 0, 1) == 0 ||
					str_cmp_ex(data, "DILITHIUM5-P384", 0, 1) == 0) {
			ret = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_P384;
		} else if (str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_BRAINPOOL384_SHA384_OID, 0, 1) == 0 || 
					str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_BRAINPOOL384_SHA384_NAME, 0, 1) == 0 || 
					str_cmp_ex(data, "DILITHIUM5-BRAINPOOL", 0, 1) == 0 ||
					str_cmp_ex(data, "D5-B384", 0, 1) == 0 ||
					str_cmp_ex(data, "DILITHIUM5-B384", 0, 1) == 0) {
			ret = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_BRAINPOOL384;
		} else if (str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_ED448_OID, 0, 1) == 0 || 
					str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_ED448_NAME, 0, 1) == 0 || 
					str_cmp_ex(data, "DILITHIUM5-448", 0, 1) == 0 ||
					str_cmp_ex(data, "DILITHIUM-ED448", 0, 1) == 0 ||
					str_cmp_ex(data, "D5-ED448", 0, 1) == 0 ||
					str_cmp_ex(data, "DILITHIUM-448", 0, 1) == 0) {
			ret = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_ED448;
		} else if (str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_P256_SHA256_OID, 0, 1) == 0 || 
					str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_P256_SHA256_NAME, 0, 1) == 0 || 
					str_cmp_ex(data, "FALCON512-P256", 0, 1) == 0 || 
					str_cmp_ex(data, "FALCON-ECDSA", 0, 1) == 0 || 
					str_cmp_ex(data, "F512-ECDSA", 0, 1) == 0 || 
					str_cmp_ex(data, "F512-P256", 0, 1) == 0 || 
					str_cmp_ex(data, "FALCON-P256", 0, 1) == 0) {
			ret = PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_P256;
		} else if (str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_BRAINPOOL256_SHA256_OID, 0, 1) == 0 || 
					str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_BRAINPOOL256_SHA256_NAME, 0, 1) == 0 || 
					str_cmp_ex(data, "FALCON512-BRAINPOOL", 0, 1) == 0 || 
					str_cmp_ex(data, "FALCON-BRAINPOOL256", 0, 1) == 0 || 
					str_cmp_ex(data, "F512-B256", 0, 1) == 0 || 
					str_cmp_ex(data, "FALCON-BRAINPOOL", 0, 1) == 0) {
			ret = PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_BRAINPOOL256;
		} else if (str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_OID, 0, 1) == 0 ||
					str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_NAME, 0, 1) == 0 || 
					str_cmp_ex(data, "FALCON512-25519", 0, 1) == 0 || 
					str_cmp_ex(data, "FALCON-ED25519", 0, 1) == 0 || 
					str_cmp_ex(data, "F512-ED25519", 0, 1) == 0 || 
					str_cmp_ex(data, "FALCON-25519", 0, 1) == 0) {
			return PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_ED25519;
		// } else if (str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_P256_SHA256_OID, 0, 1) == 0 || 
		// 			str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_P256_SHA256_NAME, 0, 1) == 0 || 
		// 			str_cmp_ex(data, "SPHINCS256-ECDSA", 0, 1) == 0 || 
		// 			str_cmp_ex(data, "SPHINCS-ECDSA", 0, 1) == 0 || 
		// 			str_cmp_ex(data, "SPHINCS-P256", 0, 1) == 0) {
		// 	return PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_ED25519;
		} else if (str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSAPSS_SHA256_OID, 0, 1) == 0 || 
					str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSAPSS_SHA256_NAME, 0, 1) == 0 || 
					str_cmp_ex(data, "DILITHIUM3-RSAPSS", 0, 1) == 0 || 
					str_cmp_ex(data, "D3-RSAPSS", 0, 1) == 0 || 
					str_cmp_ex(data, "DILITHIUM-RSAPSS", 0, 1) == 0) {
			ret = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSAPSS;
		} else if (str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_RSA_SHA256_OID, 0, 1) == 0 || 
					str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_RSA_SHA256_NAME, 0, 1) == 0 || 
					str_cmp_ex(data, "FALCON-RSA", 0, 1) == 0 ||
					str_cmp_ex(data, "F512-RSA", 0, 1) == 0 ||
					str_cmp_ex(data, "FALCON512-RSA", 0, 1) == 0) {
			ret = PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_RSA;
		// Explicit Composite - DILITHIUM5-FALCON1024-ECDSA-P521
		} else if (str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_P521_SHA512_OID, 0, 1) == 0 ||
					str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_P521_SHA512_NAME, 0, 1) == 0 ||
					str_cmp_ex(data, "DILITHIUM-FALCON-EC", 0, 1) == 0 ||
					str_cmp_ex(data, "D5-F1024-P521", 0, 1) == 0 ||
					str_cmp_ex(data, "DILITHIUM5-FALCON1024-P521", 0, 1) == 0 ||
					str_cmp_ex(data, "DILITHIUM-FALCON-P521", 0, 1) == 0) {
			ret = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_P521;
		// Explicit Composite - DILITHIUM5-FALCON1024-ECDSA-RSA
		} else if (str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_RSA_SHA256_OID, 0, 1) == 0 ||
					str_cmp_ex(data, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_RSA_SHA256_NAME, 0, 1) == 0 ||
					str_cmp_ex(data, "DILITHIUM-FALCON-RSA", 0, 1) == 0 ||
					str_cmp_ex(data, "D5-F1024-RSA", 0, 1) == 0 ||
					str_cmp_ex(data, "DILITHIUM5-FALCON1024-RSA", 0, 1) == 0) {
			ret = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_RSA;
		}
	}
#endif // End of ENABLE_OQS

#endif // End of ENABLE_COMPOSITE

#if defined(ENABLE_OQS) || defined(ENABLE_OQSPROV)
	if (ret == PKI_SCHEME_UNKNOWN) {
		if (str_cmp_ex(data, "DILITHIUMX3", 0, 1) == 0) { 
			ret = PKI_SCHEME_DILITHIUMX3;
		} else if (str_cmp_ex(data, "DILITHIUM2", 0, 1) == 0) {
			default_sec_bits = 0;
			if (classic_sec_bits) *classic_sec_bits = 128;
			if (quantum_sec_bits) *quantum_sec_bits = 128;
			ret = PKI_SCHEME_DILITHIUM;
		} else if (str_cmp_ex(data, "DILITHIUM3", 0, 1) == 0) {
			default_sec_bits = 0;
			if (classic_sec_bits) *classic_sec_bits = 192;
			if (quantum_sec_bits) *quantum_sec_bits = 192;
			ret = PKI_SCHEME_DILITHIUM;
		} else if (str_cmp_ex(data, "DILITHIUM5", 0, 1) == 0) {
			default_sec_bits = 0;
			if (classic_sec_bits) *classic_sec_bits = 256;
			if (quantum_sec_bits) *quantum_sec_bits = 256;
			ret = PKI_SCHEME_DILITHIUM;
		} else if (str_cmp_ex(data, "DILITHIUM", 0, 1) == 0) {
			ret = PKI_SCHEME_DILITHIUM;
		} else if (str_cmp_ex(data, "FALCON512", 0, 1) == 0) {
			default_sec_bits = 0;
			if (classic_sec_bits) *classic_sec_bits = 128;
			if (quantum_sec_bits) *quantum_sec_bits = 128;
			ret = PKI_SCHEME_FALCON;
		} else if (str_cmp_ex(data, "FALCON1024", 0, 1) == 0) {
			default_sec_bits = 0;
			if (classic_sec_bits) *classic_sec_bits = 256;
			if (quantum_sec_bits) *quantum_sec_bits = 256;
			ret = PKI_SCHEME_FALCON;
		} else if (str_cmp_ex(data, "FALCON", 0, 1) == 0) {
			ret = PKI_SCHEME_FALCON;
		} else if (str_cmp_ex(data, "KYBER", 0, 1) == 0) {
			ret = PKI_SCHEME_KYBER;
		}
	}
#endif

	// Checks for Traditional Crypto
	// =============================
	
	if (ret == PKI_SCHEME_UNKNOWN) {
		// RSA Option
		if (str_cmp_ex(data, "RSA", 0, 1) == 0) {
			ret = PKI_SCHEME_RSA;
		// RSA-PSS Option
		} else if (str_cmp_ex(data, "RSAPSS", 0, 1) == 0 ||
				str_cmp_ex(data, "RSA-PSS", 0, 1) == 0) {
			ret = PKI_SCHEME_RSAPSS;

#ifdef ENABLE_ECDSA
		// ED 25519 Option
		} else if (str_cmp_ex(data, "ED25519", 0, 1) == 0) {
			ret = PKI_SCHEME_ED25519;
		// X25519 Option
		} else if (str_cmp_ex(data, "X25519", 0, 1) == 0) {
			ret = PKI_SCHEME_X25519;
		// ED 448 Option
		} else if (str_cmp_ex(data, "ED448", 0, 1) == 0) {
			ret = PKI_SCHEME_ED448;
		// X448 Option
		} else if (str_cmp_ex(data, "X448", 0, 1) == 0) {
			ret = PKI_SCHEME_X448;
		// EC Option
		} else if (str_cmp_ex(data, "EC", 0, 1) == 0 ||
				str_cmp_ex(data, "ECDSA", 0, 1) == 0 ||
				str_cmp_ex(data, "B128", 0, 1) == 0 ||
				str_cmp_ex(data, "B192", 0, 1) == 0 ||
				str_cmp_ex(data, "B256", 0, 1) == 0 ||
				str_cmp_ex(data, "Brainpool", 9, 1) == 0 ||
				str_cmp_ex(data, "P256", 0, 1) == 0 ||
				str_cmp_ex(data, "P384", 0, 1) == 0 ||
				str_cmp_ex(data, "P512", 0, 1) == 0) {
			ret = PKI_SCHEME_ECDSA;
#endif // End of ENABLE_ECDSA

		// DSA
		} else if (str_cmp_ex(data, "DSA", 0, 1) == 0) {
			ret = PKI_SCHEME_DSA;
		}
	}

	// Checks if we found the scheme
	if (ret == PKI_SCHEME_UNKNOWN) {
		// Some debugging
		PKI_DEBUG("Cannot Convert [%s] into a recognized OID.", data);
	} else {
		// Checks if we need to retrieve the default security bits
		if (default_sec_bits) {
			// Returns the security bits for the scheme
			if (PKI_ERR == PKI_SCHEME_ID_security_bits(ret, classic_sec_bits, quantum_sec_bits)) {
				PKI_DEBUG("Cannot get security bits for scheme %d", ret);
				return PKI_SCHEME_UNKNOWN;
			}
		}
	}

	// Returns the scheme
	return ret;
}


/*!
 * \brief Build a PKI_ALGOR structure from its ID
 */

PKI_X509_ALGOR_VALUE * PKI_X509_ALGOR_VALUE_get(PKI_ALGOR_ID algor) {

	// Input Checks
	if (algor <= 0) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, "No Algorithm ID provided!");
		return NULL;
	}

	// Let's return the PKIX X509 Algorithm Data structure
	return PKI_X509_ALGOR_VALUE_new_type(algor);
}

// /*!
//  * \brief Build a PKI_ALGOR structure from its ID
//  */

// PKI_X509_ALGOR_VALUE * PKI_X509_ALGOR_VALUE_get_ex(PKI_ALGOR_ID pubkey_id, PKI_ALGOR_ID digest_id) {

// 	int alg_nid = PKI_ALGOR_ID_UNKNOWN;
// 	  // Algorithm Identifier

// 	// Input Checks
// 	if (pubkey_id <= 0) {
// 		PKI_ERROR(PKI_ERR_PARAM_NULL, "No Algorithm ID provided!");
// 		return NULL;
// 	}
// 	if (!EVP_get_digestbynid(digest_id)) {
// 		PKI_ERROR(PKI_ERR_ALGOR_UNKNOWN, "ERROR, Digest Algorithm ID unknown (%d)", digest_id);
// 		return NULL;
// 	}

// 	// Gets the combined algorithm ID
// 	if (!OBJ_find_sigid_by_algs(&alg_nid, digest_id, pubkey_id)) {
// 		PKI_DEBUG("Cannot find an algorithm for the pubkey (%d) and hash (%d) combination",
// 			pubkey_id, digest_id);
// 		return NULL;
// 	}

// 	// Let's return the PKIX X509 Algorithm Data structure
// 	return PKI_X509_ALGOR_VALUE_new_type(alg_nid);
// }

/* ! \brief Get a PKI_ALGOR from an PKI_ALGOR object */

PKI_ALGOR_ID PKI_X509_ALGOR_VALUE_get_id(const PKI_X509_ALGOR_VALUE *algor ) {

	// Input Checks
	if (!algor || !algor->algorithm) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ALGOR_ID_UNKNOWN;
	}

	// Gets the Algorithm Id
	return OBJ_obj2nid(algor->algorithm);
}

/*! 
 * \brief Get the Digest Algorithm from the passed PKI_ALGOR
 */
const PKI_DIGEST_ALG *PKI_X509_ALGOR_VALUE_get_digest(const PKI_X509_ALGOR_VALUE *algor) {

	PKI_ALGOR_ID digest_id = PKI_ID_UNKNOWN;
		// Digest Identifier

	// Input checks
	if (!algor) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	// Retrieves the digest id
	digest_id = PKI_X509_ALGOR_VALUE_get_digest_id(algor);

	// If nothing was found, let's return nothing
	if (digest_id == NID_undef) return EVP_md_null();

	// All Done
	return EVP_get_digestbynid(digest_id);
}

/*! 
 * \brief Returns the PKI_ALGOR_ID of the digest used in the PKI_ALGOR
 */
PKI_ALGOR_ID PKI_X509_ALGOR_VALUE_get_digest_id(const PKI_X509_ALGOR_VALUE *algor) {

	int alg_id = -1;
	int pkey_id = -1;
	int digest_id = -1;
		// Algorithm Identifiers 

	if ( !algor || !algor->algorithm ) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ALGOR_ID_UNKNOWN;
	}

	// Retrieves the Algorithm ID
	if((alg_id = PKI_X509_ALGOR_VALUE_get_id(algor)) <= 0) {
		PKI_ERROR(PKI_ERR_ALGOR_UNKNOWN, NULL);
		return PKI_ALGOR_ID_UNKNOWN;
	}

	// Gets the MD and PKEY components
	if (!OBJ_find_sigid_algs(alg_id, &digest_id, &pkey_id)) {
		PKI_DEBUG("Cannot break the signing algorithm (%d) into PKEY and MD (algor: %s).", 
			alg_id, PKI_X509_ALGOR_VALUE_get_parsed(algor));
		return PKI_ALGOR_ID_UNKNOWN;
	}

	// All Done
	return digest_id;
}

/*! \brief Returns the PKI_SCHEME_ID (signature scheme ID) of the algorithm */
PKI_SCHEME_ID PKI_X509_ALGOR_VALUE_get_scheme (const PKI_X509_ALGOR_VALUE *algor) {

	PKI_ALGOR_ID pkey_id = 0;
	PKI_ALGOR_ID digest_id = 0;
		// Algorithm Identifiers

	if (!algor) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_SCHEME_UNKNOWN;
	}

	PKI_ALGOR_ID id = PKI_X509_ALGOR_VALUE_get_id(algor);
	if (id == PKI_ALGOR_ID_UNKNOWN) {
		PKI_DEBUG("Cannot get the algorithm ID from the PKI_ALGOR_VALUE (%s)", 
			PKI_X509_ALGOR_VALUE_get_parsed(algor));
		return PKI_SCHEME_UNKNOWN;
	}

	// Gets the MD and PKEY components
	// if (!OBJ_find_sigid_algs(id, &pkey_id, &digest_id)) {
	if (!OBJ_find_sigid_algs(id, &digest_id, &pkey_id)) {
		PKI_DEBUG("Cannot break the signing algorithm (%d) into PKEY and MD (algor: %s).", 
			id, PKI_X509_ALGOR_VALUE_get_parsed(algor));
		return PKI_SCHEME_UNKNOWN;
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	// Gets the Type of PKEY
	int pkey_type = EVP_PKEY_type(pkey_id);
#else
	int pkey_type = pkey_id;
#endif // End of OPENSSL_VERSION_NUMBER

	PKI_DEBUG("******** OSSL3 UPGRADE: Check pkey_type (%d) vs. pkey_id (%d) ************", pkey_type, pkey_id);

	// Let's check the PKEY types
	switch (pkey_type) {

		// RSA
		case EVP_PKEY_RSA_PSS:
		case EVP_PKEY_RSA: {
			return PKI_SCHEME_RSA;
		} break;

		// DH
		case EVP_PKEY_DH: {
			return PKI_SCHEME_DH;
		} break;

		// ED25519
#ifdef ENABLE_ED25519
		case EVP_PKEY_ED25519: {
			return PKI_SCHEME_ED25519;
		} break;
#endif

		// ED448
#ifdef ENABLE_ED448
		case EVP_PKEY_ED448: {
			return PKI_SCHEME_ED448;
		} break;
#endif

#ifdef ENABLE_DSA
		// DSA
		case EVP_PKEY_DSA: {
			return PKI_SCHEME_DSA;
		} break;
#endif

#ifdef ENABLE_ECDSA
		// EC
		case EVP_PKEY_EC: {
			return PKI_SCHEME_ECDSA;
		} break;
#endif

#ifdef ENABLE_DSA
#endif
		
		default: {

#ifdef ENABLE_COMPOSITE

			// Check Generic Composite
			if (PKI_ID_is_composite(pkey_type, NULL)) {
				// COMPOSITE
				return PKI_SCHEME_COMPOSITE;
			}

			// Check Explicit Composite
			PKI_SCHEME_ID explicit_scheme;
			if (PKI_ID_is_explicit_composite(pkey_type, &explicit_scheme)) {
				// Explicit Composite
				return explicit_scheme;
			}
#endif

#if defined(ENABLE_OQS) || defined(ENABLE_OQSPROV)

			// Check PQC
			PKI_SCHEME_ID pqc_scheme;
			if (PKI_ID_is_pqc(pkey_type, &pqc_scheme)) {
				// Explicit Composite
				return pqc_scheme;
			}

			// // Let's see if we can find the scheme via the
			// // dynamic approach:
			// if (   pkey_type == PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_FALCON512_NAME)
			// 	|| pkey_type == PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_FALCON1024_NAME)) {
			// 	// FALCON
			// 	return PKI_SCHEME_FALCON;
			// } else if (    pkey_type == PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM2_NAME)
			// 			|| pkey_type == PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM3_NAME)
			// 			|| pkey_type == PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM5_NAME)) {
			// 	// DILITHIUM
			// 	return PKI_SCHEME_DILITHIUM;
			// } else if (    pkey_type == PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_SPHINCS128_F_SIMPLE_NAME)
			// 			|| pkey_type == PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_SPHINCS192_F_SIMPLE_NAME)) {
			// 	// SPHINCS+
			// 	return PKI_SCHEME_SPHINCS;
			// } else if (   pkey_type == PKI_ID_get_by_name("kyber512")
			// 		|| pkey_type == PKI_ID_get_by_name("kyber768")
			// 		|| pkey_type == PKI_ID_get_by_name("kyber1024")) {
			// 	// KYBER
			// 	return PKI_SCHEME_KYBER;
			// }  else if (pkey_type == PKI_ID_get_by_name("dilithiumX")) {
			// 	// DILITHIUMX
			// 	return PKI_SCHEME_DILITHIUMX3;
			// }

#endif // End of ENABLE_OQS || ENABLE_OQSPROV
		}

	}

	// Let's check the pkey type
	return PKI_SCHEME_UNKNOWN;

// 	switch ( id ) {

// 		case PKI_ALGOR_ID_DSA_SHA1:
// #ifdef ENABLE_DSA_SHA_2
// 		case PKI_ALGOR_ID_DSA_SHA224:
// 		case PKI_ALGOR_ID_DSA_SHA256:
// #endif
// 			ret = PKI_SCHEME_DSA;
// 			break;
// //		case PKI_ALGOR_RSA_MD2:
// 		case PKI_ALGOR_ID_RSA_MD4:
// 		case PKI_ALGOR_ID_RSA_MD5:
// 		case PKI_ALGOR_ID_RSA_SHA1:
// #ifdef ENABLE_SHA224
// 		case PKI_ALGOR_ID_RSA_SHA224:
// #endif
// #ifdef ENABLE_SHA256
// 		case PKI_ALGOR_ID_RSA_SHA256:
// #endif
// #ifdef ENABLE_SHA384
// 		case PKI_ALGOR_ID_RSA_SHA384:
// #endif
// #ifdef ENABLE_SHA512
// 		case PKI_ALGOR_ID_RSA_SHA512:
// 			ret = PKI_SCHEME_RSA;
// 			break;
// #endif
// #ifdef ENABLE_ECDSA
// 		case PKI_ALGOR_ID_ECDSA_SHA1:
// #endif
// #ifdef ENABLE_ECDSA_SHA_2
// 		case PKI_ALGOR_ID_ECDSA_SHA224:
// 		case PKI_ALGOR_ID_ECDSA_SHA256:
// 		case PKI_ALGOR_ID_ECDSA_SHA384:
// 		case PKI_ALGOR_ID_ECDSA_SHA512:
// 			ret = PKI_SCHEME_ECDSA;
// 			break;
// #endif

// #ifdef ENABLE_OQS

// 		// ==================
// 		// Post-Quantum Algos
// 		// ==================

// 		case PKI_ALGOR_ID_FALCON512:
// 		case PKI_ALGOR_ID_FALCON1024:
// 			ret = PKI_SCHEME_FALCON;
// 			break;

// 		case PKI_ALGOR_ID_DILITHIUM3:
// 		case PKI_ALGOR_ID_DILITHIUM5:
// 		case PKI_ALGOR_ID_DILITHIUM3_AES:
// 		case PKI_ALGOR_ID_DILITHIUM5_AES:
// 			ret = PKI_SCHEME_DILITHIUM;
// 			break;

// 		case PKI_ALGOR_ID_SPHINCS_SHA256_128_R:
// 		// case PKI_ALGOR_ID_SPHINCS_SHA256_192_R:
// 		// case PKI_ALGOR_ID_SPHINCS_SHA256_256_R:
// 		case PKI_ALGOR_ID_SPHINCS_SHAKE256_128_R:
// 			ret = PKI_SCHEME_SPHINCS;
// 			break;

// 		// ================
// 		// Composite Crypto
// 		// ================

// // NOTE: We cannot handle the composite/combined crypto
// //       this way because we do not have the static value
// //       for it, therefore we need to use a different approach
// //       by checking it separately
// // #ifdef ENABLE_COMPOSITE
// // 		case NID_composite:
// // 			ret = PKI_SCHEME_COMPOSITE;
// // 			break;
// // #endif
// //
// // #ifdef ENABLE_COMBINED
// // 		case PKI_ALGOR_ID_COMPOSITE_OR:
// // 			ret = PKI_SCHEME_COMPOSITE_OR;
// // 			break;
// // #endif

// 		// ====================
// 		// OQS Composite Crypto
// 		// ====================

// 		case PKI_ALGOR_ID_COMPOSITE_RSA_FALCON512:
// 			ret = PKI_SCHEME_COMPOSITE_RSA_FALCON;
// 			break;

// 		case PKI_ALGOR_ID_COMPOSITE_ECDSA_FALCON512:
// 		case PKI_ALGOR_ID_COMPOSITE_ECDSA_FALCON1024:
// 			ret = PKI_SCHEME_COMPOSITE_ECDSA_FALCON;
// 			break;

// 		case PKI_ALGOR_ID_COMPOSITE_RSA_DILITHIUM2:
// 			ret = PKI_SCHEME_COMPOSITE_RSA_DILITHIUM;
// 			break;

// 		case PKI_ALGOR_ID_COMPOSITE_ECDSA_DILITHIUM2:
// 		case PKI_ALGOR_ID_COMPOSITE_ECDSA_DILITHIUM3:
// 		case PKI_ALGOR_ID_COMPOSITE_ECDSA_DILITHIUM5:
// 			ret = PKI_SCHEME_COMPOSITE_ECDSA_DILITHIUM;
// 			break;

// #endif
// 		default:
// 			ret = PKI_SCHEME_UNKNOWN;
// 	}

// 	// Process the dynamic-provided schemes
// 	if (ret == PKI_SCHEME_UNKNOWN) {
// #ifdef ENABLE_COMPOSITE
// 		// Composite Crypto
// 		if (id == PKI_SCHEME_UNKNOWN && id == OBJ_txt2nid("composite")) {
// 			ret = PKI_SCHEME_COMPOSITE;
// 		}
// #endif

// #ifdef ENABLE_COMBINED
// 		if (id == PKI_SCHEME_UNKNOWN && id == OBJ_txt2nid("combined")) {
// 			ret = PKI_SCHEME_COMBINED;
// 		}
// #endif
// 	}

// 	return ( ret );
}

/*! \brief Returns the PKI_DIGEST_ALG * from its name.
 *
 * Returns the PKI_DIGEST_ALG * from its name (char *). An example
 * of algorithm identifiers are "sha1", "sha224", "ripemd160". If the
 * passed id is equal to 0, the default PKI_DIGEST_ALG is returned.
 */

const PKI_DIGEST_ALG *PKI_DIGEST_ALG_get_by_name( const char *name ) {

	// Input Check
	if (!name) {
		/* For ease of use, let's fall back to the default one */
		return PKI_DIGEST_ALG_DEFAULT;
	}

	// Returns the digest from the name
	return EVP_get_digestbyname(name);
}

/*! \brief Returns the string representation of a digest algorithm */

const char * PKI_DIGEST_ALG_get_parsed (const PKI_DIGEST_ALG * alg ) {

	if ( !alg ) return NULL;

	return EVP_MD_name ( alg );
}


/*! \brief Returns the digest algorithm based on the key */

const PKI_DIGEST_ALG * PKI_DIGEST_ALG_get_by_key (const PKI_X509_KEYPAIR *pkey ) {

	EVP_PKEY *pp = NULL;
	PKI_DIGEST_ALG * digest = NULL;

	int size = 0;
	int p_type = 0;

	/* Let's set the digest for the right signature scheme */
	if( !pkey ) return NULL;

	size = PKI_X509_KEYPAIR_get_size ( pkey );
	if (size <= 0)
	{
		PKI_ERROR(PKI_ERR_GENERAL, "Key size is 0");
		return NULL;
	}

	pp = (EVP_PKEY *) pkey->value;

// #if OPENSSL_VERSION_NUMBER > 0x30000000L
// 	int p_id = 0;
// 	p_id = PKI_X509_KEYPAIR_get_id(pkey);
// 	p_type = EVP_PKEY_type(p_id);
// 	// TODO: Fix this trick
// 	if (p_type <= 0) p_type = p_id;
// #elif OPENSSL_VERSION_NUMBER < 0x1010000fL
// 	p_type = EVP_PKEY_type(pp->type);
// #else
// 	p_type = EVP_PKEY_type(EVP_PKEY_id(pp));
// #endif

	p_type = PKI_X509_KEYPAIR_get_id(pkey);

	// TODO: Remove this debug
	PKI_DEBUG("******* OSSL3 UPGRADE: Retrieved p_type (%d) from pkey (%d) ************", p_type, pkey->type);

	// Gets the default digest for the key
	int default_nid = -1;

#if OPENSSL_VERSION_NUMBER > 0x30000000L
	char name_buf[50] = { 0x0 };
	int digestResult = EVP_PKEY_get_default_digest_name(pp, name_buf, sizeof(name_buf));
	default_nid = OBJ_txt2nid(name_buf);
#else
	int digestResult = EVP_PKEY_get_default_digest_nid(pp, &default_nid);
#endif

	PKI_DEBUG("***** OSSL3 UPGRADE: EVP_PKEY_get_default_digest_nid (%d) seems to fail *****", digestResult);

	// Returns the default digest for the key if it is
	// the only one supported
	if (digestResult == 2 || default_nid != NID_undef) {
		// The returned digest algorithm is required
		return (const PKI_DIGEST_ALG *)EVP_get_digestbynid(default_nid);
	}

	// if (default_nid != NID_undef) {
	// 	// The returned digest algorithm is required
	// 	return (const PKI_DIGEST_ALG *)EVP_get_digestbynid(default_nid);
	// }

	switch (p_type) {

		case EVP_PKEY_RSA:
		case EVP_PKEY_RSA_PSS:
			digest=PKI_DIGEST_ALG_RSA_DEFAULT;
			break;

		case EVP_PKEY_DSA:
			digest=PKI_DIGEST_ALG_DSA_DEFAULT;
			break;

		case EVP_PKEY_ED25519:
		case EVP_PKEY_ED448:
		    digest=NULL;
			break;

#ifdef ENABLE_ECDSA
		case EVP_PKEY_EC:
			if ( size <= 160  ) {
				digest = PKI_DIGEST_ALG_SHA1;
			} else if ( size <= 224 ) {
				digest = PKI_DIGEST_ALG_SHA224;
			} else if ( size <= 256 ) {
				digest = PKI_DIGEST_ALG_SHA256;
			} else if ( size <= 384 ) {
				digest = PKI_DIGEST_ALG_SHA384;
			} else if ( size <= 521 ) {
				digest = PKI_DIGEST_ALG_SHA512;
			} else {
				digest=PKI_DIGEST_ALG_ECDSA_DEFAULT;
			};
			break;
#endif

#ifdef ENABLE_OQS
			case PKI_ALGOR_ID_FALCON1024:
			case PKI_ALGOR_ID_FALCON512: {
				// PQ Algorithms, Not Returning Hash
				PKI_DEBUG("FALCON: Key Type [%d]; No Hash Returned", p_type);
				digest = PKI_DIGEST_ALG_NULL;
			} break;

			case PKI_ALGOR_ID_DILITHIUM5:
			case PKI_ALGOR_ID_DILITHIUM3:
			case PKI_ALGOR_ID_DILITHIUM2: {
				PKI_DEBUG("DILITHIUM: Key Type [%d]; No Hash Returned", p_type);
				digest = PKI_DIGEST_ALG_NULL;
			} break;

			// case PKI_ALGOR_ID_SPHINCS_SHA256_256_R:
			// case PKI_ALGOR_ID_SPHINCS_SHA256_192_R:
#ifdef NID_sphincssha2128fsimple
			case PKI_ALGOR_ID_SPHINCS_SHA2_128_F:
#endif
#ifdef NID_sphincssha2128fsimple
			case PKI_ALGOR_ID_SPHINCS_SHA2_128_S:
#endif
#ifdef NID_sphincssha2128fsimple
			case PKI_ALGOR_ID_SPHINCS_SHA2_192_F:
#endif
#ifdef NID_sphincssha2128fsimple
			case PKI_ALGOR_ID_SPHINCS_SHA2_192_S:
#endif
				PKI_DEBUG("SPHINCS+: Key Type [%d]; No Hash Returned", p_type);
				digest = PKI_DIGEST_ALG_NULL;
			break;

#endif

		default:

#ifdef ENABLE_OQSPROV
			// Dynamically checks for the support
			// of different types of keys
			if (   PKI_ID_get_by_name("dilithium2") == p_type 
			    || PKI_ID_get_by_name("dilithium3") == p_type
			    || PKI_ID_get_by_name("dilithium5") == p_type
			    || PKI_ID_get_by_name("falcon512") == p_type
			    || PKI_ID_get_by_name("falcon1024") == p_type
				|| PKI_ID_get_by_name("sphincssha2128fsimple") == p_type
				|| PKI_ID_get_by_name("sphincssha2128ssimple") == p_type
				|| PKI_ID_get_by_name("sphincssha2192fsimple") == p_type
				|| PKI_ID_get_by_name("sphincsshake128fsimple") == p_type) {
				// Use the NULL digest for these algorithms
				digest = PKI_DIGEST_ALG_NULL;
			} else {
				// No digest for other types
				digest = NULL;
			}
#else
			// No digest by default
			digest = NULL;
#endif
	}

	return (const PKI_DIGEST_ALG *)digest;
}

/*! \brief Returns the PKI_DIGEST_ALG * associated with the alg id.
 *
 * Returns the PKI_DIGEST_ALG * associated with the alg id. If the
 * passed id is equal to 0, the default PKI_DIGEST_ALG is returned.
 */


const PKI_DIGEST_ALG *PKI_DIGEST_ALG_get ( PKI_ALGOR_ID id ) {

	PKI_DIGEST_ALG * ret = NULL;

	switch ( id ) {
#ifdef ENABLE_MD4
		case PKI_ALGOR_MD4:
			ret = PKI_DIGEST_ALG_MD4;
			break;
#endif
#ifdef ENABLE_MD5
		case PKI_ALGOR_MD5:
			ret = PKI_DIGEST_ALG_MD5;
			break;
#endif
#ifdef ENABLE_SHA1
		case PKI_ALGOR_SHA1:
			ret = PKI_DIGEST_ALG_SHA1;
			break;
#endif
#ifdef PKI_ALGOR_DSS1
		case PKI_ALGOR_DSS1:
			ret = PKI_DIGEST_ALG_DSS1;
			break;
#endif
#ifdef ENABLE_SHA224
		case PKI_ALGOR_SHA224:
			ret = PKI_DIGEST_ALG_SHA224;
			break;
#endif
#ifdef ENABLE_SHA256
		case PKI_ALGOR_SHA256:
			ret = PKI_DIGEST_ALG_SHA256;
			break;
#endif
#ifdef ENABLE_SHA384
		case PKI_ALGOR_SHA384:
			ret = PKI_DIGEST_ALG_SHA384;
			break;
#endif
#ifdef ENABLE_SHA512
		case PKI_ALGOR_SHA512:
			ret = PKI_DIGEST_ALG_SHA512;
			break;
#endif
#ifdef ENABLE_RIPEMD160
		case PKI_ALGOR_RIPEMD160:
			ret = PKI_DIGEST_ALG_RIPEMD160;
			break;
#endif
#if OPENSSL_VERSION_NUMBER < 0x1000000fL
# ifdef ENABLE_ECDSA
		case PKI_ALGOR_ECDSA_DSS1:
			ret = PKI_DIGEST_ALG_ECDSA_SHA1;
			break;
# endif
#endif
		default:
			ret = PKI_DIGEST_ALG_UNKNOWN;
	}

	return (const PKI_DIGEST_ALG *) ret;
}

const PKI_DIGEST_ALG * PKI_DIGEST_ALG_get_default(const PKI_X509_KEYPAIR * const x) {

	// Input Check
	if (!x || !x->value) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, "Missing Key Value");
		return NULL;
	}

	// Gets the value
	PKI_X509_KEYPAIR_VALUE * pkey = PKI_X509_get_value(x);

	// Gets the default digest for the key
	int def_nid = -1;

#if OPENSSL_VERSION_NUMBER > 0x30000000L
	char name_buf[50] = { 0x0 };
	int digestResult = EVP_PKEY_get_default_digest_name(pkey, name_buf, sizeof(name_buf));
	def_nid = OBJ_txt2nid(name_buf);
#else
	int digestResult = EVP_PKEY_get_default_digest_nid(pkey, &def_nid);
#endif
	PKI_DEBUG("***** OSSL3 UPGRADE: EVP_PKEY_get_default_digest_nid (%d) seems to fail *****", digestResult);

	// Checks for error
	if (digestResult <= 0) {
		PKI_DEBUG("Cannot get the default digest for signing (pkey type: %d)", PKI_X509_KEYPAIR_VALUE_get_id(pkey));
		return NULL;

// #if OPENSSL_VERSION_NUMBER > 0x30000000L
// 		PKI_DEBUG("Returning the default digest (%s)", PKI_ID_get_txt(PKI_DIGEST_ALG_ID_DEFAULT));
// 		return PKI_DIGEST_ALG_DEFAULT;
// #else
// 		// Error condition
// 		return NULL;
// #endif

	}

	// If the returned value is == 2, then the returned
	// digest is mandatory and cannot be replaced
	if (digestResult == 2) {

		// If no-hash is mandatory, we return the null MD
		if (def_nid == NID_undef) return EVP_md_null();

		// Let's return the mandatory one
		return EVP_get_digestbynid(def_nid);
	}
	
	// If we reach here, the PKEY does not have
	// a mandatory hash, let's return our own default
	return PKI_DIGEST_ALG_DEFAULT;
}

const PKI_ALGOR_ID *PKI_ALGOR_ID_list ( PKI_SCHEME_ID scheme ) {

	const PKI_ALGOR_ID * ret;

	switch ( scheme ) {
		case PKI_SCHEME_RSA: {
			ret = PKI_ALGOR_ID_LIST_RSA;
		} break;

		case PKI_SCHEME_DSA: {
			ret = PKI_ALGOR_ID_LIST_DSA;
		} break;

#ifdef ENABLE_ECDSA
		case PKI_SCHEME_ECDSA: {
			ret = PKI_ALGOR_ID_LIST_ECDSA;
		} break;
#endif

#ifdef ENABLE_OQS
		case PKI_SCHEME_FALCON: {
			ret = PKI_ALGOR_ID_LIST_FALCON;
		} break;

		case PKI_SCHEME_DILITHIUM: {
			ret = PKI_ALGOR_ID_LIST_DILITHIUM;
		} break;
		
		case PKI_SCHEME_SPHINCS: {
			ret = PKI_ALGOR_ID_LIST_SPHINCS;
		} break;

		case PKI_SCHEME_CLASSIC_MCELIECE: {
			ret = PKI_ALGOR_ID_LIST_CLASSIC_MCELIECE;
		} break;

		case PKI_SCHEME_DILITHIUMX3: {
			ret = PKI_ALGOR_ID_LIST_DILITHIUM;
		} break;

#else

#ifdef ENABLE_OQSPROV
		case PKI_SCHEME_FALCON:
		case PKI_SCHEME_DILITHIUM:
		case PKI_SCHEME_SPHINCS:
		case PKI_SCHEME_CLASSIC_MCELIECE:
		case PKI_SCHEME_DILITHIUMX3: {
			PKI_DEBUG("OQS Support not enabled in this build (only OQSPROV)!");
			ret = NULL;
		} break;

#endif

#endif
		default:
			PKI_ERROR(PKI_ERR_ALGOR_UNKNOWN, NULL);
			ret = NULL;
	}

	return ret;
}

const PKI_ALGOR_ID *PKI_DIGEST_ALG_ID_list( void ) {

	return PKI_DIGEST_ALG_ID_LIST;
}

size_t PKI_ALGOR_ID_list_size( const PKI_ALGOR_ID * const list ) {

	size_t i = 0;

	if( !list ) return ( 0 );

	while ( list[i] != PKI_ALGOR_ID_UNKNOWN ) i++;

	return( i );
}

