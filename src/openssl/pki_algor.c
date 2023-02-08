/* openssl/pki_algor.c */

#include <libpki/pki.h>

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
	PKI_ALGOR_ID_DILITHIUM2_AES,
	PKI_ALGOR_ID_DILITHIUM3,
	PKI_ALGOR_ID_DILITHIUM3_AES,
	PKI_ALGOR_ID_DILITHIUM5,
	PKI_ALGOR_ID_DILITHIUM5_AES
};

PKI_ALGOR_ID PKI_ALGOR_ID_LIST_SPHINCS[] = {
	PKI_ALGOR_ID_SPHINCS_SHA256_128_R,
	PKI_ALGOR_ID_SPHINCS_SHA256_192_R,
	PKI_ALGOR_ID_SPHINCS_SHA256_256_R,
	PKI_ALGOR_ID_SPHINCS_SHAKE256_128_R
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

	if((ret = X509_ALGOR_new()) == NULL) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
	}

	return ret;
}


void PKI_X509_ALGOR_VALUE_free ( PKI_X509_ALGOR_VALUE *a ) {
	if ( !a ) return;

	X509_ALGOR_free ( a );

	return;
}

PKI_X509_ALGOR_VALUE * PKI_X509_ALGOR_VALUE_new_type ( int type ) {

	PKI_X509_ALGOR_VALUE *ret = NULL;
	  // Return Value

	if (( ret = X509_ALGOR_new()) == NULL ) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	if (!(ret->algorithm=OBJ_nid2obj(type))) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		goto err;
	}

	// Generates the parameter
	if((ret->parameter = ASN1_TYPE_new()) == NULL ) goto err;

	// Sets the Algorithm OID and Parameter Type
	ret->algorithm=OBJ_nid2obj(type);
	ret->parameter->type = V_ASN1_NULL;

	return ret;

err:

	if ( ret ) PKI_X509_ALGOR_VALUE_free ( ret );

	return NULL;
}

PKI_X509_ALGOR_VALUE * PKI_X509_ALGOR_VALUE_new_digest ( PKI_DIGEST_ALG *alg ) {

	PKI_X509_ALGOR_VALUE *ret = NULL;
	PKI_ID id = PKI_ID_UNKNOWN;

	if ( !alg ) return NULL;

	if((id = EVP_MD_nid( alg )) == NID_undef) {
		return NULL;
	};

	if (( ret = X509_ALGOR_new()) == NULL ) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	};

	if (!(ret->algorithm=OBJ_nid2obj(id))) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		goto err;
	}

    if ((ret->parameter=ASN1_TYPE_new()) == NULL) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		goto err;
	}

    ret->parameter->type=V_ASN1_NULL;

	return ret;

err:
	if (ret) X509_ALGOR_free ( ret );

	return NULL;
}


/*! \brief Build a PKI_ALGOR structure from its name (char *)
 *
 * The function returns the pointer to a PKI_ALGOR structure based on the
 * name. Names are in the form of "RSA-SHA1", "RSA-SHA512", or "DSA-SHA1".
 */

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
	if((alg_nid = OBJ_sn2nid( buf )) == PKI_ALGOR_ID_UNKNOWN ) {

		// Checks the long name database for the OID
		if((alg_nid = OBJ_ln2nid( buf )) == PKI_ALGOR_ID_UNKNOWN ) {

			// The text does not correspond to any known OID strings
			// return a NULL pointer
			return PKI_ALGOR_NULL;
		}
	}

	// Returns the pointer to the PKI_X509_ALGOR_VALUE structure
	return PKI_X509_ALGOR_VALUE_get(alg_nid);
}

/*! \brief Returns a text string with the algorithm identifier */

char * PKI_ALGOR_ID_txt ( PKI_ALGOR_ID algor ) {
	ASN1_OBJECT *a = NULL;

	if(( a = OBJ_nid2obj( algor )) == NULL ) {
		return("Undefined");
	}

	ASN1_OBJECT_free( a );

	return( (char *)OBJ_nid2sn( algor ));
}

/*! \brief Returns a text representation of the algorithm identifier */

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

/*!
 * \brief Returns a text representation of the PKI_SCHEME
 */

const char * PKI_SCHEME_ID_get_parsed ( PKI_SCHEME_ID id ) {

	const char *ret;

	switch ( id ) {

		// ========================
		// Classic or Modern Crypto
		// ========================

		case PKI_SCHEME_RSA: {
			ret = "RSA";
		} break;

#ifdef ENABLE_ECDSA
		case PKI_SCHEME_ECDSA: {
			ret = "ECDSA";
		} break;
#endif

		case PKI_SCHEME_DSA: {
			ret = "DSA";
		} break;


		// ===================
		// Post-Quantum Crypto
		// ===================

#ifdef ENABLE_OQS

		case PKI_SCHEME_FALCON: {
			ret = "FALCON";
		} break;

		case PKI_SCHEME_DILITHIUM: {
			ret = "DILITHIUM";
		} break;

		case PKI_SCHEME_DILITHIUMX3: {
			ret = "DILITHIUMX3";
		} break;

		case PKI_SCHEME_SPHINCS: {
			ret = "SPHINCS";
		} break;

		// =====================
		// Composite (PQ) Crypto
		// =====================
		
		// case PKI_SCHEME_COMPOSITE_DILITHIUM3_P256: {
		// 	ret = "DILITHIUM3-P256";
		// } break;

		// case PKI_SCHEME_COMPOSITE_DILITHIUM3_RSA: {
		// 	ret = "DILITHIUM3-RSA";
		// } break;

		// case PKI_SCHEME_COMPOSITE_FALCON512_P256: {
		// 	ret = "FALCON512-P256";
		// } break;

		// case PKI_SCHEME_COMPOSITE_FALCON512_RSA: {
		// 	ret = "FALCON512-RSA";
		// } break;

		// case PKI_SCHEME_COMPOSITE_DILITHIUM5_FALCON1024_P521: {
		// 	ret = "DILITHIUM5-FALCON1024-P521";
		// } break;

		// case PKI_SCHEME_COMPOSITE_DILITHIUM5_FALCON1024_RSA: {
		// 	ret = "DILITHIUM5-FALCON1024-RSA";
		// } break;
#endif

#ifdef ENABLE_COMPOSITE

# ifdef ENABLE_OQS

		// =========================
		// Composite: Generic and PQ
		// =========================

		case PKI_SCHEME_COMPOSITE_DILITHIUM3_RSA: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_DILITHIUM3_P256: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_P256_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_DILITHIUM3_BRAINPOOL256: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_BRAINPOOL256_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_DILITHIUM3_ED25519: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ED25519_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_DILITHIUM5_P384: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_P384_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_DILITHIUM5_BRAINPOOL384: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_BRAINPOOL384_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_DILITHIUM5_ED448: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_ED448_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_FALCON512_P256: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_P256_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_FALCON512_BRAINPOOL256: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_BRAINPOOL256_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_FALCON512_ED25519: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_SPHINCS256_P256: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_P256_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_SPHINCS256_BRAINPOOL256: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_BRAINPOOL256_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_SPHINCS256_ED25519: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_ED25519_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_FALCON512_RSA: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_RSA_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_DILITHIUM5_FALCON1024_P521: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_P521_NAME;
		} break;

	    case PKI_SCHEME_COMPOSITE_DILITHIUM5_FALCON1024_RSA: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_RSA_NAME;
		} break;

# endif
		case PKI_SCHEME_COMPOSITE: {
			ret = OPENCA_ALG_PKEY_EXP_COMP_NAME_ENTRUST;
		} break;

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

/*!
 * \brief Returns the PKI_SCHEME_ID from the passed string
 */

PKI_SCHEME_ID PKI_X509_ALGOR_VALUE_get_scheme_by_txt(const char * data) {

	if (data) {

		if (strncmp_nocase("RSA", data, 3) == 0) {
			return PKI_SCHEME_RSA;
		} else if (strncmp_nocase("DSA", data, 3) == 0) {
			return PKI_SCHEME_DSA;
#ifdef ENABLE_ECDSA
		} else if (strncmp_nocase("EC", data, 2) == 0) {
			return PKI_SCHEME_ECDSA;
#endif
#ifdef ENABLE_OQS
# ifdef ENABLE_COMPOSITE
		// Explicit Composite
		} else if (strncmp_nocase(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_NAME, data, 14) == 0) {
			return PKI_SCHEME_COMPOSITE_DILITHIUM3_RSA ;
		} else if (strncmp_nocase(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_P256_NAME, data, 15) == 0) {
			return PKI_SCHEME_COMPOSITE_DILITHIUM3_P256 ;
		} else if (strncmp_nocase(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_BRAINPOOL256_NAME, data, 23) == 0) {
			return PKI_SCHEME_COMPOSITE_DILITHIUM3_BRAINPOOL256 ;
		} else if (strncmp_nocase(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ED25519_NAME, data, 18) == 0) {
			return PKI_SCHEME_COMPOSITE_DILITHIUM3_ED25519 ;
		} else if (strncmp_nocase(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_P384_NAME, data, 15) == 0) {
			return PKI_SCHEME_COMPOSITE_DILITHIUM5_P384 ;
		} else if (strncmp_nocase(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_BRAINPOOL384_NAME, data, 13) == 0) {
			return PKI_SCHEME_COMPOSITE_DILITHIUM5_BRAINPOOL384 ;
		} else if (strncmp_nocase(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_ED448_NAME, data, 16) == 0) {
			return PKI_SCHEME_COMPOSITE_DILITHIUM5_ED448 ;
		} else if (strncmp_nocase(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_P256_NAME, data, 14) == 0) {
			return PKI_SCHEME_COMPOSITE_FALCON512_P256 ;
		} else if (strncmp_nocase(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_BRAINPOOL256_NAME, data, 12) == 0) {
			return PKI_SCHEME_COMPOSITE_FALCON512_BRAINPOOL256 ;
		} else if (strncmp_nocase(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_NAME, data, 17) == 0) {
			return PKI_SCHEME_COMPOSITE_FALCON512_ED25519 ;
		} else if (strncmp_nocase(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_P256_NAME, data, 15) == 0) {
			return PKI_SCHEME_COMPOSITE_SPHINCS256_P256 ;
		} else if (strncmp_nocase(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_BRAINPOOL256_NAME, data, 23) == 0) {
			return PKI_SCHEME_COMPOSITE_SPHINCS256_BRAINPOOL256 ;
		} else if (strncmp_nocase(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_ED25519_NAME, data, 18) == 0) {
			return PKI_SCHEME_COMPOSITE_SPHINCS256_ED25519 ;
		} else if (strncmp_nocase(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_RSA_NAME, data, 13) == 0) {
			return PKI_SCHEME_COMPOSITE_FALCON512_RSA ;
		} else if (strncmp_nocase(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_P521_NAME, data, 26) == 0) {
			return PKI_SCHEME_COMPOSITE_DILITHIUM5_FALCON1024_P521 ;
		} else if (strncmp_nocase(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_RSA_NAME, data, 25) == 0) {
			return PKI_SCHEME_COMPOSITE_DILITHIUM5_FALCON1024_RSA ;
# endif
		// Dilithium Algorithm
		// Experimental: LibPKI PQC Native
		} else if (    strncmp_nocase(OPENCA_ALG_PKEY_EXP_DILITHIUMX_NAME, data, 11) == 0) {
			return PKI_SCHEME_DILITHIUMX3;
		// OQS Post-Quantum
		} else if (    strncmp_nocase(OPENCA_ALG_PKEY_PQC_DILITHIUM2_NAME, data, 11) == 0
					|| strncmp_nocase(OPENCA_ALG_PKEY_PQC_DILITHIUM3_NAME, data, 11) == 0
					|| strncmp_nocase(OPENCA_ALG_PKEY_PQC_DILITHIUM5_NAME, data, 11) == 0) {
			return PKI_SCHEME_DILITHIUM;
		} else if (    strncmp_nocase(OPENCA_ALG_PKEY_PQC_FALCON512_NAME, data, 9) == 0
					|| strncmp_nocase(OPENCA_ALG_PKEY_PQC_FALCON1024_NAME, data, 10) == 0) {
			return PKI_SCHEME_FALCON;
		} else if (strncmp_nocase("DILITHIUM", data, 9) == 0) {
			return PKI_SCHEME_DILITHIUM;
		} else if (strncmp_nocase("SPHINCS", data, 7) == 0) {
			return PKI_SCHEME_SPHINCS;
#endif
#ifdef ENABLE_COMPOSITE
		// Generic Composite
		} else if (strncmp_nocase("COMPOSITE", data, 9) == 0) {
			return PKI_SCHEME_COMPOSITE;
#ifdef ENABLE_COMBINED
		} else if (strncmp_nocase("MULTIKEY", data, 9) == 0) {
			return PKI_SCHEME_COMBINED;
#endif
#endif
		} else {
			PKI_log_err("Cannot Convert [%s] into a recognized OID.", data);
		}

	}

	// No supported scheme found
	return PKI_SCHEME_UNKNOWN;
}

/*!
 * \brief Build a PKI_ALGOR structure from its ID
 */

PKI_X509_ALGOR_VALUE * PKI_X509_ALGOR_VALUE_get( PKI_ALGOR_ID algor ) {

	PKI_X509_ALGOR_VALUE *ret 	= NULL;
	  // Return Value

	int alg_nid 	              = PKI_ALGOR_ID_UNKNOWN;
	  // Algorithm Identifier

	int hash_nid = 0, pkey_nid = 0;
		// Identifiers for breaking down the algorithm

	// Retrieves the ID from the internal DB
	if ((alg_nid = OBJ_obj2nid(OBJ_nid2obj(algor))) == PKI_ALGOR_ID_UNKNOWN) {
		PKI_ERROR(PKI_ERR_ALGOR_UNKNOWN, "ERROR, Algorithm ID unknown (%d)", algor);
		return NULL;
	}

	// Finds if this NID is a X509_ALGOR nid, if not let's return NULL
	if (!OBJ_find_sigid_algs(alg_nid, &hash_nid, &pkey_nid)) {
		PKI_DEBUG("Cannot Find Algors for %d (%s)", alg_nid, OBJ_nid2sn(alg_nid));
		return NULL;
	}

// 	// Check if the OID found corresponds to one of the supported algorithms 
// 	switch (alg_nid) {

// 		// RSA Scheme
// #ifdef ENABLE_MD4
// 		case PKI_ALGOR_RSA_MD4:
// #endif
// #ifdef ENABLE_MD5
// 		case PKI_ALGOR_RSA_MD5:
// #endif
// #ifdef ENABLE_SHA1
// 		case PKI_ALGOR_RSA_SHA1:
// #endif
// #ifdef ENABLE_SHA224
// 		case PKI_ALGOR_RSA_SHA224:
// #endif
// #ifdef ENABLE_SHA256
// 		case PKI_ALGOR_RSA_SHA256:
// #endif
// #ifdef ENABLE_SHA384
// 		case PKI_ALGOR_RSA_SHA384:
// #endif
// #ifdef ENABLE_SHA512
// 		case PKI_ALGOR_RSA_SHA512:
// #endif
// #ifdef ENABLE_RIPEMD
// 		case PKI_ALGOR_RSA_RIPEMD128:
// 		case PKI_ALGOR_RSA_RIPEMD160:
// #endif

// 		// DSA Scheme
// 		case PKI_ALGOR_DSA_SHA1:
// #ifdef ENABLE_DSA_SHA_2
// 		case PKI_ALGOR_DSA_SHA224:
// 		case PKI_ALGOR_DSA_SHA256:
// #endif

// 		// ECDSA Scheme
// #ifdef ENABLE_ECDSA
// 		case PKI_ALGOR_ECDSA_SHA1:
// #endif
// #ifdef ENABLE_ECDSA_SHA_2
// 		case PKI_ALGOR_ECDSA_SHA224:
// 		case PKI_ALGOR_ECDSA_SHA256:
// 		case PKI_ALGOR_ECDSA_SHA384:
// 		case PKI_ALGOR_ECDSA_SHA512:
// #endif
// 			break;

// 		// Post Quantum and Composite Cryptograpy
// #ifdef ENABLE_OQS
// 		case PKI_ALGOR_FALCON512:
// 		case PKI_ALGOR_FALCON1024:
// 		case PKI_ALGOR_DILITHIUM2:
// 		case PKI_ALGOR_DILITHIUM3:
// 		case PKI_ALGOR_DILITHIUM5:
// 		case PKI_ALGOR_SPHINCS_SHA256_128_R:
// 		// case PKI_ALGOR_SPHINCS_SHA256_192_R:
// 		// case PKI_ALGOR_SPHINCS_SHA256_256_R:
// 		case PKI_ALGOR_SPHINCS_SHAKE256_128_R:
// 		case PKI_ALGOR_DILITHIUM2_AES:
// 		case PKI_ALGOR_DILITHIUM3_AES:
// 		case PKI_ALGOR_DILITHIUM5_AES:
// 		case PKI_ALGOR_COMPOSITE_RSA_FALCON512:
// 		case PKI_ALGOR_COMPOSITE_ECDSA_FALCON512:
// 		case PKI_ALGOR_COMPOSITE_ECDSA_FALCON1024:
// 		case PKI_ALGOR_COMPOSITE_RSA_DILITHIUM2:
// 		case PKI_ALGOR_COMPOSITE_RSA_DILITHIUM2_AES:
// 		case PKI_ALGOR_COMPOSITE_ECDSA_DILITHIUM2:
// 		case PKI_ALGOR_COMPOSITE_ECDSA_DILITHIUM3:
// 		case PKI_ALGOR_COMPOSITE_ECDSA_DILITHIUM5:
// 			break;
// #endif

// 		default:
// 			alg_nid = PKI_ALGOR_ID_UNKNOWN;
// 			break;
// 	}

	// If the Algorithm ID is known, let's generate the
	// PKIX algorithm data structure
	if (alg_nid == PKI_ALGOR_ID_UNKNOWN) {
		// Unknown or unsupported Algorithm
		PKI_DEBUG("Unknown algorithm [ Algor ID: %d ]", algor);
		goto err;
	}

	// Let's return the PKIX X509 Algorithm Data structure
	return PKI_X509_ALGOR_VALUE_new_type(alg_nid);

err:

  // Free Allocated Memory  
	if (ret) PKI_X509_ALGOR_VALUE_free(ret);

	// Returns NULL
	return (PKI_ALGOR_NULL);
}

/* ! \brief Get a PKI_ALGOR from an PKI_ALGOR object */

PKI_ALGOR_ID PKI_X509_ALGOR_VALUE_get_id(const PKI_X509_ALGOR_VALUE *algor ) {

	PKI_ALGOR_ID ret = PKI_ALGOR_ID_UNKNOWN;
	  // Return Value

	// Input Checks
	if (!algor || !algor->algorithm) return PKI_ALGOR_ID_UNKNOWN;

	PKI_DEBUG("Need to update the procedure to use X509_ALGOR_get0");
	
	// // Returns the algorithm's ID
	// ret = X509_ALGOR_get0(algor);
	// if (ret == PKI_ALGOR_ID_UKNOWN)

	// Gets the Algorithm Id
	if ((ret = OBJ_obj2nid(algor->algorithm)) == PKI_ALGOR_ID_UNKNOWN) {
		// ERROR: Unknown or unsupported algorithm
		PKI_ERROR( PKI_ERR_ALGOR_UNKNOWN, "PKI_ID_UNKNOWN returned (%p)", algor);
	}

  // All Done
	return ret;
}

/*! \brief Get the Digest Algorithm from the passed PKI_ALGOR
 */

const PKI_DIGEST_ALG *PKI_X509_ALGOR_VALUE_get_digest(const PKI_X509_ALGOR_VALUE *algor ) {

	PKI_ALGOR_ID id = PKI_ID_UNKNOWN;
	PKI_ALGOR_ID pkey_id = PKI_ID_UNKNOWN;
	PKI_ALGOR_ID digest_id = PKI_ID_UNKNOWN; 

	// Input checks
	if (!algor) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, "No algorithm provided");
		return NULL;
	}

	// Retrieves the Algorithm ID
	if((id = PKI_X509_ALGOR_VALUE_get_id ( algor )) <= 0) {
		PKI_ERROR(PKI_ERR_ALGOR_UNKNOWN, NULL);
		return NULL;
	}

	// Gets the MD and PKEY components
	if (!OBJ_find_sigid_algs(id, &digest_id, &pkey_id)) {
		PKI_ERROR(PKI_ERR_OBJECT_TYPE_UNKNOWN, "Cannot break the signign algorithm (%d) into PKEY and MD.", id);
		return NULL;
	}

	// If nothing was found, let's return nothing
	if (digest_id == NID_undef) return EVP_md_null();

	// Let's get the digest
	PKI_DIGEST_ALG * ret = (PKI_DIGEST_ALG *)EVP_get_digestbynid(digest_id);
	if (!ret) {
		PKI_ERROR(PKI_ERR_DIGEST_VALUE_NULL, "Cannot retrieve Digest Algorithm (NID: %d, NAME: %s)",
			digest_id, OBJ_nid2sn(digest_id));
	}

	// If we found the digest, let's get it
	return ret;
}

/*! \brief Returns the PKI_ALGOR_ID of the digest used in the PKI_ALGOR */

PKI_ALGOR_ID PKI_X509_ALGOR_VALUE_get_digest_id (const PKI_X509_ALGOR_VALUE *algor ) {

	int i = -1;
	const EVP_MD *md = NULL;

	if ( !algor || !algor->algorithm ) return PKI_ALGOR_ID_UNKNOWN;

	i = OBJ_obj2nid(algor->algorithm);
    if ((md = EVP_get_digestbyname(OBJ_nid2sn(i))) != NULL ) {
		return EVP_MD_nid(md);
	}

	return PKI_ALGOR_ID_UNKNOWN;
}

/*! \brief Returns the PKI_SCHEME_ID (signature scheme ID) of the algorithm */

PKI_SCHEME_ID PKI_X509_ALGOR_VALUE_get_scheme (const PKI_X509_ALGOR_VALUE *algor) {

	PKI_ALGOR_ID id, pkey_id, digest_id;

	if (!algor) return PKI_SCHEME_UNKNOWN;

	if ((id = PKI_X509_ALGOR_VALUE_get_id ( algor )) == PKI_ALGOR_ID_UNKNOWN)
		return PKI_SCHEME_UNKNOWN;

	// Gets the MD and PKEY components
	// if (!OBJ_find_sigid_algs(id, &pkey_id, &digest_id)) {
	if (!OBJ_find_sigid_algs(id, &digest_id, &pkey_id)) {
		PKI_ERROR(PKI_ERR_OBJECT_TYPE_UNKNOWN, "Cannot break the signing algorithm (%d) into PKEY and MD.", id);
		return PKI_SCHEME_UNKNOWN;
	}

	// Gets the Type of PKEY
	int pkey_type = EVP_PKEY_type(pkey_id);

	// Let's check the PKEY types
	switch (pkey_type) {

		// RSA
		case EVP_PKEY_RSA: {
			return PKI_SCHEME_RSA;
		} break;

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

	}

#ifdef ENABLE_COMPOSITE
	if (pkey_type == PKI_ID_get_by_name("composite")) {
		// COMPOSITE
		return PKI_SCHEME_COMPOSITE;
	}
#endif
#ifdef ENABLE_COMBINED
	if (pkey_type == PKI_ID_get_by_name("multikey")) {
		// MULTIKEYS
		return PKI_SCHEME_COMBINED;
	}
#endif

#ifdef ENABLE_OQS
	// Let's see if we can find the scheme via the
	// dynamic approach:
	if (   pkey_type == PKI_ID_get_by_name("falcon512")
	    || pkey_type == PKI_ID_get_by_name("falcon1024")) {
		// FALCON
		return PKI_SCHEME_FALCON;

	} else if (pkey_type == PKI_ID_get_by_name("dilithium3")
			   || pkey_type == PKI_ID_get_by_name("dilithium3-AES")
			   || pkey_type == PKI_ID_get_by_name("dilithium5")
			   || pkey_type == PKI_ID_get_by_name("dilithium5-AES")) {
		// DILITHIUM
		return PKI_SCHEME_DILITHIUM;
	}  else if (pkey_type == PKI_ID_get_by_name("dilithiumX")) {
		// DILITHIUMX
		return PKI_SCHEME_DILITHIUMX3;
	}
#endif

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

	// // Check if the object is a valid OID
	// if ((alg_id = OBJ_sn2nid(name)) == PKI_ALGOR_ID_UNKNOWN ) {
	// 	// Checks for the long name/description
	// 	if((alg_id = OBJ_ln2nid( name )) == PKI_ALGOR_ID_UNKNOWN ) {
	// 		// No matching OID found for the algorithm 'name'
	// 		return ( PKI_DIGEST_ALG_UNKNOWN );
	// 	}
	// }

	// // Returns the algorithm
	// return PKI_DIGEST_ALG_get(alg_id);
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

#if OPENSSL_VERSION_NUMBER < 0x1010000fL
	p_type = EVP_PKEY_type(pp->type);
#else
	p_type = EVP_PKEY_type(EVP_PKEY_id(pp));
#endif

	// Gets the default digest for the key
	int default_nid = -1;
	int digestResult = EVP_PKEY_get_default_digest_nid(pp, &default_nid);

	// Returns the default digest for the key if it is
	// the only one supported
	if (digestResult == 2) {
		// The returned digest algorithm is required
		return (const PKI_DIGEST_ALG *)EVP_get_digestbynid(default_nid);
	}

	switch (p_type) {

		case EVP_PKEY_DSA:
			digest=PKI_DIGEST_ALG_DSA_DEFAULT;
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
			case PKI_ALGOR_ID_SPHINCS_SHA256_128_R: {
				PKI_DEBUG("SPHINCS+-SHA256 -> Key Type [%d]; No Hash Returned", p_type);
				digest = PKI_DIGEST_ALG_NULL;
			} break;

			// case PKI_ALGOR_ID_SPHINCS_SHAKE256_256_R:
			// case PKI_ALGOR_ID_SPHINCS_SHAKE256_192_R:
			case PKI_ALGOR_ID_SPHINCS_SHAKE256_128_R: {
				PKI_log_err("SPHINCS+-SHAKE256 -> Key Type [%d]; No Hash Returned", p_type);
				digest = PKI_DIGEST_ALG_NULL;
			} break;
#endif

#ifdef ENABLE_COMPOSITE_CRYPTO
			case PKI_ALGOR_ID_COMPOSITE:
			case PKI_ALGOR_ID_COMPOSITE_OR: {
				digest = PKI_DIGEST_ALG_NULL;
			} break;
#endif

		case EVP_PKEY_RSA:
			digest=PKI_DIGEST_ALG_RSA_DEFAULT;
			break;

		default:
			digest = NULL;
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
	int digestResult = EVP_PKEY_get_default_digest_nid(pkey, &def_nid);

	// Checks for error
	if (digestResult <= 0) {
		PKI_DEBUG("Cannot get the default digest for signing (pkey type: %d)", EVP_PKEY_id(pkey));
		return NULL;
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
		case PKI_SCHEME_ECDSA: 
		{
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

		case PKI_SCHEME_DILITHIUMX3: {
			ret = PKI_ALGOR_ID_LIST_DILITHIUM;
		} break;

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

