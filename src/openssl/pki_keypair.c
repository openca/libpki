/* openssl/pki_pkey.c */

#include <libpki/pki.h>
#include <libpki/datatypes.h>

PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_new_null () {
	return PKI_X509_new ( PKI_DATATYPE_X509_KEYPAIR, NULL );
}

void PKI_X509_KEYPAIR_free( PKI_X509_KEYPAIR *key ) {

	PKI_X509_free ( key );
	return;
}

void PKI_X509_KEYPAIR_free_void ( void *key ) {
	PKI_X509_free_void ( (PKI_X509_KEYPAIR *) key );
	return;
}

/*! \brief Generate a new Keypair with the passed label (required for
 *         PKCS#11 HSMs ) as target
 */

PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_new( PKI_SCHEME_ID type, int bits,
					char *label, PKI_CRED *cred, HSM *hsm ) {

	PKI_KEYPARAMS kp;

	// Common
	kp.scheme = type;
	kp.bits = bits;

	// RSA
	kp.rsa.exponent = -1;

	//DSA

	// EC
#ifdef ENABLE_ECDSA
	kp.ec.form = PKI_EC_KEY_FORM_UNKNOWN;
	kp.ec.curve = -1;
#endif

	return HSM_X509_KEYPAIR_new ( &kp, label, cred, hsm );
}

/*! \brief Generate a new Keypair with the passed URL (required for
 *         PKCS#11 HSMs ) as target
 */

PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_new_url( PKI_SCHEME_ID type, int bits, 
			URL *url, PKI_CRED *cred, HSM *hsm ) {

	PKI_KEYPARAMS kp;

	// Common
	kp.scheme = type;
	kp.bits = bits;

	// RSA
	kp.rsa.exponent = -1;

	//DSA

	// EC
#ifdef ENABLE_ECDSA
	kp.ec.form = PKI_EC_KEY_FORM_UNKNOWN;
	kp.ec.curve = -1;
	kp.ec.asn1flags = -1;
#endif

	// Open Quantum Safe
#ifdef ENABLE_OQS
	kp.oqs.algId = -1;
#endif

	return HSM_X509_KEYPAIR_new_url ( &kp, url, cred, hsm );
}

/*! 
 * \brief Generate a new Keypair with the passed label (required for PKCS#11 HSMs ) as target
 */

PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_new_kp( PKI_KEYPARAMS *kp,
					   char *label, PKI_CRED *cred, HSM *hsm ) {

	return HSM_X509_KEYPAIR_new ( kp, label, cred, hsm );
}

/*! \brief Generate a new Keypair with the passed URL (required for
 *         PKCS#11 HSMs ) as target
 */

PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_new_url_kp( PKI_KEYPARAMS *kp,
							URL *url, PKI_CRED *cred, HSM *hsm ) {

	return HSM_X509_KEYPAIR_new_url ( kp, url, cred, hsm );
}

/*! \brief Returns a char * with a string representation of the Keypair
 */

char * PKI_X509_KEYPAIR_get_parsed (const PKI_X509_KEYPAIR *pkey ) {

	if( !pkey || !pkey->value ) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return ( NULL );
	};

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED, NULL);

	return NULL;
}

/*!
 * \brief Returns the signing scheme from a keypair
 */

PKI_SCHEME_ID PKI_X509_KEYPAIR_get_scheme (const PKI_X509_KEYPAIR *k ) {

	PKI_X509_KEYPAIR_VALUE *pVal = NULL;

	if ( !k ) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_SCHEME_UNKNOWN;
	};

	pVal = k->value;

	return PKI_X509_KEYPAIR_VALUE_get_scheme ( pVal );
};

/*!
 * \brief Returns the signing scheme from a keypair value
 */

PKI_SCHEME_ID PKI_X509_KEYPAIR_VALUE_get_scheme(const PKI_X509_KEYPAIR_VALUE *pVal) {

	PKI_SCHEME_ID ret = PKI_SCHEME_UNKNOWN;
		// Return Value

	int pkey_type = 0;

	if ( !pVal ) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return ret;
	}

	// Let's get the type of the keypair
	pkey_type = PKI_X509_KEYPAIR_VALUE_get_id(pVal);
	if ( pkey_type == PKI_ID_UNKNOWN) {
		PKI_DEBUG("ERROR, can not get the type of the keypair to get the scheme!");
		return ret;
	}

	// Maps the type of the keypair to the scheme
	switch(pkey_type) {

		case PKI_ALGOR_DSA:
			ret = PKI_SCHEME_DSA;
			break;

		case PKI_ALGOR_RSA:
		case PKI_ALGOR_RSAPSS:
			ret = PKI_SCHEME_RSA;
			break;

#ifdef ENABLE_ECDSA
		case PKI_ALGOR_ECDSA:
			ret = PKI_SCHEME_ECDSA;
			break;
#endif

#ifdef ENABLE_OQS

		case PKI_ALGOR_DILITHIUM2:
		case PKI_ALGOR_DILITHIUM3:
		case PKI_ALGOR_DILITHIUM5: {
			ret = PKI_SCHEME_DILITHIUM;
		} break;

		case PKI_ALGOR_FALCON512:
		case PKI_ALGOR_FALCON1024: {
			ret = PKI_SCHEME_FALCON;
		} break;

		case PKI_ALGOR_KYBER512:
		case PKI_ALGOR_KYBER768:
		case PKI_ALGOR_KYBER1024: {
			ret = PKI_SCHEME_KYBER;
		} break;

		case PKI_ALGOR_SPHINCS_SHA256_128_R:
		case PKI_ALGOR_SPHINCS_SHAKE256_128_R: {
			ret = PKI_SCHEME_SPHINCS;
		} break;

#endif

		default: {
#ifdef ENABLE_COMPOSITE

			PKI_DEBUG("Looking up the pkey_type (%d) in the composite list", pkey_type);

			// Generic Composite
			if (PKI_ID_is_composite(pkey_type)) {
				ret = PKI_SCHEME_COMPOSITE;
				PKI_DEBUG("Found a composite type (%d)", ret);
			} else if (PKI_ID_is_explicit_composite(pkey_type, &ret)) {
				// Scheme ID and PKEY types are the same
				// Nothing to do, ret was already retrieved
				PKI_DEBUG("Found an explicit composite type (%d)", ret);
			} else {
				ret = PKI_SCHEME_UNKNOWN;
				PKI_DEBUG("Cannot select the scheme for pkey_type = %d (%d)", pkey_type, ret);
			}

		// 	if ( pkey_type == OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_OID)) {
		// 		return PKI_SCHEME_COMPOSITE;
		// 	// Explicit Composite
		// 	} else if (   pkey_type == OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_SHA256_OID)
		// 			   || pkey_type == OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSAPSS_SHA256_OID)
		// 			   || pkey_type == OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_P256_SHA256_OID)
		// 			   || pkey_type == OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_BRAINPOOL256_SHA256_OID)
		// 			   || pkey_type == OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ED25519_OID)
		// 			   || pkey_type == OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_P384_SHA384_OID)
		// 			   || pkey_type == OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_BRAINPOOL384_SHA384_OID)
		// 			   || pkey_type == OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_ED448_OID)
		// 			   || pkey_type == OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_P256_SHA256_OID)
		// 			   || pkey_type == OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_BRAINPOOL256_SHA256_OID)
		// 			   || pkey_type == OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_OID)
		// 			   || pkey_type == OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_P256_SHA256_OID)
		// 			   || pkey_type == OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_BRAINPOOL256_SHA256_OID)
		// 			   || pkey_type == OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_ED25519_OID)
		// 			   ) {
		// 		return (PKI_SCHEME_ID)pkey_type;
		//    }
#endif
		} // End of default

	} // End of switch()

	// All done.
	return ret;
};

/*!
 * \brief Returns the default signing algorithm from a keypair
 */

PKI_X509_ALGOR_VALUE * PKI_X509_KEYPAIR_get_algor (const PKI_X509_KEYPAIR *k ) {

	PKI_X509_ALGOR_VALUE *ret = NULL;
	PKI_X509_KEYPAIR_VALUE *pVal = NULL;

	if ( !k ) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return ret;
	};

	pVal = k->value;

	return PKI_X509_KEYPAIR_VALUE_get_algor( pVal );
}


int PKI_X509_KEYPAIR_get_id(const PKI_X509_KEYPAIR * key) {

	// Input check
	if (!key || !key->value) return PKI_ID_UNKNOWN;

	// Forward
	return PKI_X509_KEYPAIR_VALUE_get_id(key->value);
}

int PKI_X509_KEYPAIR_VALUE_get_id(const PKI_X509_KEYPAIR_VALUE * pkey) {

	int pkey_type = PKI_ID_UNKNOWN;

	// Input Check
	if (!pkey) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ID_UNKNOWN;
	}

#if OPENSSL_VERSION_NUMBER < 0x1010000fL
	pkey_type = EVP_PKEY_type(pVal->type);
#else
	pkey_type = EVP_PKEY_type(EVP_PKEY_id(pkey));
#endif

	// Returns the PKEY ID
	return pkey_type;
}

int PKI_X509_KEYPAIR_get_default_digest(const PKI_X509_KEYPAIR * key) {
    return PKI_X509_KEYPAIR_VALUE_get_default_digest(key ? key->value : NULL);
}

int PKI_X509_KEYPAIR_VALUE_get_default_digest(const PKI_X509_KEYPAIR_VALUE * pkey) {

	int def_nid = PKI_ID_UNKNOWN;
		// Return Value

	// Input Check
	if (!pkey) return PKI_ID_UNKNOWN;

	// Retrieves the default digest for the PKEY
	int digestResult = EVP_PKEY_get_default_digest_nid((PKI_X509_KEYPAIR_VALUE *)pkey, &def_nid);

	// Check for error condition
	if (digestResult <= 0) {
		PKI_ERROR(PKI_ERR_ALGOR_UNKNOWN, NULL);
		return PKI_ID_UNKNOWN;
	}

	// All Done
	return def_nid;
}

int PKI_X509_KEYPAIR_requires_digest(const PKI_X509_KEYPAIR * k) {

	// Input Check
	if (!k || !k->value) return PKI_ERR;

	return PKI_X509_KEYPAIR_requires_digest(k->value);
}

int PKI_X509_KEYPAIR_VALUE_requires_digest(const PKI_X509_KEYPAIR_VALUE * pkey) {

	PKI_SCHEME_ID scheme_id = PKI_SCHEME_UNKNOWN;
		// Scheme identifier

	int def_nid = PKI_ID_UNKNOWN;
		// Combined algorithms ID

	// Input Check
	if (!pkey) return PKI_ERR;

	// Retrieves the default digest for the PKEY
	int digestResult = EVP_PKEY_get_default_digest_nid((PKI_X509_KEYPAIR_VALUE *)pkey, &def_nid);

	// Check for error condition
	if (digestResult <= 0) {
		PKI_ERROR(PKI_ERR_ALGOR_UNKNOWN, NULL);
		return PKI_ID_UNKNOWN;
	}

	// Checks if the returned default is the mandatory one
	if (digestResult == 2) return PKI_OK;

	scheme_id = PKI_X509_KEYPAIR_VALUE_get_scheme(pkey);
	if (scheme_id <= 0) {
		PKI_ERROR(PKI_ERR_ALGOR_UNKNOWN, NULL);
		return PKI_ERR;
	}

	// Let's return the result of the check on the scheme
	return PKI_SCHEME_ID_requires_digest(scheme_id);
}

int PKI_X509_KEYPAIR_is_digest_supported(const PKI_X509_KEYPAIR * k, const PKI_DIGEST_ALG * digest) {

	// Input Check
	if (!k || !k->value) return PKI_ERR;

	return PKI_X509_KEYPAIR_VALUE_is_digest_supported(k->value, digest);
}

int PKI_X509_KEYPAIR_VALUE_is_digest_supported(const PKI_X509_KEYPAIR_VALUE * pkey, const PKI_DIGEST_ALG * digest) {

	int def_nid = PKI_ID_UNKNOWN;
		// Default digest ID

	int algor_nid = PKI_ID_UNKNOWN;
		// Combined algorithms ID

	// Input Check
	if (!pkey) return PKI_ERR;

	// Retrieves the default digest for the PKEY
	int digestResult = EVP_PKEY_get_default_digest_nid((PKI_X509_KEYPAIR_VALUE *)pkey, &def_nid);

	// Check for error condition
	if (digestResult <= 0) {
		PKI_ERROR(PKI_ERR_ALGOR_UNKNOWN, NULL);
		return PKI_ID_UNKNOWN;
	}

	// Checks if the returned default is the mandatory one
	if (digestResult == 2 && EVP_MD_nid(digest) != def_nid) {
		return PKI_ERR;
	}

	// Checks the combined OID existence
	if (!OBJ_find_sigid_by_algs(&algor_nid, EVP_MD_nid(digest), EVP_PKEY_id(pkey))) {
		// Combined Algorithm is not found
		return PKI_ERR;
	}

	// All Done
	return PKI_OK;
}

/*!
 * \brief Returns the default signing algorithm from a keypair value
 */
PKI_X509_ALGOR_VALUE * PKI_X509_KEYPAIR_VALUE_get_algor(const PKI_X509_KEYPAIR_VALUE *pVal) {

	PKI_X509_ALGOR_VALUE *ret = NULL;
	// int pkey_type = 0;

	// int size = 0;
	int algId = NID_undef;
	// int digestId = NID_undef;

	int def_ret = -1, def_nid = -1;
		// OpenSSL return code

	PKI_SCHEME_ID scheme = PKI_X509_KEYPAIR_VALUE_get_scheme(pVal);
	PKI_DEBUG("SCHEME ID = %d", scheme);

	if (PKI_SCHEME_ID_is_explicit_composite(scheme)) {

		// Explicit does not use any global hash algorithm
		// we can safely use the same ID as the PKEY for the
		// signature algorithm
		algId = EVP_PKEY_type(EVP_PKEY_id(pVal));

		// Gets the algorithm
		ret = PKI_X509_ALGOR_VALUE_new_type(EVP_PKEY_type(EVP_PKEY_id(pVal)));
		if (!ret) {
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			return NULL;
		}
		
	} else if (PKI_SCHEME_ID_is_post_quantum(scheme) == PKI_OK) {

		PKI_DEBUG("SCHEME is a post-quantum scheme");

		// PQC does not have a default digest, we use direct signing
		algId = EVP_PKEY_type(EVP_PKEY_id(pVal));

		// Gets the algorithm
		ret = PKI_X509_ALGOR_VALUE_new_type(EVP_PKEY_type(EVP_PKEY_id(pVal)));
		
	} else {

		PKI_DEBUG("SCHEME is not a explicit composite ");
	
		// Retrieves the default digest
		def_ret = EVP_PKEY_get_default_digest_nid((EVP_PKEY *)pVal, &def_nid);

		if (def_ret <= 0 || def_nid == NID_undef) {
			// Error or No digest is supported
			PKI_DEBUG("No default digest for algorithm (%d), using the PKEY as the Algorithm ID");
			algId = EVP_PKEY_id(pVal);
			ret = PKI_X509_ALGOR_VALUE_new_type(algId);
		} else if (def_nid != NID_undef) {
			// Digest supported, let's use it
			if (!OBJ_find_sigid_by_algs(&algId, def_nid, EVP_PKEY_id(pVal))) {
				// No default algorithm found, let's return the PKEY id
				ret = PKI_X509_ALGOR_VALUE_new_type(EVP_PKEY_type(EVP_PKEY_id(pVal)));
			}
			PKI_DEBUG("Got the default signing algorithm ID from the KEY value");
			// Gets the algorithm
			ret = PKI_X509_ALGOR_VALUE_new_type(algId);
		}
	}

	if (!ret) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	// Debugging
	PKI_DEBUG("------> algId: %d, ret: %p", algId, ret);

	// All Done
	return ret;

// 	// For OQS/PQC we do not use a default hash (null is ok)
// 	if (PKI_SCHEME_ID_requires_digest(scheme_id)) {
// 		// Debugging Info
// 		PKI_DEBUG("ALGOR requires Digest (SCHEME: %d, ALGOR: %d)",scheme_id, EVP_PKEY_id(pVal));
// 		// Gets the default digest for the algorithm
// 		if (!OBJ_find_sigid_by_algs(&algId, PKI_DIGEST_ALG_ID_DEFAULT, EVP_PKEY_id(pVal))) {
// 			// No default algorithm found, let's return the PKEY id
// 			algId = PKI_X509_KEYPAIR_VALUE_get_id(pVal);
// 		}
// 		if (!OBJ_find_sigid_by_algs(&algId, PKI_DIGEST_ALG_ID_DEFAULT, EVP_PKEY_id(pVal))) {
// 			// No default algorithm found, let's return the PKEY id
// 			algId = PKI_X509_KEYPAIR_VALUE_get_id(pVal);
// 		}
// 	} else if (PKI_SCHEME_ID_is_post_quantum(scheme_id)) {
// 		// OQS/PQC uses the same OID for PKEY and SIGS
// 		// when no digest is used
// 		algId = PKI_X509_KEYPAIR_VALUE_get_id(pVal);
// 	} else {
// 		// Search for the default algorithm without hash
// 		if (!OBJ_find_sigid_by_algs(&algId, PKI_DIGEST_ALG_ID_NULL, EVP_PKEY_id(pVal))) {
// 			// Search for the default algorithm with default hash
// 			if (!OBJ_find_sigid_by_algs(&algId, PKI_DIGEST_ALG_ID_DEFAULT, EVP_PKEY_id(pVal))) {
// 				// No default algorithm found, let's return the PKEY id
// 				algId = PKI_X509_KEYPAIR_VALUE_get_id(pVal);
// 			}
// 		}
// 	}

// 	if (algId != NID_undef) {
// 		PKI_DEBUG("Returning Algorithm ID => %d", algId);
// 		return PKI_X509_ALGOR_VALUE_new_type(EVP_PKEY_id(pVal));
// 	}

// #if OPENSSL_VERSION_NUMBER < 0x1010000fL
// 	pkey_type = EVP_PKEY_type(pVal->type);
// #else
// 	pkey_type = EVP_PKEY_type(EVP_PKEY_id(pVal));
// #endif

// 	switch (pkey_type)
// 	{
// 		case EVP_PKEY_DSA:
// 			algId = PKI_ALGOR_DSA_SHA256;
// 			break;

// 		case EVP_PKEY_RSA:
// 			algId = PKI_ALGOR_RSA_SHA256;
// 			break;

// #ifdef ENABLE_ECDSA
// 		case EVP_PKEY_EC:
// 			if ( size < 384 ) {
// 				algId = PKI_ALGOR_ECDSA_SHA256;
// 			} else if ( size < 512 ) {
// 				algId = PKI_ALGOR_ECDSA_SHA384;
// 			} else {
// 				algId = PKI_ALGOR_ECDSA_SHA512;
// 			};
// 			break;
// #endif

// #ifdef ENABLE_OQS

// 		// Open Quantum Safe Algos
// 		case PKI_ALGOR_FALCON512:
// 		case PKI_ALGOR_FALCON1024:
// 		case PKI_ALGOR_DILITHIUM2:
// 		case PKI_ALGOR_DILITHIUM3:
// 		case PKI_ALGOR_DILITHIUM5:
// 		case PKI_ALGOR_DILITHIUM2_AES:
// 		case PKI_ALGOR_DILITHIUM3_AES:
// 		case PKI_ALGOR_DILITHIUM5_AES:
// 		case PKI_ALGOR_SPHINCS_SHA256_128_R:
// 		case PKI_ALGOR_SPHINCS_SHAKE256_128_R:
// 			algId = pkey_type;
// 			break;

// 		// Composite Crypto Quantum Safe Algos
// 		case PKI_ALGOR_COMPOSITE_RSA_FALCON512:
// 		case PKI_ALGOR_COMPOSITE_ECDSA_FALCON512:
// 		case PKI_ALGOR_COMPOSITE_ECDSA_FALCON1024:
// 		case PKI_ALGOR_COMPOSITE_RSA_DILITHIUM2:
// 		case PKI_ALGOR_COMPOSITE_ECDSA_DILITHIUM2:
// 		case PKI_ALGOR_COMPOSITE_ECDSA_DILITHIUM3:
// 		case PKI_ALGOR_COMPOSITE_ECDSA_DILITHIUM5:
// 			algId = pkey_type;
// 			break;
// #endif

// 		default:
// 			PKI_DEBUG("Algorithm not found in static methods [%d]", pkey_type);
// 	};

// 	// Address the dynamic methods
// #ifdef ENABLE_COMPOSITE

// 	if (algId <= NID_undef) {
// 		if (algId <= NID_undef && pkey_type == OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_OID)) {
// 			algId = OBJ_txt2nid(OPENCA_ALG_SIGS_COMP_SHA512_OID);
// 		}
// 	}

// 	// Checks for the Explicit Composite Crypto combinations
// 	if (algId <= NID_undef && (
// 			// Dilithium3 - Standard Explicit
// 			pkey_type == OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_SHA256_OID) ||
// 			pkey_type == OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_P256_SHA256_OID) ||
// 			pkey_type == OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_BRAINPOOL256_SHA256_OID) ||
// 			pkey_type == OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ED25519_OID) ||
// 			// Dilithium5 - Standard Explicit
// 			pkey_type == OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_P384_SHA384_OID) ||
// 			pkey_type == OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_BRAINPOOL384_SHA384_OID) ||
// 			pkey_type == OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_ED448_OID) ||
// 			// Falcon512 - Standard Explicit
// 			pkey_type == OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_P256_SHA256_OID) || 
// 			pkey_type == OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_BRAINPOOL256_SHA256_OID) || 
// 			pkey_type == OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_OID) ||
// 			// Sphincs256 - Standard Explicit
// 			pkey_type == OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_P256_SHA256_OID) ||
// 			pkey_type == OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_BRAINPOOL256_SHA256_OID) ||
// 			pkey_type == OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_ED25519_OID) ||
// 			// RSA PSS
// 			pkey_type == OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSAPSS_SHA256_OID) ||
// 			// Non-Standard Explicit Combinations
// 			pkey_type == OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_RSA_SHA256_OID) || 
// 			pkey_type == OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_P521_SHA512_OID) ||
// 			pkey_type == OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_RSA_SHA256_OID) ||
// 			pkey_type == OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_RSA_SHA256_OID))) {
// 		// Sets the default algorithm ID to be the same as the key ID
// 		// (no hash support for now for explicit)
// 		algId = pkey_type;
// 	}
// #endif

// #ifdef ENABLE_COMBINED
// 	if (algId == NID_undef && pkey_type == OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_ALT_OID)) {
// 		algId = OBJ_txt2nid(OPENCA_ALG_SIGS_ALT_SHA512_OID);
// 	}
// #endif

// 	// Experimental - Native PQC implementation
// 	if (algId <= 0) {
// 		if (pkey_type == OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_DILITHIUMX_OID)) {
// 			algId = OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_DILITHIUMX_OID);
// 		}
// 	}

// 	// Final checks
// 	if( algId > 0 ) {
// 		ret = PKI_X509_ALGOR_VALUE_get(algId);
// 	} else {
// 		PKI_DEBUG("Algorithm not found in dynamic methods [%d]", pkey_type);
// 		PKI_ERROR(PKI_ERR_ALGOR_UNKNOWN, NULL);
// 	}

// 	// All Done
// 	return ret;
}

/*!
 * \brief Returns the size (in bits) of a pubkey
 */

int PKI_X509_KEYPAIR_get_size (const PKI_X509_KEYPAIR *k ) {

	PKI_X509_KEYPAIR_VALUE *pKey = NULL;

	if (!k) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return -1;
	};

	pKey = k->value;

	return PKI_X509_KEYPAIR_VALUE_get_size ( pKey );
}

/*!
 * \brief Returns the size (in bits) of a pubkey value
 */

int PKI_X509_KEYPAIR_VALUE_get_size (const PKI_X509_KEYPAIR_VALUE *pKey ) {

	int ret = -1;

	if (!pKey) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return ret;
	};

	return EVP_PKEY_bits((PKI_X509_KEYPAIR_VALUE *)pKey);
}

/*! \brief Returns the (unsigned char *) digest of a pubkey value */

PKI_DIGEST *PKI_X509_KEYPAIR_VALUE_pub_digest (const PKI_X509_KEYPAIR_VALUE * pkey,
					       					   const PKI_DIGEST_ALG         * md) {

	X509_PUBKEY *xpk = NULL;
	PKI_DIGEST * ret = NULL;
	 
	unsigned char * buf = NULL;
	int buf_size = 0;

	// Input Check
	if (!pkey) return NULL;

	// Check for MD (if not, let's use the default)
	if(!md) md = PKI_DIGEST_ALG_DEFAULT;

	// Sets the Public Key
	if(!X509_PUBKEY_set(&xpk, (EVP_PKEY *)pkey)) {
		PKI_DEBUG("Error building X509 PUBKEY data");
		return NULL;
	}

	// Checks the results of the set operation
	if (!xpk) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

#if OPENSSL_VERSION_NUMBER < 0x1010000fL

	buf = xpk->public_key->data;
	buf_size = xpk->public_key->length;

#else

	if (1 != X509_PUBKEY_get0_param(NULL, 
			(const unsigned char **)&buf, &buf_size, NULL, xpk)) {
		PKI_log_err("Can not get the PublicKeyInfo from the KeyPair.");
		X509_PUBKEY_free(xpk);
		return NULL;
	}

#endif

	// Calculates the digest over the DER representation of the pubkey
	if (buf != NULL && buf_size > 0) {

		// Gets the Digest Value
		if ((ret = PKI_DIGEST_new(md, buf, (size_t) buf_size)) == NULL) {
			PKI_DEBUG("Crypto Error: %s", ERR_error_string( ERR_get_error(), NULL ));
			X509_PUBKEY_free(xpk);
			return NULL;
		}
	}

	// Free the X509_KEYPAIR memory
	X509_PUBKEY_free(xpk);

	// Success
	return ret;
}

/*! \brief Returns the (unsigned char *) digest of the pubkey */

PKI_DIGEST *PKI_X509_KEYPAIR_pub_digest (const PKI_X509_KEYPAIR *k, 
						const PKI_DIGEST_ALG *md) {

	if( !k || !k->value ) return ( NULL );

	return PKI_X509_KEYPAIR_VALUE_pub_digest ( k->value, md );

}

/*! \brief Returns the passed PKI_X509_KEYPAIR in PKCS#8 format */

PKI_MEM *PKI_X509_KEYPAIR_get_p8 (const PKI_X509_KEYPAIR *k ) {

	BIO *mem = NULL;
	PKI_MEM *ret = NULL;
	PKI_X509_KEYPAIR_VALUE *pkey = NULL;

	if ( !k || !k->value ) return NULL;

	pkey = k->value;

	if((mem = BIO_new(BIO_s_mem())) == NULL ) {
		return NULL;
	}

	if(i2d_PKCS8PrivateKeyInfo_bio(mem, (EVP_PKEY *) pkey) > 0 ) {
		if( BIO_flush ( mem ) <= 0 ) {
			PKI_log_debug("ERROR flushing mem");
		}
		ret = PKI_MEM_new_bio ( mem, NULL );
	}

	BIO_free ( mem );

	return ( ret );
}

/*! \brief Reads a PKI_X509_KEYPAIR from a PKCS#8 format */

PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_new_p8 (const PKI_MEM *buf ) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED, NULL );

	return ( NULL );
}

/*!
 * \brief Returns a DER encoded Public Key
 */

PKI_MEM * PKI_X509_KEYPAIR_get_pubkey(const PKI_X509_KEYPAIR *kp)
{
	PKI_X509_KEYPAIR_VALUE *kVal = NULL;
	PKI_MEM *ret = NULL;

	if(!kp || !kp->value)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	};

	kVal = kp->value;

	if((ret = PKI_MEM_new_null())==NULL)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	};

	ret->size = (size_t) i2d_PUBKEY(kVal, &(ret->data));

	return ret;
}

/*!
 * \brief Returns a Private Key in PKCS#8 format
 */

PKI_MEM *PKI_X509_KEYPAIR_get_privkey(const PKI_X509_KEYPAIR *kp)
{
	return PKI_X509_KEYPAIR_get_p8(kp);

	/*
	PKI_X509_KEYPAIR_VALUE *kVal = NULL;
	PKI_X509_MEM *ret = NULL;

	if(!kp || !kp->value) reutrn PKI_ERR(PKI_ERROR_NULL_PARAM, NULL);

	kVal = kp->value;

	if((ret = PKI_X509_MEM_new_null())==NULL)
	{
		PKI_ERR(PKI_ERROR_NULL_PARAM, NULL);
		return NULL;
	};

	ret->size = i2d_PRIVKEY(kVal, &(ret->data));

	return ret;
	*/

};

/*!
 * \brief Returns the PKI_ID of the EC curve of the Key (EC keys only)
 */

int PKI_X509_KEYPAIR_get_curve (const PKI_X509_KEYPAIR *kp )
{
#ifdef ENABLE_ECDSA
	PKI_X509_KEYPAIR_VALUE *pVal = NULL;
	const EC_GROUP *gr;
	EC_GROUP *gr2;
	EC_KEY *ec = NULL;
	EC_POINT *point = NULL;
	BN_CTX *ctx = NULL;
	int ret = PKI_ID_UNKNOWN;

	EC_builtin_curve *curves = NULL;
	size_t num_curves = 0;
	int i;

	BIGNUM *order = NULL;

	unsigned long long keyBits = 0;
	unsigned long long curveBits = 0;

	pVal = kp->value;
	if (!pVal ) return PKI_ID_UNKNOWN;

	ctx = BN_CTX_new();

	switch (EVP_PKEY_type(EVP_PKEY_id(pVal)))
	{
		case EVP_PKEY_EC: {
			// ec = pVal->pkey.ec;
			if ((ec = EVP_PKEY_get1_EC_KEY(pVal)) == NULL) goto err;
		} break;

		default: {
			goto err;
		} break;
	}

	if ((gr = EC_KEY_get0_group(ec)) == NULL) return PKI_ID_UNKNOWN;

	order = BN_new();
	if (EC_GROUP_get_order(gr, order, NULL)) {
		keyBits = (unsigned long long) BN_num_bits(order);
	}
	BN_free( order );
	order = NULL;

	if((point = EC_POINT_new( gr )) == NULL ) {
		PKI_log_err("Can not generate a new point in Key's Group");
		goto err;
	};

	/* Get the number of availabe ECDSA curves in OpenSSL */
	if ((num_curves = EC_get_builtin_curves(NULL, 0)) < 1 ) {
		/* No curves available! */
		goto err;
	}

	/* Alloc the needed memory */
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
	curves = OPENSSL_malloc((int)(sizeof(EC_builtin_curve) * num_curves));
#else
	curves = OPENSSL_malloc(sizeof(EC_builtin_curve) * num_curves);
#endif
	if (curves == NULL) goto err;

	/* Get the builtin curves */
	if (!EC_get_builtin_curves(curves, num_curves)) goto err;

	// Allocates the BN
	order = BN_new();

	/* Cycle through the curves and display the names */
	for( i = 0; i < num_curves; i++ ) {
		int nid;

		nid = curves[i].nid;

		if(( gr2 = EC_GROUP_new_by_curve_name( nid )) == NULL) {
			PKI_log_err("Can not get default curve [%d]", i);
			break;
		};

		if (EC_GROUP_get_order(gr2, order, NULL)) {
			curveBits = (unsigned long long) BN_num_bits(order);
		};

		if ( curveBits == keyBits ) {
			if( EC_POINT_is_on_curve( gr2, point, ctx ) ) {
				ret = nid;
				break;
			};
		};

		if( gr2 ) EC_GROUP_free ( gr2 );
	};

	// Free Memory
	if (order) BN_free(order);
	if (curves) free(curves);
	if (ctx) BN_CTX_free(ctx);
	if (ec) EC_KEY_free(ec);

	// Return Result
	return ret;

err:

	// Free Memory
	if (order) BN_free (order);
	if (curves) free(curves);
	if (ctx) BN_CTX_free(ctx);
	if (ec) EC_KEY_free(ec);

	// Return Error
	return PKI_ID_UNKNOWN;

#else
	return PKI_ID_UNKNOWN;
#endif
}

PKI_MEM * PKI_X509_KEYPAIR_VALUE_encrypt(const PKI_X509_KEYPAIR_VALUE * pVal, 
                                    	 const unsigned char          * const data, 
                                   		 size_t                         const data_len,
                                   		 int                            const flags) {

	EVP_PKEY * pkey = (EVP_PKEY *)pVal;
		// Pointer to the keypair value

	EVP_PKEY_CTX * pkey_ctx = NULL;
		// Pointer to the EVP context

	PKI_MEM * out_mem = NULL;
		// Output buffer

	int padding = -1;
		// Padding

	size_t enc_size = 0;
		// Encrypted data max size

	// Input Checks
	if (!pVal || !data || data_len == 0) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	// Checks the padding
	if (flags <= 0) {
		if (EVP_PKEY_RSA == EVP_PKEY_id(pkey) || 
		    EVP_PKEY_RSA2 == EVP_PKEY_id(pkey) ||
		    EVP_PKEY_RSA_PSS == EVP_PKEY_id(pkey)) {
		   // RSA supports encryption and different
		   // padding options, let's set the default
		   padding = RSA_PKCS1_OAEP_PADDING;
		}
	} else {
		padding = flags;
	}

	// Creates a new PKEY context
	if ((pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	// Initializes the Encryption Process (will fail for key pairs
	// that do not support encryption)
	if (EVP_PKEY_encrypt_init(pkey_ctx) <= 0) {
		PKI_ERROR(PKI_ERR_X509_KEYPAIR_ENCRYPT_INIT, NULL);
		goto err;
	}

	// Sets the padding, if one is set
	if (padding > 0) {

		// Sets the padding via the CTRL interface
		switch (EVP_PKEY_id(pkey)) {

			// RSA Algorithm(s)
			case EVP_PKEY_RSA:
			case EVP_PKEY_RSA2:
			case EVP_PKEY_RSA_PSS: {
				if (EVP_PKEY_CTX_ctrl(pkey_ctx, EVP_PKEY_id(pkey), EVP_PKEY_OP_ENCRYPT, EVP_PKEY_CTRL_RSA_PADDING, padding, NULL) <= 0) {
					PKI_ERROR(PKI_ERR_X509_KEYPAIR_ENCRYPT_INIT, NULL);
					goto err;
				}
			} break;

			// Default Algorithms
			default:
				PKI_DEBUG("Public Key Type %d does not support encryption");
				goto err;
		}
	}

	//Let's encrypt the data
	if (EVP_PKEY_encrypt(pkey_ctx, NULL, &enc_size, data, data_len) <= 0) {
		PKI_ERROR(PKI_ERR_X509_KEYPAIR_ENCRYPT, NULL);
		goto err;
	}

	// Let's allocate the output buffer
	if ((out_mem = PKI_MEM_new(enc_size)) == NULL) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		goto err;
	}

	//Let's encrypt the data
	if (EVP_PKEY_encrypt(pkey_ctx, out_mem->data, &out_mem->size, data, data_len) <= 0) {
		PKI_ERROR(PKI_ERR_X509_KEYPAIR_ENCRYPT, NULL);
		goto err;
	}

	// Free allocated CTX
	if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
	pkey_ctx = NULL; // Safety

	// All Done.
	return out_mem;

err:

	// Free allocated memory
	if (out_mem) PKI_MEM_free(out_mem);
	out_mem = NULL; // Safety

	// Free the CTX from OpenSSL
	if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
	pkey_ctx = NULL; // Safety

	// Error condition
	return NULL;
}

PKI_MEM * PKI_X509_KEYPAIR_encrypt(const PKI_X509_KEYPAIR * keypair, 
                                   const unsigned char    * const data, 
                                   size_t                   const data_len,
                                   int                      const flags) {

	// Wrapper for the call to the lower crypto layer
	return PKI_X509_KEYPAIR_VALUE_encrypt(PKI_X509_get_value(keypair), data, data_len, flags);
}

PKI_MEM * PKI_X509_KEYPAIR_VALUE_decrypt(const PKI_X509_KEYPAIR_VALUE * pVal, 
                                         const unsigned char          * const data, 
                                         size_t                         const data_len,
                                         int                            const flags) {
	
	EVP_PKEY * pkey = (EVP_PKEY *)pVal;
		// Pointer to the keypair value

	EVP_PKEY_CTX * pkey_ctx = NULL;
		// Pointer to the EVP context

	PKI_MEM * out_mem = NULL;
		// Output buffer

	int padding = -1;
		// Padding

	size_t dec_size = 0;
		// Size of decrypted data

	// Input Checks
	if (!pVal || !data || data_len == 0) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	// Checks the padding
	if (flags <= 0) {
		if (EVP_PKEY_RSA == EVP_PKEY_id(pkey) || 
		    EVP_PKEY_RSA2 == EVP_PKEY_id(pkey) ||
		    EVP_PKEY_RSA_PSS == EVP_PKEY_id(pkey)) {
		   // RSA supports encryption and different
		   // padding options, let's set the default
		   padding = RSA_PKCS1_OAEP_PADDING;
		}
	} else {
		padding = flags;
	}

	// Creates a new PKEY context
	if ((pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	// Initializes the Encryption Process (will fail for key pairs
	// that do not support encryption)
	if (!EVP_PKEY_decrypt_init(pkey_ctx)) {
		PKI_ERROR(PKI_ERR_X509_KEYPAIR_ENCRYPT_INIT, NULL);
		return NULL;
	}

	// Sets the padding, if one is set
	if (padding > 0) {

		// Sets the padding via the CTRL interface
		switch (EVP_PKEY_id(pkey)) {

			// RSA Algorithm(s)
			case EVP_PKEY_RSA:
			case EVP_PKEY_RSA2:
			case EVP_PKEY_RSA_PSS: {
				if (EVP_PKEY_CTX_ctrl(pkey_ctx, EVP_PKEY_id(pkey), EVP_PKEY_OP_DECRYPT, EVP_PKEY_CTRL_RSA_PADDING, padding, NULL) <= 0) {
					PKI_ERROR(PKI_ERR_X509_KEYPAIR_ENCRYPT_INIT, NULL);
					goto err;
				}
			} break;

			// Default Algorithms
			default:
				PKI_DEBUG("Public Key Type %d does not support encryption");
				goto err;
		}
	}

	// Let's get the output buffer size
	if (!EVP_PKEY_decrypt(pkey_ctx, NULL, &dec_size, data, data_len)) {
		PKI_ERROR(PKI_ERR_X509_KEYPAIR_ENCRYPT, NULL);
		return NULL;
	}

	// Let's allocate the output buffer
	if ((out_mem = PKI_MEM_new(dec_size)) == NULL) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	// Let's decrypt the data
	if (!EVP_PKEY_decrypt(pkey_ctx, out_mem->data, &out_mem->size, data, data_len)) {
		PKI_ERROR(PKI_ERR_X509_KEYPAIR_ENCRYPT, NULL);
		return NULL;
	}

	// Free allocated CTX
	if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
	pkey_ctx = NULL; // Safety

	// All Done.
	return out_mem;

err:

	// Free allocated memory
	if (out_mem) PKI_MEM_free(out_mem);
	out_mem = NULL; // Safety

	// Free the CTX from OpenSSL
	if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
	pkey_ctx = NULL; // Safety

	// Error condition
	return NULL;
}

PKI_MEM * PKI_X509_KEYPAIR_decrypt(const PKI_X509_KEYPAIR * keypair, 
                                   const unsigned char    * const data, 
                                   size_t                   const data_len,
                                   int                      const flags) {

	// Wrapper for lower-layer crypto call
	return PKI_X509_KEYPAIR_VALUE_decrypt(PKI_X509_get_value(keypair), data, data_len, flags);
}

/*! \brief Puts a X509_KEYPAIR to a PKI_MEM */

PKI_MEM *PKI_X509_KEYPAIR_get_public_bitstring(const PKI_X509_KEYPAIR  * key, 
							                   PKI_MEM       	      ** pki_mem) {

	PKI_X509_KEYPAIR_VALUE * k_val = NULL;
		// Pointer to the underlying crypto-layer

	// Input checks
	if (!key) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	// Gets the value and calls the lower-level function
	k_val = PKI_X509_get_value(key);

	// All done
	return PKI_X509_KEYPAIR_VALUE_get_public_bitstring(k_val, pki_mem);
}

/*! \brief Puts a X509_KEYPAIR_VALUE's raw key value into a PKI_MEM */

PKI_MEM *PKI_X509_KEYPAIR_VALUE_get_public_bitstring(const PKI_X509_KEYPAIR_VALUE  * const k_val, 
							  		                 PKI_MEM          		      ** pki_mem) {

	const unsigned char * buff;
	int len = 0;
		// Output buffer for the raw key

	X509_PUBKEY * xpk = NULL;
		// Data structures to extract the raw data

	PKI_MEM * ret = NULL;
		// Return data structure

	// Input checks
	if (!k_val) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	// Sets the Public Key
	if(!X509_PUBKEY_set(&xpk, (EVP_PKEY *)k_val)) {
		PKI_ERROR(PKI_ERR_X509_KEYPAIR_ENCODE, NULL);
		return NULL;
	}

	// Checks we have a good pointer
	if (!xpk) {
		PKI_ERROR(PKI_ERR_POINTER_NULL, NULL);
		return NULL;
	}

	// Extracts the Public Key
	if (!X509_PUBKEY_get0_param(NULL, (const unsigned char **)&buff, &len, NULL, xpk)) {
		PKI_ERROR(PKI_ERR_X509_KEYPAIR_ENCODE, NULL);
		X509_PUBKEY_free(xpk);
		return NULL;
	}

	// Checks if to re-use the passed structure or create a new one
	if (pki_mem && *pki_mem) {
		// Uses the passed PKI_MEM structure
		ret = *pki_mem;
		// Frees the data, if any is present
		if (ret->data) PKI_Free(ret->data);
		ret->data = NULL;
		// Allocates the new buffer and copies the data
		if (PKI_OK != PKI_MEM_add(ret, buff, (size_t)len)) {
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			return NULL;
		}
	} else if (pki_mem) {
		// Let's generate the return object
		if ((ret = PKI_MEM_new_data((size_t)len, buff)) == NULL) {
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			return NULL;
		}
		// Let's update the output parameter
		if (pki_mem) *pki_mem = ret;
	}

	// Free heap memory
	if (xpk) X509_PUBKEY_free(xpk);
	xpk = NULL;

	// All Done
	return ret;
}