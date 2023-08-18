/* openssl/pki_keyparams.c */

#include <libpki/pki.h>

#include <libpki/datatypes.h>

/*!
 * \brief Allocates memory for a new PKI_KEYPARAMS (for key of type 'scheme')
 */

PKI_KEYPARAMS *PKI_KEYPARAMS_new(PKI_SCHEME_ID 			  scheme_id, 
				  				 const PKI_X509_PROFILE * prof) {

	PKI_KEYPARAMS *kp = NULL;
		// Pointer to the data structure

	// Allocates the memory
	if ((kp = (PKI_KEYPARAMS *)PKI_Malloc(sizeof(PKI_KEYPARAMS))) == NULL) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	// Zeroize the Memory
	memset(kp, 0, sizeof(PKI_KEYPARAMS));

	// Sets the security bits
	kp->sec_bits = -1;
	kp->pq_sec_bits = -1;

	// Checks and Fixes the Scheme
	if (scheme_id <= 0) { scheme_id = PKI_SCHEME_DEFAULT; } 
	
	// Sets the scheme
	if (PKI_ERR == PKI_KEYPARAMS_set_scheme(kp, scheme_id, PKI_DEFAULT_CLASSIC_SEC_BITS)) {
		PKI_DEBUG("ERROR, can not set the scheme (%d)", scheme_id);
		PKI_Free(kp);
		return NULL;
	}


#ifdef ENABLE_COMPOSITE

	// Allocates the memory for the stack of keys (composite keys)
	if ((kp->comp.k_stack = PKI_STACK_X509_KEYPAIR_new()) == NULL) {
		OPENSSL_free(kp);
		return NULL;
	}

	kp->comp.k_of_n = NULL;

#endif

	if (prof) {
		
		// PKI_X509_ALGOR_VALUE *alg = NULL;
		char *tmp_s = NULL;

		// Scheme
		if (scheme_id <= 0 ) {
			if(( tmp_s = PKI_CONFIG_get_value(prof, 
						"/profile/keyParams/algorithm" )) != NULL ) {
				// if((alg = PKI_X509_ALGOR_VALUE_get_by_name(tmp_s)) != NULL ) {
				PKI_SCHEME_ID scheme_id = PKI_SCHEME_ID_get_by_name(tmp_s, NULL, NULL);
				if (!scheme_id) {
					PKI_DEBUG("ERROR, can not get the scheme id for %s", tmp_s);
					PKI_Free(tmp_s);
					PKI_KEYPARAMS_free(kp);
					return NULL;
				}
				if (PKI_ERR == PKI_KEYPARAMS_set_scheme(kp, scheme_id, -1)) {
					PKI_DEBUG("ERROR, can not set the scheme (%d)", scheme_id);
					PKI_Free(tmp_s);
					PKI_KEYPARAMS_free(kp);
					return NULL;
				}
				// kp->scheme = PKI_X509_ALGOR_VALUE_get_scheme ( alg );
				// }

				// TODO: Remove this debug statement
				PKI_DEBUG("Selected ALGOR is %s\n", tmp_s );

				PKI_Free ( tmp_s );
			};
		} else {
			kp->scheme = scheme_id;
		}

		// // Get the Profile value of Bits
		// if ((tmp_s = PKI_CONFIG_get_value(prof, 
		// 			"/profile/keyParams/bits" )) != NULL ) {
		// 	if (PKI_ERR == PKI_KEYPARAMS_set_security_bits(kp, atoi(tmp_s))) {
		// 		PKI_DEBUG("ERROR, can not set the security bits from the profile (%s)!", tmp_s);
		// 		PKI_KEYPARAMS_free(kp);
		// 		PKI_Free(tmp_s);
		// 		return NULL;
		// 	}
		// 	PKI_Free ( tmp_s );
		// } else {
		// 	kp->bits = -1;
		// };
		
		if( kp->scheme == PKI_SCHEME_UNKNOWN ) kp->scheme = PKI_SCHEME_DEFAULT;

		// Looks for the security bits
		if ((tmp_s = PKI_CONFIG_get_value(prof, 
					"/profile/keyParams/secBits" )) != NULL ) {
			// Sets the configured security bits
			if (PKI_ERR == PKI_KEYPARAMS_set_security_bits(kp, atoi(tmp_s))) {
				PKI_DEBUG("ERROR, can not set the security bits from the profile (%s)!", tmp_s);
				PKI_KEYPARAMS_free(kp);
				PKI_Free(tmp_s);
				return NULL;
			}
			PKI_Free(tmp_s);
		} else {
			// Use the default
			if (PKI_ERR == PKI_KEYPARAMS_set_scheme(kp, kp->scheme, PKI_DEFAULT_CLASSIC_SEC_BITS)) {
				PKI_DEBUG("ERROR, can not set the security bits from the profile (%d)!", PKI_DEFAULT_CLASSIC_SEC_BITS);
				PKI_KEYPARAMS_free(kp);
				return NULL;
			}
		}

		// Get the Profile Params
		switch (kp->scheme) {

#if defined(ENABLE_OQS) || defined(ENABLE_OQSPROV)

			case PKI_SCHEME_DILITHIUM: {
				if ((tmp_s = PKI_CONFIG_get_value(prof, 
							"/profile/keyParams/mode" )) != NULL ) {

					if (strncmp_nocase("AES", tmp_s, 3) == 0) {
						// Sets the correct algorithm
						PKI_KEYPARAMS_set_oqs_key_params(kp, PKI_ALGOR_OQS_PARAM_DILITHIUM_AES);
					}

					PKI_Free (tmp_s);
				};
			} break;

#endif

#ifdef ENABLE_ECDSA
			case PKI_SCHEME_ECDSA: {
				
				// Sets the standard defaults
				kp->ec.asn1flags = PKI_EC_KEY_ASN1_DEFAULT;
				kp->ec.form = PKI_EC_KEY_FORM_DEFAULT;

				if ((tmp_s = PKI_CONFIG_get_value(prof, 
							"/profile/keyParams/curveName" )) != NULL) {
					PKI_OID *oid = NULL;

					if((oid = PKI_OID_get( tmp_s )) != NULL) {
						if((kp->ec.curve = PKI_OID_get_id( oid )) == PKI_ID_UNKNOWN) {;
							kp->ec.curve = -1;
						};
						PKI_OID_free ( oid );
					}
					PKI_Free( tmp_s );
				};

				if(( tmp_s = PKI_CONFIG_get_value( prof,
							"/profile/keyParams/pointType" )) != NULL ) {
					if(strncmp_nocase( tmp_s, "uncompressed", 12) == 0 ) {
						kp->ec.form = PKI_EC_KEY_FORM_UNCOMPRESSED;
					} else if ( strncmp_nocase( tmp_s, "compressed", 10) == 0 ) {
						kp->ec.form = PKI_EC_KEY_FORM_COMPRESSED;
					} else if ( strncmp_nocase( tmp_s, "hybrid", 6) == 0 ) {
						kp->ec.form = PKI_EC_KEY_FORM_HYBRID;
					} else {
						kp->ec.form = PKI_EC_KEY_FORM_UNKNOWN;
					};
					PKI_Free ( tmp_s );
				};

				if(( tmp_s = PKI_CONFIG_get_value(prof, 
							"/profile/keyParams/ecParams" )) != NULL ) {
					if(strncmp_nocase(tmp_s, "namedCurve", 10) == 0) {
						kp->ec.asn1flags = 1;
					} else if (strncmp_nocase(tmp_s,"implicitCurve",13) == 0){
						kp->ec.asn1flags = 2;
					} else if (strncmp_nocase(tmp_s,"specifiedCurve",14) == 0){
						kp->ec.asn1flags = 0;
					} else {
						// Defaults to namedCurve
						kp->ec.asn1flags = 1;
					};
					PKI_Free ( tmp_s );
				} else {
					kp->ec.asn1flags = -1;
				};
			} break;

#endif // End of ENABLE_ECDSA

			case PKI_SCHEME_RSA:
			case PKI_SCHEME_RSAPSS: {
				if ((tmp_s = PKI_CONFIG_get_value(prof, 
					"/profile/keyParams/bits" )) != NULL ) {
					// Sets the configured security bits
					if (PKI_ERR == PKI_KEYPARAMS_set_security_bits(kp, atoi(tmp_s))) {
						PKI_DEBUG("ERROR, can not set the security bits from the profile (%s)!", tmp_s);
						PKI_KEYPARAMS_free(kp);
						PKI_Free(tmp_s);
						return NULL;
					}
					PKI_Free(tmp_s);
				}
			} break;

			default:
				PKI_DEBUG("No supported special parameter processing for selected algorithm (%d).", kp->scheme);
		}
	}

	// All Done
	return kp;
};

/*!
 * \brief Frees the memory associated with a PKI_KEYPARAMS structure
 */

void PKI_KEYPARAMS_free ( PKI_KEYPARAMS *kp ) {

	if (!kp) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return;
	};

#ifdef ENABLE_COMPOSITE

	if (kp->comp.k_stack) PKI_STACK_X509_KEYPAIR_free_all(kp->comp.k_stack);
	kp->comp.k_stack = NULL;

#endif
	PKI_Free ( kp );

	return;
};

/*!
 * \brief Returns the type (PKI_SCHEME_ID) of the PKI_KEYPARAMS
 */

PKI_SCHEME_ID PKI_KEYPARAMS_get_type(const PKI_KEYPARAMS *kp) {

	if (!kp) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_SCHEME_UNKNOWN;
	}

	return (PKI_SCHEME_ID)kp->scheme;
};

/* !\brief Sets the scheme for the key generation. Returns PKI_OK or PKI_ERR. */

int PKI_KEYPARAMS_set_scheme(PKI_KEYPARAMS * kp, PKI_SCHEME_ID scheme_id, int sec_bits) {

	int scheme_sec_bits = 0;
	int scheme_pq_sec_bits = 0;
		// Security bits for the scheme

	// Input checks
	if (kp == NULL || scheme_id <= 0) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	// Let's use the default, if nothing was passed
	if (sec_bits <= 0) sec_bits = PKI_DEFAULT_CLASSIC_SEC_BITS;

	// Let's check if the scheme supports the sec_bits
	if (PKI_ERR == PKI_SCHEME_ID_security_bits(scheme_id, &scheme_sec_bits, &scheme_pq_sec_bits)) {
		PKI_DEBUG("Can not get security bits for scheme %d", scheme_id);
		return PKI_ERR;
	}
	
	// If the returned value is positive, it means the scheme only supports
	// a single value for the size.
	if (scheme_sec_bits > 0) {
		// Returns an error if the sec_bits were actually set
		if (scheme_sec_bits < sec_bits) {
			PKI_DEBUG("Scheme %d only supports %d bits", scheme_id, scheme_sec_bits);
			return PKI_ERR;
		}
	}
	
	// Sets the security bits
	kp->sec_bits = sec_bits;
	
	// Sets the PQ security bits
	kp->pq_sec_bits = scheme_pq_sec_bits;

	// If the scheme supports more than one value (i.e., -1),
	// it means that we need to look in the switch below.
	switch (scheme_id) {

		case PKI_SCHEME_DSA: {
			kp->scheme = PKI_SCHEME_DSA;
			kp->pkey_type = EVP_PKEY_DSA;
			     if (sec_bits <= 112) { kp->dsa.bits = 1024 ; kp->sec_bits = 112; } 
			else if (sec_bits <= 128) { kp->dsa.bits = 3072; kp->sec_bits = 128; } 
			else { 
				PKI_DEBUG("Security Bits value not supported (%d) (max: 128)", sec_bits);
				return PKI_ERR;
			}
			kp->bits = kp->dsa.bits;
		} break;

		case PKI_SCHEME_RSAPSS:
		case PKI_SCHEME_RSA: {
			if (scheme_id == PKI_SCHEME_RSAPSS) {
				kp->pkey_type = EVP_PKEY_RSA_PSS;
				kp->scheme = PKI_SCHEME_RSAPSS;
			} else {
				kp->pkey_type = EVP_PKEY_RSA;
				kp->scheme = PKI_SCHEME_RSA;
			}
				// Sec sec_bits Sizes
			     if (sec_bits <= 112 ) { kp->rsa.bits = 2048; kp->sec_bits = 112; }
			else if (sec_bits <= 128 ) { kp->rsa.bits = 3072; kp->sec_bits = 128; }
			else if (sec_bits <= 192 ) { kp->rsa.bits = 4096; kp->sec_bits = 192; }
			else if (sec_bits <= 256 ) { kp->rsa.bits = 8192; kp->sec_bits = 256; }
			else if (sec_bits <= 384 ) { kp->rsa.bits = 16384; kp->sec_bits = 384; }
			else { 
				PKI_DEBUG("Security Bits value not supported (%d)", sec_bits);
				return -1;
			}
			kp->bits = kp->rsa.bits;
		} break;

		case PKI_SCHEME_ECDSA: {
			kp->scheme = PKI_SCHEME_ECDSA;
			kp->pkey_type = EVP_PKEY_EC;
				 if (sec_bits <= 112) { kp->ec.curve = NID_secp224r1 ; kp->sec_bits = 112; } 
			else if (sec_bits <= 128) { kp->ec.curve = NID_X9_62_prime256v1; kp->sec_bits = 128; } 
			else if (sec_bits <= 192) { kp->ec.curve = NID_secp384r1; kp->sec_bits = 192; }
			else if (sec_bits <= 256) { kp->ec.curve = NID_secp521r1; kp->sec_bits = 256; }
			else { 
				PKI_DEBUG("Security Bits value not supported (%d)", sec_bits);
				return -1;
			}
			kp->ec.asn1flags = -1;
			kp->ec.form = PKI_EC_KEY_FORM_UNKNOWN;
		} break;

		case PKI_SCHEME_ED448:
		case PKI_SCHEME_X448: {
			if (scheme_id == PKI_SCHEME_ED448) {
				kp->scheme = PKI_SCHEME_ED448;
				kp->pkey_type = EVP_PKEY_ED448;
			} else {
				kp->scheme = PKI_SCHEME_X448;
				kp->pkey_type = EVP_PKEY_X448;
			}
			if (sec_bits > 224) { 
				PKI_DEBUG("Security Bits value not supported (%d)", sec_bits);
				return -1;
			}
			kp->sec_bits = 224;
		} break;

		case PKI_SCHEME_ED25519:
		case PKI_SCHEME_X25519: {
			if (scheme_id == PKI_SCHEME_ED25519) {
				kp->scheme = PKI_SCHEME_ED25519;
				kp->pkey_type = EVP_PKEY_ED25519;
			} else {
				kp->scheme = PKI_SCHEME_X25519;
				kp->pkey_type = EVP_PKEY_X25519;
			}
			if (sec_bits > 128) { 
				PKI_DEBUG("Security Bits value not supported (%d)", sec_bits);
				return -1;
			}
			kp->sec_bits = 128;
		} break;

#if defined(ENABLE_OQS) || defined(ENABLE_OQSPROV)

		// =============================================
		// Post Quantum Cryptography: Digital Signatures
		// =============================================

		case PKI_SCHEME_FALCON: {
			kp->scheme = PKI_SCHEME_FALCON;
			     if (sec_bits <= 128) { kp->oqs.algId = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_FALCON512_NAME); kp->sec_bits = 128; }
			else if (sec_bits <= 256) { kp->oqs.algId = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_FALCON1024_NAME); kp->sec_bits = 256; }
			else { 
				PKI_DEBUG("Security Bits value not supported (%d)", sec_bits);
				return -1;
			}
			kp->pkey_type = kp->oqs.algId;
		} break;
		
		case PKI_SCHEME_DILITHIUM: {
			kp->scheme = PKI_SCHEME_DILITHIUM;
			     if (sec_bits <= 128) { kp->oqs.algId = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM2_NAME); kp->sec_bits = 128; }
			else if (sec_bits <= 192) { kp->oqs.algId = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM3_NAME); kp->sec_bits = 192; } 
			else if (sec_bits <= 256) {	kp->oqs.algId = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM5_NAME); kp->sec_bits = 256; }
			else { 
				PKI_DEBUG("Security Bits value not supported (%d)", sec_bits);
				return -1;
			}
			kp->pkey_type = kp->oqs.algId;
		} break;

		// TODO: We need to change from the robust to the
		//       fast implementations as the robust is not
		//       going to be standardized
		case PKI_SCHEME_SPHINCS: {
			kp->scheme = PKI_SCHEME_SPHINCS;
				 if (sec_bits <= 128) { kp->oqs.algId = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_SPHINCS128_F_SIMPLE_NAME); kp->sec_bits = 128; } 
			else if (sec_bits <= 192) {	kp->oqs.algId = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_SPHINCS192_F_SIMPLE_NAME); kp->sec_bits = 128; }
			else { 
				PKI_DEBUG("Security Bits value not supported (%d)", sec_bits);
				return -1;
			}
			kp->pkey_type = kp->oqs.algId;
		} break;

		case PKI_SCHEME_KYBER: {
			kp->scheme = PKI_SCHEME_KYBER;
			     if (sec_bits <= 128) { kp->oqs.algId = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_KYBER512_NAME); kp->sec_bits = 128; } 
			else if (sec_bits <= 192) {	kp->oqs.algId = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_KYBER512_NAME); kp->sec_bits = 192; }
			else if (sec_bits <= 256) {	kp->oqs.algId = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_KYBER512_NAME); kp->sec_bits = 256; }
			else { 
				PKI_DEBUG("Security Bits value not supported (%d)", sec_bits);
				return -1;
			}
			kp->pkey_type = kp->oqs.algId;
		} break;

#endif // End of ENABLE_OQS || ENABLE_OQSPROV

#ifdef ENABLE_COMBINED
		case PKI_SCHEME_COMBINED: {
			// No need to translate, output the input
			ret = sec_bits;
		} break;
#endif

#ifdef ENABLE_COMPOSITE

		// =============================
		// Native Composite Cryptography
		// =============================

		case PKI_SCHEME_COMPOSITE: {
			kp->scheme = PKI_SCHEME_COMPOSITE;
			kp->pkey_type = PKI_ID_get_by_name(OPENCA_ALG_PKEY_EXP_COMP_NAME);
			kp->sec_bits = sec_bits;
		} break;

#if defined(ENABLE_OQS) || defined (ENABLE_OQSPROV)
		// ===============================
		// Explicit Composite Combinations
		// ===============================

		// Explicit Composite Crypto Schemes
		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSA: {
			kp->scheme = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSA;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_SHA256_NAME);
			kp->pkey_type = kp->oqs.algId;
			kp->sec_bits = 192;
			kp->pq_sec_bits = 192;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSAPSS: {
			kp->scheme = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSAPSS;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSAPSS_SHA256_NAME);
			kp->pkey_type = kp->oqs.algId;
			kp->sec_bits = 192;
			kp->pq_sec_bits = 192;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_P256: {
			kp->scheme = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_P256;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_P256_SHA256_NAME);
			kp->pkey_type = kp->oqs.algId;
			kp->sec_bits = 192;
			kp->pq_sec_bits = 192;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_BRAINPOOL256: {
			kp->scheme = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_BRAINPOOL256;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_BRAINPOOL256_SHA256_NAME);
			kp->pkey_type = kp->oqs.algId;
			kp->sec_bits = 192;
			kp->pq_sec_bits = 192;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_ED25519: {
			kp->scheme = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_ED25519;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ED25519_NAME);
			kp->pkey_type = kp->oqs.algId;
			kp->sec_bits = 192;
			kp->pq_sec_bits = 192;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_P384: {
			kp->scheme = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_P384;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_P384_SHA384_NAME);
			kp->pkey_type = kp->oqs.algId;
			kp->sec_bits = 256;
			kp->pq_sec_bits = 256;
		} break;
		
		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_BRAINPOOL384: {
			kp->scheme = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_BRAINPOOL384;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_BRAINPOOL384_SHA384_NAME);
			kp->pkey_type = kp->oqs.algId;
			kp->sec_bits = 256;
			kp->pq_sec_bits = 256;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_ED448: {
			kp->scheme = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_ED448;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_ED448_NAME);
			kp->pkey_type = kp->oqs.algId;
			kp->sec_bits = 256;
			kp->pq_sec_bits = 256;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_P256: {
			kp->scheme = PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_P256;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_P256_SHA256_NAME);
			kp->pkey_type = kp->oqs.algId;
			kp->sec_bits = 128;
			kp->pq_sec_bits = 128;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_BRAINPOOL256: {
			kp->scheme = PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_BRAINPOOL256;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_BRAINPOOL256_SHA256_NAME);
			kp->pkey_type = kp->oqs.algId;
			kp->sec_bits = 128;
			kp->pq_sec_bits = 128;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_ED25519: {
			kp->scheme = PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_ED25519;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_NAME);
			kp->pkey_type = kp->oqs.algId;
			kp->sec_bits = 128;
			kp->pq_sec_bits = 128;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_RSA: {
			kp->scheme = PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_RSA;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_RSA_SHA256_NAME);
			kp->pkey_type = kp->oqs.algId;
			kp->sec_bits = 128;
			kp->pq_sec_bits = 128;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_P521: {
			kp->scheme = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_P521;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_P521_SHA512_NAME);
			kp->pkey_type = kp->oqs.algId;
			kp->sec_bits = 256;
			kp->pq_sec_bits = 256;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_RSA: {
			kp->scheme = PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_RSA;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_RSA_SHA256_NAME);
			kp->pkey_type = kp->oqs.algId;
			kp->sec_bits = 256;
			kp->pq_sec_bits = 256;
		} break;

#endif // End of ENABLE_OQS || ENABLE_OQSPROV

#endif // End of ENABLE_COMPOSITE

		default: {
			// Sets the sec_bits
			PKI_ERROR(PKI_ERR_ALGOR_UNKNOWN, "Scheme not supported (%d)", scheme_id);
			return PKI_ERR;
		}
	}

	// All Done
	return PKI_OK;
};

/* !\brief Sets the curve for key generation (and resets the scheme to EC) */
int PKI_KEYPARAMS_set_curve(PKI_KEYPARAMS   * kp, 
                            const char      * curveName, 
                            PKI_EC_KEY_FORM   curveForm,
                            PKI_EC_KEY_ASN1   asn1flags) {

#ifdef ENABLE_ECDSA

	int curveId = 0;

	// Input Checks
	if (!kp || !curveName) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// Let's get the curve Identifier
	if ((curveId = PKI_OID_get_id(PKI_OID_get(curveName))) == PKI_ID_UNKNOWN)
		return PKI_ERR;

	// Let's now set the curve name and the scheme (to be sure)
	kp->scheme = PKI_SCHEME_ECDSA;
	kp->ec.curve  = curveId;

	// Sets the Form for the curve (if specified)
	if (curveForm > 0) kp->ec.form = curveForm;

	// Sets the flags
	if (asn1flags > -1) kp->ec.asn1flags = asn1flags;

	// All Done
	return PKI_OK;

#else
	return PKI_ERR;
#endif
};


int PKI_KEYPARAMS_set_security_bits(PKI_KEYPARAMS * kp, int sec_bits) {

	// Input Checks
	if (!kp) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	if (kp->scheme == PKI_SCHEME_UNKNOWN) {
		PKI_ERROR(PKI_ERR_GENERAL, "Unknown scheme when setting the bits size");
		return PKI_ERR;
	}

	// Assigns the Bits
	// if (kp->bits <= 0 && sec_bits > 0) kp->bits = sec_bits;

	if (PKI_ERR == PKI_KEYPARAMS_set_scheme(kp, kp->scheme, sec_bits)) {
		PKI_DEBUG("Can not set the KEY_PARAMS scheme (%s at %d bits)", 
			PKI_SCHEME_ID_get_parsed(kp->scheme), sec_bits);
		return PKI_ERR;
	}

	// // Retrieves the default bits size for the scheme (sec level)
	// if (!PKI_SCHEME_ID_security_bits(kp->scheme, &sec_bits, NULL)) {
	// 	PKI_ERROR(PKI_ERR_GENERAL, "Can not retrieve the default sec bits for scheme %d", kp->scheme);
	// 	return PKI_ERR;
	// }

	// Let's update the key params, if we got good values
	// (i.e., the scheme is not just a generic one)
	if (kp->sec_bits > 0) {

		// Sets the bits size from the security bits
		kp->bits = PKI_SCHEME_ID_get_bitsize(kp->scheme, kp->sec_bits);
		
		// Returns the bits size
		return PKI_OK;
	}

	// All Done
	return PKI_OK;
};

/*! \brief Sets the bits size for key generation */
int PKI_KEYPARAMS_set_key_size(PKI_KEYPARAMS * kp, int bits) {

	int sec_bits = -1;

	// Input Checks
	if (!kp) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	switch (kp->scheme) {
		case PKI_SCHEME_RSA:
		case PKI_SCHEME_RSAPSS: {
			// Assigns the bits
			kp->rsa.bits = bits;
		} break;

		case PKI_SCHEME_DSA: {
			// Assigns the bits
			kp->dsa.bits = bits;
		} break;

		default: {
			PKI_ERROR(PKI_ERR_GENERAL, "Scheme not supported when setting the bits size (scheme id: %d)", kp->scheme);
			return PKI_ERR;
		}
	}

	// Updates the secBits
	if (bits <= 50 ) { bits = 50; sec_bits = 32; }
	else if (bits <= 512 ) { bits = 512; sec_bits = 80; }
	else if (bits <= 1024 ) { bits = 1024; sec_bits = 96; }
	else if (bits <= 1536 ) { bits = 1536; sec_bits = 110; }
	// Acceptable bit sizes
	else if (bits <= 2048 ) { bits = 2048; sec_bits = 112; }
	else if (bits <= 3072 ) { bits = 3072; sec_bits = 128; }
	else if (bits <= 4096 ) { bits = 4096; sec_bits = 192; }
	// Over the top bit sizes
	else if (bits <= 7680 ) { bits = 7680; sec_bits = 256; }
	else { 
		PKI_DEBUG("Bits value not supported (%d)", bits);
		return -1;
	}

	// Sets the security bits
	kp->sec_bits = PKI_KEYPARAMS_set_security_bits(kp, sec_bits);

	// All Done
	return PKI_OK;
};

#if defined(ENABLE_OQS) || defined (ENABLE_OQSPROV)

/*! \brief Sets the bits size for key generation */
int PKI_KEYPARAMS_set_oqs_key_params(PKI_KEYPARAMS * kp, PKI_ALGOR_OQS_PARAM algParam) {

	// Input Checks
	if (!kp || kp->bits <= 0) return
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if (kp->scheme == PKI_SCHEME_UNKNOWN)
		return PKI_ERROR(PKI_ERR_GENERAL, "Unknown scheme when setting the bits size");

	switch (kp->scheme) {

		// =============================================
		// Post Quantum Cryptography: Digital Signatures
		// =============================================


		case PKI_SCHEME_DILITHIUM: {
			if (algParam != PKI_ALGOR_OQS_PARAM_DILITHIUM_AES) {
				return PKI_ERROR(PKI_ERR_GENERAL, 
					"Dilithium only supports the AES parameter");
			};
			if (kp->bits <= 128) {
				kp->oqs.algId = PKI_ALGOR_ID_DILITHIUM2;
			} else if (kp->bits <= 192) {
				kp->oqs.algId = PKI_ALGOR_ID_DILITHIUM3;
			} else {
				kp->oqs.algId = PKI_ALGOR_ID_DILITHIUM5;
			}
		} break;

		case PKI_SCHEME_FALCON: {
			if (kp->bits <= 128) {
				kp->oqs.algId = PKI_ALGOR_ID_FALCON512;
			} else {
				kp->oqs.algId = PKI_ALGOR_ID_FALCON1024;
			}
		} break;

		case PKI_SCHEME_SPHINCS: {
			if (algParam != PKI_ALGOR_OQS_PARAM_SPHINCS_SHAKE) {
				return PKI_ERROR(PKI_ERR_GENERAL, 
					"SPHINCS+ only supports the SHAKE parameter");
			};
			if (kp->bits <= 128) {
				kp->oqs.algId = PKI_ALGOR_ID_SPHINCS_SHA2_128_F;
			} else if (kp->bits <= 192) {
				kp->oqs.algId = PKI_ALGOR_ID_SPHINCS_SHA2_192_F;
			} else {
				PKI_DEBUG("SPHINCS+ WITH SHAKE only supports 128 bits of security.");
				return PKI_ERR;
			}
		} break;

		default: {
			PKI_DEBUG("Trying to set OQS param [%d] on a non-OQS algorithm [%d]", algParam, kp->scheme);
			return PKI_ERR;
		}
	}

	// All Done
	return PKI_OK;
}

#endif

#ifdef ENABLE_COMPOSITE

/*! \brief Sets the bits size for key generation */
int PKI_KEYPARAMS_add_key(PKI_KEYPARAMS * kp, PKI_X509_KEYPAIR * key) {

#ifdef ENABLE_COMPOSITE

	int add_key_id = -1;
	int last_key_id = -1;
	int next_required_id = -1;
		// Adding, Last, and Next Key Types

	int key_sk_elements = 0;
		// Number of components for the key

	PKI_X509_KEYPAIR_STACK * key_sk = NULL;
		// Pointer to the stack of components for the key

	// Input Checks
	if (!kp || !kp->comp.k_stack) {
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
	}

	// Let's set the key stack
	key_sk = kp->comp.k_stack;

	// Let's get the ID for the that is being added
	// add_key_id = EVP_PKEY_id((EVP_PKEY *)key->value);
	add_key_id = PKI_X509_KEYPAIR_get_id(key);
	PKI_DEBUG("***** OSSL3 UPGRADE: GOT KEY ID %d vs. EVP_PKEY_id() -> %d", add_key_id, EVP_PKEY_id((EVP_PKEY *)key->value));
	if (add_key_id <= NID_undef) {
		return PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, 
			"Missing Type for the new key component");
	}
	
	// Let's check if we have any key in the stack already
	if ((key_sk_elements = PKI_STACK_X509_KEYPAIR_elements(key_sk)) > 0) {

		const PKI_X509_KEYPAIR_VALUE * evp_pkey;
			// Pointer to the OSSL key pointer
	
		// Let's get the ID from the latest key on the stack
		evp_pkey = PKI_X509_get_value(PKI_STACK_X509_KEYPAIR_get_num(key_sk, key_sk_elements - 1));
		if (!evp_pkey) {
			PKI_DEBUG("Cannot verify the type of key component #%d", key_sk_elements);
			return PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, NULL);
		}

		// Gets the Last Key's ID
		int last_key = PKI_X509_KEYPAIR_VALUE_get_id(evp_pkey);
		last_key_id = EVP_PKEY_type(last_key);
		if (last_key_id <= 0) {
#if OPENSSL_VERSION_NUMBER > 0x3000000fL
			last_key_id = last_key;
#else
			PKI_ERROR(PKI_ERR_ALGOR_UNKNOWN, NULL);
			return NULL;
#endif // End of OPENSSL_VERSION_NUMBER > 0x3000000fL
		}
		PKI_DEBUG("***** OSSL3 UPGRADE: GOT KEY ID %d vs. EVP_PKEY_id() -> %d", add_key_id, EVP_PKEY_id((EVP_PKEY *)key->value));
	}

	// Checks ID requirements (explicit composite only)	
	switch (kp->scheme) {

		case PKI_SCHEME_COMPOSITE: {
			next_required_id = 0; // No Required ID (any can work)
		} break;

#if defined(ENABLE_OQS) || defined(ENABLE_OQSPROV)

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSA: {

			// NID_dilithium3
			if (last_key_id <= 0) {
				next_required_id = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM3_NAME);
			// NID_rsaEncryption
			} else if (last_key_id == PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM3_NAME)) {
				next_required_id = NID_rsaEncryption;
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
			
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSAPSS: {

			// NID_dilithium3
			if (last_key_id <= 0) {
				next_required_id = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM3_NAME);
			// NID_rsaEncryption
			} else if (last_key_id == PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM3_NAME)) {
				next_required_id = NID_rsassaPss;
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
			
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_BRAINPOOL256: {
			// NID_dilithium3
			if (last_key_id <= 0) {
				next_required_id = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM3_NAME);
			// NID_brainpoolP256r1
			} else if (last_key_id == PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM3_NAME)) {
				// Requires an EC key
				next_required_id = NID_X9_62_id_ecPublicKey;
				// Requires the Brainpool P256 curve
				if (NID_brainpoolP256r1 != PKI_X509_KEYPAIR_get_curve(key)) {
					PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
					return PKI_ERR;
				}
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_ED25519: {
			// NID_dilithium3
			if (last_key_id <= 0) {
				next_required_id = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM3_NAME);
			// NID_secp256v1
			} else if (last_key_id == PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM3_NAME)) {
				next_required_id = NID_ED25519;
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_P384: {
			// NID_dilithium5
			if (last_key_id <= 0) {
				next_required_id = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM5_NAME);
			// NID_secp384r1
			} else if (last_key_id == PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM5_NAME)) {
				// Requires an EC key
				next_required_id = NID_X9_62_id_ecPublicKey;
				// Requires the secp384r1 curve
				if (NID_secp384r1 != PKI_X509_KEYPAIR_get_curve(key)) {
					PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
					return PKI_ERR;
				}
				// EC_KEY * ec = EVP_PKEY_get0_EC_KEY((EVP_PKEY *)key->value);
				// if (!ec) {
				// 	PKI_ERROR(PKI_ERR_POINTER_NULL, NULL);
				// 	return PKI_ERR;
				// }
				// const EC_GROUP * pkey_group = EC_KEY_get0_group(ec);
				// if (NID_secp384r1 != EC_GROUP_get_curve_name(pkey_group)) {
				// 	PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				// 	return PKI_ERR;
				// }
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_BRAINPOOL384: {
			// NID_dilithium5
			if (last_key_id <= 0) {
				next_required_id = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM5_NAME);
			// NID_brainpoolP384r1
			} else if (last_key_id == PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM5_NAME)) {
				// Requires an EC key
				next_required_id = NID_X9_62_id_ecPublicKey;
				// Requires the Brainpool P384 curve
				if (NID_brainpoolP384r1 != PKI_X509_KEYPAIR_get_curve(key)) {
					PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
					return PKI_ERR;
				}
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_ED448: {
			// NID_dilithium5
			if (last_key_id <= 0) {
				next_required_id = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM5_NAME);
			// NID_ED448
			} else if (last_key_id == PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM5_NAME)) {
				next_required_id = NID_ED448;
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_P256: {
			// NID_falcon512
			if (last_key_id <= 0) {
				next_required_id = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_FALCON512_NAME);
			// NID_X9_62_prime256v1
			} else if (last_key_id == PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_FALCON512_NAME)) {
				// Requires an EC key
				next_required_id = NID_X9_62_id_ecPublicKey;
				// Requires the prime256v1 curve
				if (NID_X9_62_prime256v1 != PKI_X509_KEYPAIR_get_curve(key)) {
					PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
					return PKI_ERR;
				}
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_BRAINPOOL256: {
			// NID_falcon512
			if (last_key_id <= 0) {
				next_required_id = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_FALCON512_NAME);
			// NID_brainpoolP256r1
			} else if (last_key_id == PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_FALCON512_NAME)) {
				// Requires an EC key
				next_required_id = NID_X9_62_id_ecPublicKey;
				// Requires the Brainpool P256 curve
				if (NID_brainpoolP256r1 != PKI_X509_KEYPAIR_get_curve(key)) {
					PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
					return PKI_ERR;
				}
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_ED25519: {
			// NID_falcon512
			if (last_key_id <= 0) {
				next_required_id = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_FALCON512_NAME);
			// NID_ED25519
			} else if (last_key_id == PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_FALCON512_NAME)) {
				next_required_id = NID_ED25519;
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_RSA: {
			// NID_falcon512
			if (last_key_id <= 0) {
				next_required_id = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_FALCON512_NAME);
			// NID_rsaEncryption
			} else if (last_key_id == PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_FALCON512_NAME)) {
				next_required_id = NID_rsaEncryption;
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_P521: {
			// NID_dilithium5
			if (last_key_id <= 0) {
				next_required_id = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM5_NAME);
			// NID_falcon1024
			} else if (last_key_id == PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM5_NAME)) {
				next_required_id = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_FALCON1024_NAME);
			// NID_secp521r1
			} else if (last_key_id == PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_FALCON1024_NAME)) {
				// Requires an EC key
				next_required_id = NID_X9_62_id_ecPublicKey;
				// Requires the Brainpool P256 curve
				if (NID_secp521r1 != PKI_X509_KEYPAIR_get_curve(key)) {
					PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
					return PKI_ERR;
				}
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_RSA: {
			// NID_dilithium5
			if (last_key_id <= 0) {
				next_required_id = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM5_NAME);
			// NID_falcon1024
			} else if (last_key_id == PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM5_NAME)) {
				next_required_id = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_FALCON1024_NAME);
			// NID_rsaEncryption
			} else if (last_key_id == PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_FALCON1024_NAME)) {
				next_required_id = NID_rsaEncryption;
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;
		
#endif // End of ENABLE_OQS || ENABLE_OQSPROV

		default: {
			// Not Handled
			next_required_id = -1;
		}

	} 

	if (next_required_id > 0 && next_required_id != add_key_id) {
		PKI_DEBUG("Key type (%d) is not the right one (expected: %d)",
				add_key_id, next_required_id);
		PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
		return PKI_ERR;
	}

	// Checks we have a good stack
	if (PKI_STACK_X509_KEYPAIR_push(kp->comp.k_stack, key) <= 0) {
		PKI_DEBUG("Cannot add a component key to the composite one");
		PKI_ERROR(PKI_ERR_ALGOR_ADD, NULL);
		return PKI_ERR;
	}

	// All Done
	return PKI_OK;

#else

	// No Composite Support
	return PKI_ERR;

#endif // End of ENABLE_COMPOSITE

}

/*! \brief Sets the k_of_n parameter for Composite keys */
int PKI_KEYPARAMS_set_kofn(PKI_KEYPARAMS * kp, int kofn) {

	if (!kp) return PKI_ERR;

	kp->comp.k_of_n = ASN1_INTEGER_new();
	if (!kp->comp.k_of_n) return PKI_ERR;

	if (kofn > 0) {
		ASN1_INTEGER_set(kp->comp.k_of_n, kofn);
	} else {
		ASN1_INTEGER_set(kp->comp.k_of_n, 1);
	}

	return PKI_OK;
}

#endif // ENABLE_COMPOSITE