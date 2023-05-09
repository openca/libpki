/* openssl/pki_keyparams.c */

#include <libpki/pki.h>

#include <libpki/datatypes.h>

/*!
 * \brief Allocates memory for a new PKI_KEYPARAMS (for key of type 'scheme')
 */

PKI_KEYPARAMS *PKI_KEYPARAMS_new( PKI_SCHEME_ID scheme, 
				  const PKI_X509_PROFILE *prof ) {

	PKI_KEYPARAMS *kp = NULL;
		// Pointer to the data structure

	// Allocates the memory
	if ((kp = (PKI_KEYPARAMS *) PKI_Malloc(sizeof(PKI_KEYPARAMS))) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	// Zeroize the Memory
	memset(kp, 0, sizeof(PKI_KEYPARAMS));

#ifdef ENABLE_COMPOSITE

	if ((kp->comp.k_stack = PKI_STACK_X509_KEYPAIR_new()) == NULL) {
		OPENSSL_free(kp);
		return NULL;
	}

	kp->comp.k_of_n = NULL;

#endif

	if (prof) {
		
		PKI_X509_ALGOR_VALUE *alg = NULL;
		char *tmp_s = NULL;

		// Scheme
		if( scheme <= 0 ) {
			if(( tmp_s = PKI_CONFIG_get_value(prof, 
						"/profile/keyParams/algorithm" )) != NULL ) {
				if((alg = PKI_X509_ALGOR_VALUE_get_by_name(tmp_s)) != NULL ) {
					// algorID = PKI_ALGOR_get_id(alg);
					kp->scheme = PKI_X509_ALGOR_VALUE_get_scheme ( alg );
				}

				// TODO: Remove this debug statement
				PKI_DEBUG("Selected ALGOR is %s\n", tmp_s );

				PKI_Free ( tmp_s );
			} else {
				kp->scheme = PKI_SCHEME_UNKNOWN;
			};
		} else {
			kp->scheme = scheme;
		};

		// Get the Profile value of Bits
		if ((tmp_s = PKI_CONFIG_get_value(prof, 
					"/profile/keyParams/bits" )) != NULL ) {
			kp->bits = atoi(tmp_s);
			PKI_Free ( tmp_s );
		} else {
			kp->bits = -1;
		};
		
		if( kp->scheme == PKI_SCHEME_UNKNOWN ) kp->scheme = PKI_SCHEME_DEFAULT;

		// Get the Profile Params
		switch (kp->scheme) {
			case PKI_SCHEME_RSA:
			case PKI_SCHEME_DSA:

#ifdef ENABLE_OQS

			case PKI_SCHEME_FALCON:
				break;

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

			case PKI_SCHEME_DILITHIUMX3: {
				kp->bits = 192;
			} break;

			case PKI_SCHEME_CLASSIC_MCELIECE:
				break;

			case PKI_SCHEME_SPHINCS:
				break;

#endif // ENABLE OQS

#ifdef ENABLE_COMPOSITE

			case PKI_SCHEME_COMPOSITE:
				break;

#ifdef ENABLE_COMBINED
			case PKI_SCHEME_COMBINED:
				break;
#endif

#endif // ENABLE_COMPOSITE

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
#endif

			default:
				if ( kp ) PKI_KEYPARAMS_free ( kp );
				PKI_log(PKI_LOG_ERR, "Error: scheme %d is not supported!", kp->scheme);
				return NULL;
		}

	} else {
		
		if ( scheme <= 0 ) {
			kp->scheme = PKI_SCHEME_DEFAULT;
		} else {
			kp->scheme = scheme;
		};

		PKI_DEBUG("Checking Bits for SCHEME %d", kp->scheme);

		switch(kp->scheme) {

			// Classic or Modern Cryptography - Digital Signatures
			case PKI_SCHEME_RSA:
			case PKI_SCHEME_DSA: {
				kp->bits = -1;
			} break;

#ifdef ENABLE_OQS
			// Post Quantum Cryptography - KEMS
			case PKI_SCHEME_NTRU_PRIME:
			case PKI_SCHEME_BIKE:
			case PKI_SCHEME_FRODOKEM: {
				kp->bits = -1;
			} break;

			// Post Quantum Cryptography - Digital Signatures
			case PKI_SCHEME_FALCON:
			case PKI_SCHEME_DILITHIUM:
			case PKI_SCHEME_SPHINCS: {
				kp->bits = 128;
			} break;

			case PKI_SCHEME_CLASSIC_MCELIECE:
			case PKI_SCHEME_KYBER: {
				kp->bits = 128;
			}

			case PKI_SCHEME_DILITHIUMX3: {
				kp->bits = 128;
			}

# ifdef ENABLE_COMPOSITE
			// Post Quantum Cryptography - Composite Crypto
			case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_P256:
			case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_BRAINPOOL256:
			case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_ED25519:
			case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSA: {
				kp->bits = 192;
			} break;

			case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_P256:
			case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_ED25519:
			case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_RSA: {
				kp->bits = 128;
			} break;

			case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_P521:
			case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_RSA: {
				kp->bits = 256;
			} break;
# endif
#endif // ENABLE_OQS

#ifdef ENABLE_COMPOSITE
			case PKI_SCHEME_COMPOSITE: {
				kp->bits = -1;
			} break;
#endif // ENABLE_COMPOSITE

#ifdef ENABLE_COMBINED
			case PKI_SCHEME_COMBINED: {
				kp->bits = 128;
			} break;
#endif // ENABLE_COMBINED

#ifdef ENABLE_ECDSA
			case PKI_SCHEME_ECDSA: {
				kp->bits 		= -1;
				kp->ec.curve 	= -1;
				kp->ec.form 	= PKI_EC_KEY_FORM_UNKNOWN;
				kp->ec.asn1flags = -1;
			} break;
#endif // ENABLE_ECDSA

			default:
				if (kp) PKI_KEYPARAMS_free(kp);
				PKI_log(PKI_LOG_ERR, "Error: scheme %d is not supported!", kp->scheme);
				return NULL;
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

int PKI_KEYPARAMS_set_scheme(PKI_KEYPARAMS * kp, PKI_SCHEME_ID schemeId) {

	// Input Checks
	if (!kp) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// Sets the Scheme
	kp->scheme = schemeId;

	// Done
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

/*! \brief Sets the bits size for key generation */
int PKI_KEYPARAMS_set_bits(PKI_KEYPARAMS * kp, int bits) {

	// Input Checks
	if (!kp) return
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if (kp->scheme == PKI_SCHEME_UNKNOWN)
		return PKI_ERROR(PKI_ERR_GENERAL, "Unknown scheme when setting the bits size");

	// Assigns the Bits
	if (kp->bits <= 0 && bits > 0) kp->bits = bits;

	// Checks for modifiers
	switch (kp->scheme) {

		case PKI_SCHEME_RSA: {
			if (bits <= 0) { kp->bits = 2048; }
			// Sec Bits Sizes
			else if (bits <= 128 ) { kp->bits = 2048; }
			else if (bits <= 192 ) { kp->bits = 3072; }
			else if (bits <= 256 ) { kp->bits = 4096; }
			else if (bits <= 384 ) { kp->bits = 4096 /* 8192 */ ; }
			else if (bits <= 521 ) { kp->bits = 4096 /* 16384 */; }
			// Classical Sizes
			else if (bits <= 512 ) { kp->bits = 512;  }
			else if (bits <= 756 ) { kp->bits = 756;  }
			else if (bits <= 1024) { kp->bits = 1024; }
			else if (bits <= 2048) { kp->bits = 2048; }
			else if (bits <= 4096) { kp->bits = 4096; }
			else if (bits <= 8192) { kp->bits = 8192; }
			else if (bits <= 16384) { kp->bits = 16384; }
			else { kp->bits = bits; }
		} break;

		case PKI_SCHEME_ECDSA: {
			if (bits <= 224) { kp->bits = 224; } 
			else if (bits <= 256) { kp->bits = 256; } 
			else if (bits <= 384) { kp->bits = 384; }
			else if (bits <= 521) { kp->bits = 521; }
			else { kp->bits = bits; }
		} break;


#ifdef ENABLE_COMPOSITE

		// =============================
		// Native Composite Cryptography
		// =============================

		case PKI_SCHEME_COMPOSITE: {
			// Unfortunately we do not have many
			// options in terms of composite, we might
			// need to enable more on LibOQS
			kp->oqs.algId = OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_OID);
			kp->bits = bits;
		} break;
#endif

#ifdef ENABLE_COMBINED
		case PKI_SCHEME_COMBINED: {
			// Unfortunately we do not have many
			// options in terms of composite, we might
			// need to enable more on LibOQS
			kp->oqs.algId = OBJ_txt2id(OPENCA_ALG_PKEY_EXP_ALT_OID);;
			kp->bits = bits;
		} break;
#endif

#ifdef ENABLE_OQS

		// =============================================
		// Post Quantum Cryptography: Digital Signatures
		// =============================================

		case PKI_SCHEME_FALCON: {

			if (bits <= 128) {
				kp->oqs.algId = PKI_ALGOR_ID_FALCON512;
				kp->bits = 128;
			} else {
				kp->oqs.algId = PKI_ALGOR_ID_FALCON1024;
				kp->bits = 256;
			}
		} break;
		
		case PKI_SCHEME_DILITHIUM: {
			if (bits <= 128) {
				kp->oqs.algId = PKI_ALGOR_ID_DILITHIUM2;
				kp->bits = 128;
			} else if (bits <= 192) {
				kp->oqs.algId = PKI_ALGOR_ID_DILITHIUM3;
				kp->bits = 192;
			} else {
				kp->oqs.algId = PKI_ALGOR_ID_DILITHIUM5;
				kp->bits = 256;
			}
		} break;

		// Experimental: We want to provide a separate
		//               implementation for PQC / Dilithium
		//               to show the use of a single OID
		//               for family of algorithms
		case PKI_SCHEME_DILITHIUMX3: {
			kp->oqs.algId = OBJ_sn2nid("DilithiumX3");
			kp->bits = 128;
		} break;

		// TODO: We need to change from the robust to the
		//       fast implementations as the robust is not
		//       going to be standardized
		case PKI_SCHEME_SPHINCS: {
			if (bits <= 128) {
				kp->oqs.algId = PKI_ALGOR_ID_SPHINCS_SHA256_128_R;
				kp->bits = 128;
			} else if (bits <= 192) {
				kp->oqs.algId = PKI_ALGOR_ID_SPHINCS_SHA256_192_R;
				kp->bits = 192;
			} else {
				kp->oqs.algId = PKI_ALGOR_ID_SPHINCS_SHA256_256_R;
				kp->bits = 256;
			}
		} break;

# ifdef ENABLE_COMPOSITE
		// ===============================
		// Explicit Composite Combinations
		// ===============================

		// Explicit Composite Crypto Schemes
		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSA: {
			PKI_DEBUG("%s - %s", OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_SHA256_NAME,
				OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_SHA256_OID);
			// Updates key parameters
			kp->bits = 128;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_SHA256_NAME);
			PKI_DEBUG("OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_SHA256_NAME) = %d",
				kp->oqs.algId);
			// Combination bits check
			if (bits > 128) return PKI_ERR;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSAPSS: {
			// Updates key parameters
			kp->bits = 128;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSAPSS_SHA256_NAME);
			// Combination bits check
			if (bits > 128) return PKI_ERR;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_P256: {
			// Updates key parameters
			kp->bits = 192;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_P256_SHA256_NAME);
			// Combination bits check
			if (bits > 192) return PKI_ERR;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_BRAINPOOL256: {
			// Updates key parameters
			kp->bits = 192;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_BRAINPOOL256_SHA256_NAME);
			// Combination bits check
			if (bits > 192) return PKI_ERR;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_ED25519: {
			kp->bits = 192;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ED25519_NAME);
			// Combination bits check
			if (bits > 192) return PKI_ERR;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_P384: {
			// Updates key parameters
			kp->bits = 256;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_P384_SHA384_NAME);
			// Combination bits check
			if (bits > 256) return PKI_ERR;
		} break;
		
		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_BRAINPOOL384: {
			// Updates key parameters
			kp->bits = 256;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_BRAINPOOL384_SHA384_NAME);
			// Combination bits check
			if (bits > 256) return PKI_ERR;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_ED448: {
			// Updates key parameters
			kp->bits = 256;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_ED448_NAME);
			// Combination bits check
			if (bits > 256) return PKI_ERR;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_P256: {
			// Updates key parameters
			kp->bits = 128;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_P256_SHA256_NAME);
			// Combination bits check
			if (bits > 128) return PKI_ERR;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_BRAINPOOL256: {
			// Updates key parameters
			kp->bits = 128;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_BRAINPOOL256_SHA256_NAME);
			// Combination bits check
			if (bits > 128) return PKI_ERR;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_ED25519: {
			// Updates key parameters
			kp->bits = 128;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_NAME);
			// Combination bits check
			if (bits > 128) return PKI_ERR;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_SPHINCS256_P256: {
			// Updates key parameters
			kp->bits = 128;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_P256_SHA256_NAME);
			// Combination bits check
			if (bits > 128) return PKI_ERR;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_SPHINCS256_BRAINPOOL256: {
			// Updates key parameters
			kp->bits = 128;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_BRAINPOOL256_SHA256_NAME);
			// Combination bits check
			if (bits > 128) return PKI_ERR;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_SPHINCS256_ED25519: {
			// Updates key parameters
			kp->bits = 128;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_ED25519_NAME);
			// Combination bits check
			if (bits > 128) return PKI_ERR;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_RSA: {
			// Updates key parameters
			kp->bits = 128;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_RSA_SHA256_NAME);
			// Combination bits check
			if (bits > 128) return PKI_ERR;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_P521: {
			// Updates key parameters
			kp->bits = 512;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_P521_SHA512_NAME);
			// Combination bits check
			if (bits > 512) return PKI_ERR;
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_RSA: {
			// Updates key parameters
			kp->bits = 512;
			kp->oqs.algId = OBJ_sn2nid(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_RSA_SHA256_NAME);
			// Combination bits check
			if (bits > 512) return PKI_ERR;
		} break;

# endif // ENABLE_COMPOSITE
#endif // ENABLE_OQS

		default: {
			// Sets the bits
			PKI_ERROR(PKI_ERR_ALGOR_UNKNOWN, "Scheme not supported (%d)", kp->scheme);
			return PKI_ERR;
		}
	}

	// All Done
	return PKI_OK;
};

#ifdef ENABLE_OQS

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
					"Sphincs only supports the SHAKE parameter");
			};
			if (kp->bits <= 128) {
				kp->oqs.algId = PKI_ALGOR_ID_SPHINCS_SHAKE256_128_R;
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
	add_key_id = EVP_PKEY_id((EVP_PKEY *)key->value);
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
		last_key_id = EVP_PKEY_id(evp_pkey);
	}

	// Checks ID requirements (explicit composite only)	
	switch (kp->scheme) {

		case PKI_SCHEME_COMPOSITE: {
			next_required_id = 0; // No Required ID (any can work)
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSA: {

			// NID_dilithium3
			if (last_key_id <= 0) {
				next_required_id = NID_dilithium3;
			// NID_rsaEncryption
			} else if (last_key_id == NID_dilithium3) {
				next_required_id = NID_rsaEncryption;
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
			
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSAPSS: {

			// NID_dilithium3
			if (last_key_id <= 0) {
				next_required_id = NID_dilithium3;
			// NID_rsaEncryption
			} else if (last_key_id == NID_dilithium3) {
				next_required_id = NID_rsassaPss;
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
			
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_BRAINPOOL256: {
			// NID_dilithium3
			if (last_key_id <= 0) {
				next_required_id = NID_dilithium3;
			// NID_brainpoolP256r1
			} else if (last_key_id == NID_dilithium3) {
				next_required_id = NID_brainpoolP256r1;
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_ED25519: {
			// NID_dilithium3
			if (last_key_id <= 0) {
				next_required_id = NID_dilithium3;
			// NID_secp256v1
			} else if (last_key_id == NID_dilithium3) {
				next_required_id = NID_ED25519;
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_P384: {
			// NID_dilithium5
			if (last_key_id <= 0) {
				next_required_id = NID_dilithium5;
			// NID_secp384r1
			} else if (last_key_id == NID_dilithium5) {
				next_required_id = NID_secp384r1;
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_BRAINPOOL384: {
			// NID_dilithium5
			if (last_key_id <= 0) {
				next_required_id = NID_dilithium5;
			// NID_brainpoolP384r1
			} else if (last_key_id == NID_dilithium5) {
				next_required_id = NID_brainpoolP384r1;
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_ED448: {
			// NID_dilithium5
			if (last_key_id <= 0) {
				next_required_id = NID_dilithium5;
			// NID_ED448
			} else if (last_key_id == NID_dilithium5) {
				next_required_id = NID_ED448;
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_P256: {
			// NID_falcon512
			if (last_key_id <= 0) {
				next_required_id = NID_falcon512;
			// NID_X9_62_prime256v1
			} else if (last_key_id == NID_falcon512) {
				next_required_id = NID_X9_62_prime256v1;
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_BRAINPOOL256: {
			// NID_falcon512
			if (last_key_id <= 0) {
				next_required_id = NID_falcon512;
			// NID_brainpoolP256r1
			} else if (last_key_id == NID_falcon512) {
				next_required_id = NID_brainpoolP256r1;
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_ED25519: {
			// NID_falcon512
			if (last_key_id <= 0) {
				next_required_id = NID_falcon512;
			// NID_ED25519
			} else if (last_key_id == NID_falcon512) {
				next_required_id = NID_ED25519;
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_SPHINCS256_P256: {
			// NID_sphincssha256128frobust
			if (last_key_id <= 0) {
				next_required_id = NID_sphincssha256128frobust;
			// NID_prime256v1
			} else if (last_key_id == NID_sphincssha256128frobust) {
				next_required_id = NID_X9_62_prime256v1;
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_SPHINCS256_BRAINPOOL256: {
			// NID_sphincssha256128frobust
			if (last_key_id <= 0) {
				next_required_id = NID_sphincssha256128frobust;
			// NID_brainpoolP256r1
			} else if (last_key_id == NID_sphincssha256128frobust) {
				next_required_id = NID_brainpoolP256r1;
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_SPHINCS256_ED25519: {
			// NID_sphincssha256128frobust
			if (last_key_id <= 0) {
				next_required_id = NID_sphincssha256128frobust;
			// NID_ED25519
			} else if (last_key_id == NID_sphincssha256128frobust) {
				next_required_id = NID_ED25519;
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_RSA: {
			// NID_falcon512
			if (last_key_id <= 0) {
				next_required_id = NID_falcon512;
			// NID_rsaEncryption
			} else if (last_key_id == NID_falcon512) {
				next_required_id = NID_rsaEncryption;
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_P521: {
			// NID_dilithium5
			if (last_key_id <= 0) {
				next_required_id = NID_dilithium5;
			// NID_falcon1024
			} else if (last_key_id == NID_dilithium5) {
				next_required_id = NID_falcon1024;
			// NID_secp521r1
			} else if (last_key_id == NID_falcon1024) {
				next_required_id = NID_secp521r1;
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;

		case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_RSA: {
			// NID_dilithium5
			if (last_key_id <= 0) {
				next_required_id = NID_dilithium5;
			// NID_falcon1024
			} else if (last_key_id == NID_dilithium5) {
				next_required_id = NID_falcon1024;
			// NID_rsaEncryption
			} else if (last_key_id == NID_falcon1024) {
				next_required_id = NID_rsaEncryption;
			} else {
				PKI_ERROR(PKI_ERR_ALGOR_COMPOSITE_EXPLICIT_WRONG_COMPONENT, NULL);
				return PKI_ERR;
			}
		} break;

		default: {
			// Not Handled
			next_required_id = -1;
		}

	} 

	if (next_required_id > 0 && next_required_id != add_key_id) {
		PKI_DEBUG("Key type (%d) is not the right one (expected: %d)",
				add_key_id, next_required_id);
		return PKI_ERR;
	}

	// Checks we have a good stack
	if (PKI_STACK_X509_KEYPAIR_push(kp->comp.k_stack, key) <= 0) {
		PKI_DEBUG("Cannot add a component key to the composite one");
		return PKI_ERR;
	}

	// All Done
	return PKI_OK;
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