/* openssl/pki_keyparams.c */

#include <libpki/pki.h>

/*!
 * \brief Allocates memory for a new PKI_KEYPARAMS (for key of type 'scheme')
 */

PKI_KEYPARAMS *PKI_KEYPARAMS_new( PKI_SCHEME_ID scheme, 
				  const PKI_X509_PROFILE *prof ) {

	PKI_KEYPARAMS *kp = NULL;

	if ((kp = (PKI_KEYPARAMS *) PKI_Malloc(sizeof(PKI_KEYPARAMS))) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

#ifdef ENABLE_COMPOSITE

	if ((kp->comp.k_stack = PKI_STACK_X509_KEYPAIR_new()) == NULL) {
		OPENSSL_free(kp);
		return NULL;
	}

#endif

	if (prof)
	{
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
						PKI_KEYPARAMS_set_oqs(kp, PKI_ALGOR_OQS_PARAM_DILITHIUM_AES);
					}

					PKI_Free (tmp_s);
				};
			} break;

#endif // ENABLE OQS

#ifdef ENABLE_COMPOSITE

			case PKI_SCHEME_COMPOSITE:
			case PKI_SCHEME_COMPOSITE_OR:
				break;

#endif // ENABLE_COMPOSITE

#ifdef ENABLE_ECDSA
			case PKI_SCHEME_ECDSA:
				if(( tmp_s = PKI_CONFIG_get_value(prof, 
							"/profile/keyParams/curveName" )) != NULL ) {
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
				} else {
						kp->ec.form = PKI_EC_KEY_FORM_UNKNOWN;
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
						PKI_log_err("ecParams (%s) not supported: use "
							"namedCurve or specifiedCurve");
					};
					PKI_Free ( tmp_s );
				} else {
					kp->ec.asn1flags = -1;
				};
				break;
#endif

				default:
					if ( kp ) PKI_KEYPARAMS_free ( kp );
					PKI_log(PKI_LOG_ERR, "Error: scheme %d is not supported!", kp->scheme);
					return NULL;
			};
	} else {
		
		if ( scheme <= 0 ) {
			kp->scheme = PKI_SCHEME_DEFAULT;
		} else {
			kp->scheme = scheme;
		};

		switch ( kp->scheme ) {

			// Classic or Modern Cryptography - Digital Signatures
			case PKI_SCHEME_RSA:
			case PKI_SCHEME_DSA:
				kp->bits = -1;
				break;

#ifdef ENABLE_OQS
			// Post Quantum Cryptography - KEMS
			case PKI_SCHEME_NTRU_PRIME:
			case PKI_SCHEME_SIKE:
			case PKI_SCHEME_BIKE:
			case PKI_SCHEME_FRODOKEM:
			// Post Quantum Cryptography - Digital Signatures
			case PKI_SCHEME_FALCON:
			case PKI_SCHEME_DILITHIUM:
			case PKI_SCHEME_SPHINCS:
			// Post Quantum Cryptography - Composite Crypto
			case PKI_SCHEME_COMPOSITE_RSA_FALCON:
			case PKI_SCHEME_COMPOSITE_ECDSA_FALCON:
			case PKI_SCHEME_COMPOSITE_RSA_DILITHIUM:
			case PKI_SCHEME_COMPOSITE_ECDSA_DILITHIUM:
				kp->bits = 128;
				break;
#endif // ENABLE_OQS

#ifdef ENABLE_COMPOSITE

			case PKI_SCHEME_COMPOSITE:
			case PKI_SCHEME_COMPOSITE_OR:
				kp->bits = 128;
				break;

#endif // ENABLE_COMPOSITE

#ifdef ENABLE_ECDSA
			case PKI_SCHEME_ECDSA:
				kp->bits 		= -1;
				kp->ec.curve 	= -1;
				kp->ec.form 	= PKI_EC_KEY_FORM_UNKNOWN;
				kp->ec.asn1flags = -1;
#endif
				break;

			default:
				if ( kp ) PKI_KEYPARAMS_free ( kp );
				PKI_log(PKI_LOG_ERR, "Error: scheme %d is not supported!", kp->scheme);
				return PKI_ERR;
		};
	};

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
			else if (bits <= 128 ) { kp->bits = 2048; }
			else if (bits <= 192 ) { kp->bits = 3072; }
			else if (bits <= 256 ) { kp->bits = 4096; }
			else if (bits <= 512 ) { kp->bits = 512;  }
			else if (bits <= 756 ) { kp->bits = 756;  }
			else if (bits <= 1024) { kp->bits = 1024; }
			else if (bits <= 2048) { kp->bits = 2048; }
		} break;

		case PKI_SCHEME_ECDSA: {
			if (bits <= 256) { kp->bits = 256; } 
			else if (bits <= 384) { kp->bits = 384; }
			else if (bits <= 521) { kp->bits = 521; }
		} break;


#ifdef ENABLE_COMPOSITE

		// =============================
		// Native Composite Cryptography
		// =============================

		case PKI_SCHEME_COMPOSITE: {
			// Unfortunately we do not have many
			// options in terms of composite, we might
			// need to enable more on libpqs
			kp->oqs.algId = PKI_ALGOR_ID_COMPOSITE;
			kp->bits = 128;
		} break;

		case PKI_SCHEME_COMPOSITE_OR: {
			// Unfortunately we do not have many
			// options in terms of composite, we might
			// need to enable more on libpqs
			kp->oqs.algId = PKI_ALGOR_ID_COMPOSITE_OR;
			kp->bits = 128;
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
			} else if(bits <= 192) {
				kp->oqs.algId = PKI_ALGOR_ID_DILITHIUM3;
				kp->bits = 192;
			} else {
				kp->oqs.algId = PKI_ALGOR_ID_DILITHIUM5;
				kp->bits = 256;
			}
		} break;

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

		// ==========================
		// OQS Composite Cryptography
		// ==========================

		case PKI_SCHEME_COMPOSITE_RSA_FALCON: {
			// Unfortunately we do not have many
			// options in terms of composite, we might
			// need to enable more on libpqs
			kp->oqs.algId = PKI_ALGOR_ID_COMPOSITE_RSA_FALCON512;
			kp->bits = 128;
		} break;

		case PKI_SCHEME_COMPOSITE_ECDSA_FALCON: {
			if (kp->bits <= 128) {
				kp->oqs.algId = PKI_ALGOR_ID_COMPOSITE_ECDSA_FALCON512;
				kp->bits = 128;
			} else {
				kp->oqs.algId = PKI_ALGOR_ID_COMPOSITE_ECDSA_FALCON1024;
				kp->bits = 256;
			}
		} break;

		case PKI_SCHEME_COMPOSITE_RSA_DILITHIUM: {
			// Unfortunately we do not have many
			// options in terms of composite, we might
			// need to enable more on LibOQS
			kp->oqs.algId = PKI_ALGOR_ID_COMPOSITE_RSA_DILITHIUM2;
			kp->bits = 128;
		} break;

		case PKI_SCHEME_COMPOSITE_ECDSA_DILITHIUM: {
			if (kp->bits <= 128) {
				kp->oqs.algId = PKI_ALGOR_ID_COMPOSITE_ECDSA_DILITHIUM2;
				kp->bits = 128;
			} else if (kp->bits <= 192) {
				kp->oqs.algId = PKI_ALGOR_ID_COMPOSITE_ECDSA_DILITHIUM3;
				kp->bits = 192;
			} else {
				kp->oqs.algId = PKI_ALGOR_ID_COMPOSITE_ECDSA_DILITHIUM5;
				kp->bits = 256;
			}
		} break;

#endif // ENABLE_OQS

		default: {
			// Sets the bits
			PKI_log_err("Scheme not supported (%d)", kp->scheme);
			return PKI_ERR;
		}
	}

	// All Done
	return PKI_OK;
};

#ifdef ENABLE_OQS

/*! \brief Sets the bits size for key generation */
int PKI_KEYPARAMS_set_oqs(PKI_KEYPARAMS * kp, PKI_ALGOR_OQS_PARAM algParam) {

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
				kp->oqs.algId = PKI_ALGOR_ID_DILITHIUM2_AES;
			} else if (kp->bits <= 192) {
				kp->oqs.algId = PKI_ALGOR_ID_DILITHIUM3_AES;
			} else {
				kp->oqs.algId = PKI_ALGOR_ID_DILITHIUM5_AES;
			}
		} break;

		default: {
			PKI_DEBUG("Trying to set OQS param [%d] on a non-OQS algorithm [%d]",
				algParam, kp->scheme);

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

	PKI_DEBUG("Adding a Key To Composite Key...");

	// Input Checks
	if (!kp) return
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if (kp->scheme != PKI_SCHEME_COMPOSITE &&
		kp->scheme != PKI_SCHEME_COMPOSITE_OR) {
		return PKI_ERROR(PKI_ERR_GENERAL, 
			"Error while adding keys to non-composite scheme");
	}

	if (0 >= PKI_STACK_X509_KEYPAIR_push(kp->comp.k_stack, key)) {
		return PKI_ERROR(PKI_ERR_GENERAL, 
			"Error while adding a component key to a composite one");
	}

	PKI_DEBUG("Key Added Successfully.");

	// All Done
	return PKI_OK;
}

#endif // ENABLE_COMPOSITE