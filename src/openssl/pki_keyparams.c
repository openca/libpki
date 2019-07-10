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
	};

	if (prof)
	{
		PKI_X509_ALGOR_VALUE *alg = NULL;
		char *tmp_s = NULL;

		// Get the Profile value of Bits
		if ((tmp_s = PKI_CONFIG_get_value(prof, 
					"/profile/keyParams/bits" )) != NULL ) {
			kp->bits = atoi(tmp_s);
			PKI_Free ( tmp_s );
		} else {
			kp->bits = -1;
		};

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
		
		if( kp->scheme == PKI_SCHEME_UNKNOWN ) kp->scheme = PKI_SCHEME_DEFAULT;

		// Get the Profile Params
		switch (kp->scheme) {
			case PKI_SCHEME_RSA:
			case PKI_SCHEME_DSA:
				break;

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
			case PKI_SCHEME_RSA:
			case PKI_SCHEME_DSA:
				kp->bits = -1;
				break;

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
	if (!kp || bits <= 0) return
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// Sets the bits
	kp->bits = bits;

	// All Done
	return PKI_OK;
};

