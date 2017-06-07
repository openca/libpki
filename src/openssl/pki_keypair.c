/* openssl/pki_pkey.c */

#include <libpki/pki.h>

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

char * PKI_X509_KEYPAIR_get_parsed ( PKI_X509_KEYPAIR *pkey ) {

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

PKI_SCHEME_ID PKI_X509_KEYPAIR_get_scheme ( PKI_X509_KEYPAIR *k ) {

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

PKI_SCHEME_ID PKI_X509_KEYPAIR_VALUE_get_scheme ( PKI_X509_KEYPAIR_VALUE *pVal ) {

	PKI_SCHEME_ID ret = PKI_SCHEME_UNKNOWN;
	int p_type = 0;

	if ( !pVal ) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return ret;
	};

#if OPENSSL_VERSION_NUMBER < 0x1010000fL
	p_type = EVP_PKEY_type(pVal->type);
#else
	p_type = EVP_PKEY_type(EVP_PKEY_id(pVal));
#endif

	switch(p_type) {
		case EVP_PKEY_DSA:
			ret = PKI_SCHEME_DSA;
			break;

		case EVP_PKEY_RSA:
			ret = PKI_SCHEME_RSA;
			break;

#ifdef ENABLE_ECDSA
		case EVP_PKEY_EC:
			ret = PKI_SCHEME_ECDSA;
			break;
#endif

		default:
			return ret;
	};

	return ret;
};

/*!
 * \brief Returns the default signing algorithm from a keypair
 */

PKI_ALGOR * PKI_X509_KEYPAIR_get_algor ( PKI_X509_KEYPAIR *k ) {

	PKI_ALGOR *ret = NULL;
	PKI_X509_KEYPAIR_VALUE *pVal = NULL;

	if ( !k ) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return ret;
	};

	pVal = k->value;

	return PKI_X509_KEYPAIR_VALUE_get_algor( pVal );
}


/*!
 * \brief Returns the default signing algorithm from a keypair value
 */

PKI_ALGOR * PKI_X509_KEYPAIR_VALUE_get_algor ( PKI_X509_KEYPAIR_VALUE *pVal )
{
	PKI_ALGOR *ret = NULL;
	int p_type = 0;

	int size = -1;
	int algId = -1;

	size = PKI_X509_KEYPAIR_VALUE_get_size(pVal);
	if (size <= 0) PKI_ERROR(PKI_ERR_GENERAL, "Key size is 0!");

#if OPENSSL_VERSION_NUMBER < 0x1010000fL
	p_type = EVP_PKEY_type(pVal->type);
#else
	p_type = EVP_PKEY_type(EVP_PKEY_id(pVal));
#endif

	switch (p_type)
	{
		case EVP_PKEY_DSA:
			algId = PKI_ALGOR_DSA_SHA1;
			break;

		case EVP_PKEY_RSA:
			algId = PKI_ALGOR_RSA_SHA256;
			break;

#ifdef ENABLE_ECDSA
		case EVP_PKEY_EC:
			if ( size < 256 ) {
				algId = PKI_ALGOR_ECDSA_SHA1;
			} else if ( size < 384 ) {
				algId = PKI_ALGOR_ECDSA_SHA256;
			} else if ( size < 512 ) {
				algId = PKI_ALGOR_ECDSA_SHA384;
			} else {
				algId = PKI_ALGOR_ECDSA_SHA512;
			};
			break;
#endif

		default:
			return ret;
	};

	if( algId > 0 ) ret = PKI_ALGOR_get ( algId );

	return ret;
};

/*!
 * \brief Returns the size (in bits) of a pubkey
 */

int PKI_X509_KEYPAIR_get_size ( PKI_X509_KEYPAIR *k ) {

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

int PKI_X509_KEYPAIR_VALUE_get_size ( PKI_X509_KEYPAIR_VALUE *pKey ) {

	int ret = -1;

	if (!pKey) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return ret;
	};

	return EVP_PKEY_bits( pKey );

/*
	switch ( PKI_X509_KEYPAIR_VALUE_get_scheme( pKey ) ) {
		case PKI_SCHEME_DSA:
		case PKI_SCHEME_RSA:
			ret = EVP_PKEY_size ( pKey );
			break;

#ifdef ENABLE_ECDSA
		case PKI_SCHEME_ECDSA:
			if ((order = BN_new()) != NULL) {
				const EC_GROUP *group;

				if ((group = EC_KEY_get0_group(pKey->pkey.ec)) != NULL) {
    				if (EC_GROUP_get_order(group, order, NULL)) {
        				ret = BN_num_bits(order);
					};
				};

				if( order ) BN_free ( order );
			};
			break;
	};
#endif
*/

	return ret;
}

/*! \brief Returns the (unsigned char *) digest of a pubkey value */

PKI_DIGEST *PKI_X509_KEYPAIR_VALUE_pub_digest ( PKI_X509_KEYPAIR_VALUE *pkey,
							PKI_DIGEST_ALG *md ) {

	X509_PUBKEY *xpk = NULL;
	PKI_DIGEST * ret = NULL;
	 
	unsigned char * buf = NULL;
	int buf_size = 0;

	// Input Check
	if (!pkey) return NULL;

	// Check for MD (if not, let's use the default)
	if(!md) md = PKI_DIGEST_ALG_DEFAULT;

	// Sets the Public Key
	if(!X509_PUBKEY_set(&xpk, pkey)) {
		PKI_log_debug("PKI_X509_KEYPAIR_pub_digest()::Error building X509 "
			"PUBKEY data");
		return NULL;
	}

	// Let's allocate enough space for the DER representation
	// of the key
	buf_size = i2d_X509_PUBKEY(xpk, &buf);

	// Calculates the digest over the DER representation of the pubkey
	if (buf != NULL && buf_size > 0) {

		// Gets the Digest Value
		if ((ret = PKI_DIGEST_new(md, buf, (size_t) buf_size)) == NULL) {
			PKI_log_debug("PKI_X509_KEYPAIR_pub_digest()::%s",
				ERR_error_string( ERR_get_error(), NULL ));
			return NULL;
		}

		// Free the Buffer Memory
		PKI_Free(buf);
	}

	/*
	ASN1_BIT_STRING *key = NULL;

	if((key = xpk->public_key ) == NULL ) {
		PKI_log_debug("PKI_X509_KEYPAIR_pub_digest()::No pubkey found!");
		return ( NULL );
	}

	if( key->length < 1 ) {
		PKI_log_debug("PKI_X509_KEYPAIR_pub_digest()::Pubkey len is 0!");
		return ( NULL );
	}

	if(( ret = PKI_DIGEST_new( md, key->data, 
					(size_t) key->length )) == NULL ) {
		PKI_log_debug("PKI_X509_KEYPAIR_pub_digest()::%s",
			ERR_error_string( ERR_get_error(), NULL ));
		return ( NULL );
	}
	*/

	return ret;
}

/*! \brief Returns the (unsigned char *) digest of the pubkey */

PKI_DIGEST *PKI_X509_KEYPAIR_pub_digest ( PKI_X509_KEYPAIR *k, 
							PKI_DIGEST_ALG *md) {

	if( !k || !k->value ) return ( NULL );

	return PKI_X509_KEYPAIR_VALUE_pub_digest ( k->value, md );

}

/*! \brief Returns the passed PKI_X509_KEYPAIR in PKCS#8 format */

PKI_MEM *PKI_X509_KEYPAIR_get_p8 ( PKI_X509_KEYPAIR *k ) {

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

PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_new_p8 ( PKI_MEM *buf ) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED, NULL );

	return ( NULL );
}

/*!
 * \brief Returns a DER encoded Public Key
 */

PKI_MEM * PKI_X509_KEYPAIR_get_pubkey(PKI_X509_KEYPAIR *kp)
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

PKI_MEM *PKI_X509_KEYPAIR_get_privkey(PKI_X509_KEYPAIR *kp)
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

int PKI_X509_KEYPAIR_get_curve ( PKI_X509_KEYPAIR *kp )
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

	BIGNUM *order;

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
	};

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
};

