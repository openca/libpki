/* openssl/pki_pkey.c */

#include <libpki/pki.h>

/* Internal usage only - we want to keep the lib abstract */
#ifndef _LIBPKI_HSM_OPENSSL_PKEY_H
#define _LIBPKI_HSM_OPENSSL_PKEY_H

/*
typedef struct __ec_key_st2 {
    int version;

    EC_GROUP *group;

    EC_POINT *pub_key;
    BIGNUM   *priv_key;

    unsigned int enc_flag;
    point_conversion_form_t conv_form;

    int     references;

    void *method_data;
};
*/

PKI_RSA_KEY * _pki_rsakey_new( PKI_KEYPARAMS *kp );
PKI_DSA_KEY * _pki_dsakey_new( PKI_KEYPARAMS *kp );
#ifdef ENABLE_ECDSA
PKI_EC_KEY * _pki_ecdsakey_new( PKI_KEYPARAMS *kp);
#else
void * _pki_ecdsakey_new( PKI_KEYPARAMS *kp );
#endif

int _pki_rand_init( void );

/* End of _LIBPKI_INTERNAL_PKEY_H */
#endif

int _pki_rand_seed( void ) {
	unsigned char seed[20];

	if (!RAND_pseudo_bytes(seed, 20)) {
		return 0;
	}
	RAND_seed(seed, sizeof seed);

	return(1);
}

PKI_RSA_KEY * _pki_rsakey_new( PKI_KEYPARAMS *kp ) {

	BIGNUM *bn = NULL;
	unsigned long esp = 0x10001;
	PKI_RSA_KEY *rsa = NULL;

	int bits = PKI_RSA_KEY_DEFAULT_SIZE;

	if ( kp && kp->bits > 0 ) {
		bits = kp->bits;
	};

	if ( bits < PKI_RSA_KEY_MIN_SIZE ) {
		PKI_ERROR(PKI_ERR_X509_KEYPAIR_SIZE_SHORT, NULL);
		return NULL;
	};

	if( (rsa = RSA_generate_key(bits, esp, NULL, NULL)) == NULL ) {
		/* Error */
		BN_free( bn );
		PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, NULL);
		return NULL;
	}

	/* Let's return the RSA_KEY infrastructure */
	return (rsa);
};

PKI_DSA_KEY * _pki_dsakey_new( PKI_KEYPARAMS *kp ) {
	PKI_DSA_KEY *k = NULL;
	unsigned char seed[20];

	int bits = PKI_DSA_KEY_DEFAULT_SIZE;

	if ( kp && kp->bits > 0 ) bits = kp->bits;

	if ( bits < PKI_DSA_KEY_MIN_SIZE ) {
		PKI_ERROR(PKI_ERR_X509_KEYPAIR_SIZE_SHORT, NULL);
		return NULL;
	};

	if (!RAND_pseudo_bytes(seed, 20)) {
		/* Not enought rand ? */
		PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Too low Entropy");
		return NULL;
	}

	if((k = DSA_generate_parameters( bits,
				seed, 20, NULL, NULL, NULL, NULL)) == NULL ) {
		if( k ) DSA_free( k );
		PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not generated DSA params");
		return NULL;
	}

	return( k );
}

#ifdef ENABLE_ECDSA
PKI_EC_KEY * _pki_ecdsakey_new( PKI_KEYPARAMS *kp ) {
	/* ECDSA is a little more complicated than the other
	   schemes as it involves a group of functions. As the
	   purpose of this library is to provide a very hi-level
	   easy to use library, we will provide some hardwired
	   parameters.
	*/
	PKI_EC_KEY *k = NULL;
	EC_builtin_curve *curves = NULL;
	EC_GROUP *group = NULL;
	int num_curves = 0;
	int degree = 0;

	int bits 	= PKI_EC_KEY_DEFAULT_SIZE;
	int curve 	= PKI_EC_KEY_CURVE_DEFAULT;
	int form 	= PKI_EC_KEY_FORM_DEFAULT;
	int flags   = PKI_EC_KEY_ASN1_DEFAULT;

	// struct __ec_key_st2 *ecKeyPnt = NULL;

	/* Get the number of availabe ECDSA curves in OpenSSL */
	if ((num_curves = (int) EC_get_builtin_curves(NULL, 0)) < 1 ) {
		/* No curves available! */
		PKI_ERROR(PKI_ERR_OBJECT_CREATE, "Builtin EC curves");
		return NULL;
	}

	/* Alloc the needed memory */
	curves = OPENSSL_malloc(sizeof(EC_builtin_curve) * num_curves);

	/* Check for memory allocation */
	if (curves == NULL) return NULL;

	/* Get the builtin curves */
	if (!EC_get_builtin_curves(curves, (size_t) num_curves))
	{
		PKI_ERROR(PKI_ERR_OBJECT_CREATE, "Can not get builtin EC curves (%d)", num_curves);
		goto err;
		return NULL;
	}

	/* We completely change behavior - we adopt one of the two
         * curves suggested by NIST. In particular:
         * - NID_secp384r1
         * - NID_secp521r1
         * For today (2008) usage, the first curve + SHA256 seems to be
         * the best approach
         */

	if( kp && kp->bits > 0 ) {
		bits = kp->bits;
	};

	if(bits < PKI_EC_KEY_MIN_SIZE ){
		PKI_ERROR(PKI_ERR_X509_KEYPAIR_SIZE_SHORT, "%d", bits);
		return NULL;
	};

	if( kp && kp->ec.curve > 0 ) {
		curve = kp->ec.curve;
	} else {
		if( bits <= 112 ) {
			bits = 112;
			curve = NID_secp112r1;
		} else if( bits <= 128 ) {
			bits = 128;
			curve = NID_secp128r1;
		} else if( bits <= 160 ) {
			bits = 160;
			curve = NID_secp160r1;
		} else if( bits <= 192 ) {
			bits = 192;
			curve = NID_X9_62_prime192v1;
		} else if( bits <= 224 ) {
			bits = 224;
			curve = NID_secp224r1;
		} else if( bits <= 256 ) {
			bits = 256;
			curve = NID_X9_62_prime256v1;
		} else if( bits <= 384 ) {
			bits = 384;
			curve = NID_secp384r1;
		} else {
			bits = 512;
			curve = NID_secp521r1;
		};
	};

	/* Initialize the key */
	if ((k = EC_KEY_new()) == NULL) {
		PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, NULL);
		goto err;
		return NULL;
	}

	if((group = EC_GROUP_new_by_curve_name(curve)) == NULL ) {
		PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Invalid Curve - %d", curve);
		goto err;
		return NULL;
	};

	/* Assign the group to the key */
	if (EC_KEY_set_group(k, group) == 0) {
		PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Invalid Group");
		goto err;
		return NULL;
	}


	/* Sets the point compression */
	if ( kp && kp->ec.form > -1 ) {
		form = kp->ec.form;
	};
	EC_KEY_set_conv_form(k, form);

	/* Sets the type of parameters, flags > 0 ==> by OID, 
 	 * flags == 0 ==> specifiedCurve
 	 */
	if ( kp->ec.asn1flags > -1 ) {
		flags = kp->ec.asn1flags;
	};
	EC_KEY_set_asn1_flag(k, flags);

	/* We do not need it now, let's free the group */
	if ( group ) EC_GROUP_free( group );
	group = NULL;

	if((group = (EC_GROUP *) EC_KEY_get0_group(k)) != NULL ) {
		EC_GROUP_set_asn1_flag( group, OPENSSL_EC_NAMED_CURVE );
	};

	degree = EC_GROUP_get_degree(EC_KEY_get0_group(k));

	if( degree < bits ) {
		/* Fix the problem, let's get the right bits */
		bits = degree;
	}

	//	// Let's cycle through all the available curves
	//	// until we find one that matches (if any)
	//	i = (i + 1 ) % num_curves;
	//
	// } while ( (degree < bits ) && (i != n_start) );

	/* Now generate the key */
	if (!EC_KEY_generate_key(k)) {
		PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, NULL );
		goto err;
		return NULL;
	}

	/* Verify the Key to be ok */
	if (!EC_KEY_check_key(k)) {
		PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Verify failed for ECDSA key" );
		goto err;
		return NULL;
	}

	// EC_KEY_set_enc_flags(k, EC_PKEY_NO_PARAMETERS);
	// ecKeyPnt = (struct __ec_key_st2 *) k;
	// ecKeyPnt->version = 1;

	goto end;

err:
	if( curves ) free ( curves );
	if ( group ) EC_GROUP_free( group );

	if( k ) {
		EC_KEY_free ( k );
		k = NULL;
	};

end:
	return ( k );
}

#else /* EVP_PKEY_EC */

void * _pki_ecdsakey_new( PKI_KEYPARAMS *kp ) {
	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED, NULL);
	return ( NULL );
}

#endif


PKI_X509_KEYPAIR *HSM_OPENSSL_X509_KEYPAIR_new( PKI_KEYPARAMS *kp, 
		URL *url, PKI_CRED *cred, HSM *hsm ) {

	PKI_X509_KEYPAIR *ret = NULL;
	PKI_RSA_KEY *rsa = NULL;
	PKI_DSA_KEY *dsa = NULL;
#ifdef ENABLE_ECDSA
	PKI_EC_KEY *ec = NULL;
#endif

	int type = PKI_SCHEME_DEFAULT;

	if ( kp && kp->scheme > -1 ) type = kp->scheme;

	if((ret = PKI_X509_new ( PKI_DATATYPE_X509_KEYPAIR, NULL )) == NULL ) {
		PKI_ERROR(PKI_ERR_OBJECT_CREATE, "KeyPair");
		return NULL;
	}

	if((ret->value = (PKI_X509_KEYPAIR_VALUE *) EVP_PKEY_new()) == NULL ) {
		PKI_ERROR(PKI_ERR_OBJECT_CREATE, "KeyPair Value");
		return NULL;
	}

	if( _pki_rand_seed() == 0 ) {
		/* Probably low level of randomization available */
		PKI_log_debug("WARNING, low rand available!");
	}

	switch (type) {
		case PKI_SCHEME_RSA:
			if((rsa = _pki_rsakey_new( kp )) == NULL ) {
				if( ret ) HSM_OPENSSL_X509_KEYPAIR_free( ret );
				return NULL;
			};
			if(!EVP_PKEY_assign_RSA((EVP_PKEY *) ret->value, rsa)) {
				PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not assign RSA key");
				if( rsa ) RSA_free( rsa );
				if( ret ) HSM_OPENSSL_X509_KEYPAIR_free( ret );
				return NULL;
			};
			break;

		case PKI_SCHEME_DSA:
			if((dsa = _pki_dsakey_new( kp )) == NULL ) {
				if( ret ) HSM_OPENSSL_X509_KEYPAIR_free( ret );
				return(NULL);
			};
			if (!DSA_generate_key( dsa )) {
				PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, NULL);
				if( ret ) HSM_OPENSSL_X509_KEYPAIR_free( ret );
				return NULL;
			}
			if (!EVP_PKEY_assign_DSA((EVP_PKEY *)ret->value, dsa)) {
				PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not assign DSA key");
				if( dsa ) DSA_free ( dsa );
				if( ret ) HSM_OPENSSL_X509_KEYPAIR_free( ret );
				return NULL;
			}
			dsa=NULL;
			break;

#ifdef ENABLE_ECDSA
		case PKI_SCHEME_ECDSA:
			if((ec = _pki_ecdsakey_new( kp )) == NULL ) {
				if( ret ) HSM_OPENSSL_X509_KEYPAIR_free( ret );
				return(NULL);
			};
			if (!EVP_PKEY_assign_EC_KEY((EVP_PKEY *)ret->value,ec)){
				PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not assign ECDSA key");
				if( ec ) EC_KEY_free ( ec );
				if( ret ) HSM_OPENSSL_X509_KEYPAIR_free( ret );
				return NULL;
			}
			ec=NULL;
			break;
#endif

		default:
			/* No recognized scheme */
			PKI_ERROR(PKI_ERR_HSM_SCHEME_UNSUPPORTED, "%d", type );
			if( ret ) HSM_OPENSSL_X509_KEYPAIR_free( ret );
			return NULL;
	}

	/* Let's return the PKEY infrastructure */
	return ( ret );
}

/* Key Free function */
void HSM_OPENSSL_X509_KEYPAIR_free ( PKI_X509_KEYPAIR *pkey ) {

	if( !pkey) return;

	PKI_X509_free ( pkey );

	return;
}

// OpenSSL Fix
// When writing PEM formatted Keys the wrong version "0" is
// used by the default EVP_PKEY_ write functions for EC keys,
// we have to provide our own function until OpenSSL solve
// this issue

int OPENSSL_HSM_write_bio_PrivateKey (BIO *bp, EVP_PKEY *x, 
		const EVP_CIPHER *enc, unsigned char *kstr, int klen, 
		pem_password_cb *cb, void *u) {

	int ret = 0;

	if(!x || !bp) return 0;

	switch( EVP_PKEY_type( x->type ))
	{
		case EVP_PKEY_DSA:
    case EVP_PKEY_RSA:
				// ret = PEM_write_bio_PrivateKey( bp, x, enc, kstr, klen, cb, u);
				ret = PEM_write_bio_PKCS8PrivateKey(bp, x, enc, (char *) kstr, klen, cb, u);
				break;
#ifdef ENABLE_ECDSA
    case EVP_PKEY_EC:
				ret = PEM_write_bio_ECPrivateKey(bp, x->pkey.ec, enc, (unsigned char *) kstr, klen, cb, u);
				break;
#endif
		default:
			ret = 0;
	};

	return ret;
}

// OpenSSL Fix
//
// Strangely enough OpenSSL does not provide an EVP_PKEY_dup()
// function, we supply it

EVP_PKEY *OPENSSL_HSM_KEYPAIR_dup(EVP_PKEY *kVal)
{
	PKI_MEM *mem = NULL;
	PKI_X509_KEYPAIR *tmp_key = NULL;
	EVP_PKEY *ret = NULL;

	if(!kVal) {
			return NULL;
	}

	if((tmp_key = PKI_X509_new_value(PKI_DATATYPE_X509_KEYPAIR,
			(void *) kVal, NULL)) == NULL) {
		return NULL;
	};

	if((mem = PKI_X509_KEYPAIR_put_mem(tmp_key, PKI_DATA_FORMAT_PEM,
				NULL, NULL, NULL )) == NULL) {
		goto err;
	};

	// Let's free the value of the key
	tmp_key->value = NULL;
	PKI_X509_KEYPAIR_free ( tmp_key );
	tmp_key = NULL; // Security

	// FILE * file = fopen("key.pem", "w+");
	// fwrite(mem->data, mem->size, 1, file);
	// fclose(file);

	// Now generate a new key based on the encoded value
	if((tmp_key = PKI_X509_KEYPAIR_get_mem(mem, NULL)) == NULL) {
		if((ret = d2i_PUBKEY(NULL, (const unsigned char **) &(mem->data), 
				(long) mem->size)) == NULL) {
			// fprintf(stderr, "[%s:%d] DEBUG\n", __FILE__, __LINE__ );
			goto err;
		};
	};

	if ( tmp_key ) {
		ret = tmp_key->value;
		tmp_key->value = NULL;
		PKI_X509_KEYPAIR_free ( tmp_key );
	};

	// Let's free the value of the PKI_MEM
	if(mem) PKI_MEM_free (mem);
	mem = NULL;

	return ret;

err:

	if(tmp_key) {
		tmp_key->value = NULL;
		PKI_X509_KEYPAIR_free(tmp_key);
	};

	if( mem ) PKI_MEM_free ( mem );

	return NULL;

};

