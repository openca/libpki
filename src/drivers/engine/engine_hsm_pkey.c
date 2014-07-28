/* engine/engine_hsm_pkey.c */

#include <libpki/pki.h>

/* Internal usage only - we want to keep the lib abstract */
#ifndef _LIBPKI_HSM_ENGINE_PKEY_H
#define _LIBPKI_HSM_ENGINE_PKEY_H

#define PKI_RSA_KEY	RSA
#define PKI_DSA_KEY	DSA

#ifdef ENABLE_ECDSA
#define PKI_EC_KEY	EC_KEY
#endif

#define PKI_RSA_KEY_MIN_SIZE		512
#define PKI_DSA_KEY_MIN_SIZE		512
#define PKI_EC_KEY_MIN_SIZE		56
PKI_DSA_KEY * _engine_pki_dsakey_new( PKI_KEYPARAMS *kp, ENGINE *e );
#ifdef ENABLE_ECDSA
PKI_EC_KEY * _engine_pki_ecdsakey_new( PKI_KEYPARAMS *kp, ENGINE *e);
#else
void * _engine_pki_ecdsakey_new( PKI_KEYPARAMS *kp, ENGINE *e );
#endif /* ENDIF::ENABLE_ECDSA */

int _engine_pki_rand_init( void );

#endif /* ENDIF::_LIBPKI_HSM_ENGINE_PKEY */

int _engine_pki_rand_seed( void ) {
	unsigned char seed[20];

	if (!RAND_pseudo_bytes(seed, 20)) {
		return 0;
	}
	RAND_seed(seed, sizeof seed);

	return(1);
}

PKI_RSA_KEY * _engine_pki_rsakey_new( PKI_KEYPARAMS *kp, ENGINE *e ) {
	BIGNUM *bn = NULL;
	unsigned long esp = 0x10001;
	PKI_RSA_KEY *rsa = NULL;

	int bits = PKI_RSA_KEY_DEFAULT_SIZE;

	if ( kp && kp->bits > 0 ) bits = kp->bits;

	if ( bits < PKI_RSA_KEY_MIN_SIZE ) {
		PKI_ERROR(PKI_ERR_X509_KEYPAIR_SIZE_SHORT, NULL);
		return NULL;
	};

	if( (rsa = RSA_generate_key(bits, esp, NULL, NULL)) == NULL ) {
		/* Error */
		BN_free( bn );
		return NULL;
	}

	/* Let's return the RSA_KEY infrastructure */
	return (rsa);
}

PKI_DSA_KEY * _engine_pki_dsakey_new( PKI_KEYPARAMS *kp, ENGINE *e ) {
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

	// if(!DSA_generate_parameters_ex( k, bits,
	if((k = DSA_generate_parameters( bits,
				seed, 20, NULL, NULL, NULL, NULL)) == NULL ) {
		if( k ) DSA_free( k );
		PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not generated DSA params");
		return NULL;
	}

	return( k );
}

#ifdef ENABLE_ECDSA
PKI_EC_KEY * _engine_pki_ecdsakey_new( PKI_KEYPARAMS *kp, ENGINE *e ) {
	/* ECDSA is a little more complicated than the other
	   schemes as it involves a group of functions. As the
	   purpose of this library is to provide a very hi-level
	   easy to use library, we will provide some hardwired
	   parameters.
	*/

	PKI_EC_KEY *k = NULL;

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED, "Engine EC keygen");

	return ( k );
}

#else /* EVP_PKEY_EC */

void * _engine_pki_ecdsakey_new( PKI_KEYPARAMS *kp, ENGINE *e ) {
	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED, "Engine EC keygen");
	return ( NULL );
}

#endif


PKI_X509_KEYPAIR *HSM_ENGINE_X509_KEYPAIR_new( PKI_KEYPARAMS *kp, 
				URL *url, PKI_CRED *cred, HSM *driver ) {

	PKI_X509_KEYPAIR *ret = NULL;
	PKI_X509_KEYPAIR_VALUE *val = NULL;
	PKI_RSA_KEY *rsa = NULL;
	PKI_DSA_KEY *dsa = NULL;
#ifdef ENABLE_ECDSA
	PKI_EC_KEY *ec = NULL;
#endif
	ENGINE *e = NULL;

	int type = PKI_SCHEME_DEFAULT;

	if ( kp && kp->scheme > -1 ) type = kp->scheme;

	if((val = EVP_PKEY_new()) == NULL ) {
		PKI_ERROR(PKI_ERR_OBJECT_CREATE, "KeyPair value");
		return NULL;
	}

	e = (ENGINE *) driver;
	if( _engine_pki_rand_seed() == 0 ) {
		/* Probably low level of randomization available */
		PKI_log_debug("WARNING, low rand available (ENGINE HSM)");
	}

	switch (type) {

		case PKI_SCHEME_RSA:
			if((rsa = _engine_pki_rsakey_new( kp, e )) == NULL ) {
				if( val ) EVP_PKEY_free( val );
				return NULL;
			};
			if(!EVP_PKEY_assign_RSA( (EVP_PKEY *) val, rsa)) {
				PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not assign RSA key");
				if( rsa ) RSA_free( rsa );
				if( val ) EVP_PKEY_free( val );
				return NULL;
			};
			break;

		case PKI_SCHEME_DSA:
			if((dsa = _engine_pki_dsakey_new( kp, e )) == NULL ) {
				if( val ) EVP_PKEY_free( val );
				return(NULL);
			};
			if (!DSA_generate_key( dsa )) {
				PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, NULL);
				if( val ) EVP_PKEY_free( val );
				return NULL;
			}
			if (!EVP_PKEY_assign_DSA( (EVP_PKEY *) val, dsa)) {
				PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not assign DSA key");
				if( dsa ) DSA_free ( dsa );
				if( val ) EVP_PKEY_free( val );
				return NULL;
			}
                        dsa=NULL;
			break;

#ifdef ENABLE_ECDSA
		case PKI_SCHEME_ECDSA:
			if((ec = _engine_pki_ecdsakey_new( kp, e)) == NULL ) {
				if( val ) EVP_PKEY_free( val );
				return(NULL);
			};
			if (!EVP_PKEY_assign_EC_KEY( (EVP_PKEY *) val, ec)) {
				PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not assign ECDSA key");
				if( ec ) EC_KEY_free ( ec );
				if( val ) EVP_PKEY_free( val );
				return NULL;
			}
			ec=NULL;
			break;
#endif
		default:
			/* No recognized scheme */
			PKI_ERROR(PKI_ERR_HSM_SCHEME_UNSUPPORTED, "%d", type );
			if( val ) EVP_PKEY_free( val );
			return NULL;
	}

	if((ret = PKI_X509_new( PKI_DATATYPE_X509_KEYPAIR, driver)) == NULL ) {
		if( val ) EVP_PKEY_free ( val );
		return NULL;
	}

	ret->value = val;

	/* Let's return the PKEY infrastructure */
	return ( ret );
}

/* Key Free function */
void HSM_ENGINE_X509_KEYPAIR_free ( PKI_X509_KEYPAIR *pkey ) {

	if( !pkey) return;

	PKI_X509_KEYPAIR_free( pkey);

	return;

}

