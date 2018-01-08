/* pkcs11/pki_pkey.c */

#include <libpki/pki.h>
#include <libpki/drivers/pkcs11/pkcs11_hsm.h>

/* Internal usage only - we want to keep the lib abstract */
#ifndef _LIBPKI_HSM_PKCS11_PKEY_H
#define _LIBPKI_HSM_PKCS11_PKEY_H

#define PKI_RSA_KEY	RSA
#define PKI_DSA_KEY	DSA

#ifdef ENABLE_ECDSA
#define PKI_EC_KEY	EC_KEY
#endif

#define PKI_RSA_KEY_MIN_SIZE		1024
#define PKI_DSA_KEY_MIN_SIZE		1024
#define PKI_EC_KEY_MIN_SIZE			128

#define RSA_SIGNATURE_MAX_SIZE		8192

PKI_RSA_KEY * _pki_pkcs11_rsakey_new( PKI_KEYPARAMS *kp, URL *url,
					PKCS11_HANDLER *lib, void *driver );

PKI_DSA_KEY * _pki_pkcs11_dsakey_new( PKI_KEYPARAMS *kp, URL *url, 
					PKCS11_HANDLER *lib, void *driver );
#ifdef ENABLE_ECDSA
PKI_EC_KEY * _pki_pkcs11_ecdsakey_new( PKI_KEYPARAMS *kp,
			URL *url, PKCS11_HANDLER *lib, void *driver );
#else
void * _pki_pkcs11_ecdsakey_new( PKI_KEYPARAMS *kp,
			URL *url, PKCS11_HANDLER *lib, void *driver );
#endif

int _pki_pkcs11_rand_init( void );

/* End of _LIBPKI_INTERNAL_PKEY_H */
#endif


// Definition for the RSA Key Generation Mechs
#define RSA_MECH_LIST_SIZE 2
static CK_MECHANISM RSA_MECH_LIST[RSA_MECH_LIST_SIZE] = {
	{CKM_RSA_X9_31_KEY_PAIR_GEN, NULL_PTR, 0 },
	{CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 }
};

// Definitions for the ECDSA Key Generation Mechs
#define EC_MECH_LIST_SIZE 1
static CK_MECHANISM EC_MECH_LIST[EC_MECH_LIST_SIZE] = {
	{CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0}
};

// Definitions for the DSA Key Generation Mechs
#define DSA_MECH_LIST_SIZE 1
static CK_MECHANISM DSA_MECH_LIST[DSA_MECH_LIST_SIZE] = {
	{CKM_DSA_KEY_PAIR_GEN, NULL_PTR, 0}
};

/* ---------------------------- Functions -------------------------------- */

int _pki_pkcs11_rand_seed( void ) {
	unsigned char seed[20];

	if (!RAND_bytes(seed, 20)) return 0;
	RAND_seed(seed, sizeof seed);

	return(1);
}

/*
size_t _get_key_id ( char *id, size_t size ) {

	unsigned char id_rand[1024];
	int rand_len = 0;
	int n = 0;

	BIGNUM *bn;

	if( BN_hex2bn(&bn, id) == 0 ) {
                return ( 0 );
        }

	if( RAND_bytes( id_rand, rand_len) == 0 ) {
		return ( 0 );
	}

	memset( id, 0x0, size );
	for( n = 0; n < rand_len; n++ ) {
		char * dest = NULL;

		dest = (char *) id + n*2 + n;
		sprintf(dest, "%2.2x", (CK_BYTE) id_rand[n] );

		if( n < sizeof(id_rand)-1 ) dest[2] = ':';
	}

	return ( strlen(id) );
}
*/

PKI_RSA_KEY * _pki_pkcs11_rsakey_new( PKI_KEYPARAMS *kp, URL *url,
					PKCS11_HANDLER *lib, void *driver) {

	PKI_RSA_KEY *ret = NULL;

	CK_OBJECT_HANDLE *handler_pubkey = NULL;
	CK_OBJECT_HANDLE *handler_privkey = NULL;

	CK_ATTRIBUTE privTemp[32];
	CK_ATTRIBUTE pubTemp[32];

	CK_RV rv;

	CK_MECHANISM * RSA_MECH_PTR = NULL;

	CK_ULONG i = 0;
	CK_ULONG n = 0;

	CK_ULONG bits = 0;

	size_t label_len = 0;

	unsigned char *data = NULL;
	CK_BYTE *esp = NULL;
	CK_ULONG size = 0;

	BIGNUM *bn = NULL;
	BIGNUM *id_num = NULL;

	char *id     = NULL;
	int   id_len = 8; 

	int idx = 0;

	if ( !url || !url->addr ) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return ( NULL );
	}

	label_len = strlen( url->addr );

	/* Check the min size for the key */
	if ( kp ) {
		if( kp->bits < PKI_RSA_KEY_MIN_SIZE ) {
			PKI_ERROR(PKI_ERR_X509_KEYPAIR_SIZE_SHORT, NULL);
		} else {
			bits = (CK_ULONG) kp->bits;
		}
	} else {
		bits = PKI_RSA_KEY_DEFAULT_SIZE;
	}

	// Look for a supported key generation mechanism
	for (idx = 0; idx < RSA_MECH_LIST_SIZE; idx++) {

		// Checks if the mechanism is supported
		if (HSM_PKCS11_check_mechanism(lib, 
				RSA_MECH_LIST[idx].mechanism) == PKI_OK) {

			// Set the pointer to the supported mechanism
			RSA_MECH_PTR = &RSA_MECH_LIST[idx];

			// Debugging Information
			PKI_DEBUG("Found RSA KEY GEN MECHANISM 0x%8.8X",
				RSA_MECH_LIST[idx].mechanism);

			// Breaks out of the loop
			break;

		} else {

			// Let's provide debug information for not-supported mechs
			PKI_DEBUG("RSA KEY GEN MECHANISM 0x%8.8X not supported",
				RSA_MECH_LIST[idx].mechanism);
		}
	}

	// If no key gen algors are supported, abort
	if (RSA_MECH_PTR == NULL) {
		PKI_ERROR(PKI_ERR_HSM_KEYPAIR_GENERATE, "No KeyGen Mechanisms supported!");
		return NULL;
	}

PKI_DEBUG("BITS FOR KEY GENERATION %lu (def: %lu)", bits, PKI_RSA_KEY_DEFAULT_SIZE);

	if (kp && kp->rsa.exponent > 3) {
		// TO be Implemented
	} else {
		if( BN_hex2bn(&bn, "10001") == 0 ) {
			PKI_log_debug("ERROR, can not convert 10001 to BIGNUM");
			return ( NULL );
		}
	}

	if( url->path != NULL ) {
		if((BN_hex2bn(&id_num, url->path )) == 0 ) {
			PKI_log_debug("ERROR, can not convert %s to BIGNUM",
						url->path );
			return ( NULL );
		}
		if((id_len = BN_num_bytes(id_num)) < 0 ) {
			if ( bn ) BN_free ( bn );
			if ( id_num ) BN_free ( id_num );
			return ( NULL );
		}
		id = PKI_Malloc ( (size_t ) id_len );
		BN_bn2bin( id_num, (unsigned char *) id );
	} else {
		id_len = 10;
		if((id = PKI_Malloc ( (size_t) id_len )) == NULL ) {
			if ( bn ) BN_free ( bn );
			return ( NULL );
		}

		if( RAND_bytes( (unsigned char *) id, id_len) == 0 ) {
			PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not generate RAND bytes");
			if( bn ) BN_free ( bn );
        	        return ( NULL );
        	}
	}

	PKI_DEBUG("Setting the Bits to %lu", bits);

	/* Setting Attributes for the public Key Template */
	n = 0;
	//HSM_PKCS11_set_attr_int( CKA_CLASS, CKO_PUBLIC_KEY, &pubTemp[n++]);
	//HSM_PKCS11_set_attr_int( CKA_KEY_TYPE, CKK_RSA, &pubTemp[n++]);
	HSM_PKCS11_set_attr_int( CKA_MODULUS_BITS, bits, &pubTemp[n++]);

	HSM_PKCS11_set_attr_bool( CKA_TOKEN, CK_TRUE, &pubTemp[n++]);
	HSM_PKCS11_set_attr_bool( CKA_ENCRYPT, CK_TRUE, &pubTemp[n++]);
	HSM_PKCS11_set_attr_bool( CKA_VERIFY, CK_TRUE, &pubTemp[n++]);
	HSM_PKCS11_set_attr_bool( CKA_WRAP, CK_TRUE, &pubTemp[n++]);

	HSM_PKCS11_set_attr_bn(CKA_PUBLIC_EXPONENT, bn, &pubTemp[n++]);
	HSM_PKCS11_set_attr_sn(CKA_LABEL, url->addr, label_len, &pubTemp[n++]);
	HSM_PKCS11_set_attr_sn(CKA_ID, id, (size_t) id_len, &pubTemp[n++]);

	/* Setting Attributes for the private Key Template */
	i = 0;
	//HSM_PKCS11_set_attr_int( CKA_CLASS, CKO_PRIVATE_KEY, &privTemp[i++]);
	//HSM_PKCS11_set_attr_int( CKA_KEY_TYPE, CKK_RSA, &privTemp[i++]);
	//HSM_PKCS11_set_attr_int( CKA_MODULUS_BITS, bits, &privTemp[i++]);

	HSM_PKCS11_set_attr_bool( CKA_TOKEN, CK_TRUE, &privTemp[i++]);
	HSM_PKCS11_set_attr_bool( CKA_PRIVATE, CK_TRUE, &privTemp[i++]);
	HSM_PKCS11_set_attr_bool( CKA_SENSITIVE, CK_TRUE, &privTemp[i++]);
	HSM_PKCS11_set_attr_bool( CKA_DECRYPT, CK_TRUE, &privTemp[i++]);
	HSM_PKCS11_set_attr_bool( CKA_SIGN, CK_TRUE, &privTemp[i++]);
	// HSM_PKCS11_set_attr_bool( CKA_NEVER_EXTRACTABLE, CK_TRUE, 
	// 						&privTemp[i++]);
	// HSM_PKCS11_set_attr_bool( CKA_EXTRACTABLE, CK_FALSE, &privTemp[i++]);
	HSM_PKCS11_set_attr_bool( CKA_UNWRAP, CK_TRUE, &privTemp[i++]);

	// HSM_PKCS11_set_attr_bn(CKA_PUBLIC_EXPONENT, bn, &privTemp[i++]);
	HSM_PKCS11_set_attr_sn(CKA_LABEL, url->addr, label_len, &privTemp[i++]);
	HSM_PKCS11_set_attr_sn(CKA_ID, id, (size_t) id_len, &privTemp[i++]);

	/* Allocate the handlers for pub and priv keys */
	handler_pubkey = (CK_OBJECT_HANDLE *) PKI_Malloc ( 
						sizeof( CK_OBJECT_HANDLE ));
	handler_privkey = (CK_OBJECT_HANDLE *) PKI_Malloc ( 
						sizeof( CK_OBJECT_HANDLE ));

	if( !handler_pubkey || !handler_privkey ) {
		if ( bn ) BN_free ( bn );
		if ( esp ) PKI_Free ( esp );
		return ( NULL );
	}

	PKI_log_debug("HSM_PKCS11_KEYPAIR_new()::Generating a new Key ... ");
	rv = lib->callbacks->C_GenerateKeyPair (
			lib->session, RSA_MECH_PTR, 
			pubTemp, n,
			privTemp, i,
			handler_pubkey, 
			handler_privkey);

	if( rv != CKR_OK ) {
		if ( rv == CKR_MECHANISM_INVALID ) {
			PKI_log_err("HSM_PKCS11_KEYPAIR_new()::RSA Algorithm "
				"is not supported by the Token" );
		} else {
			PKI_log_debug ("HSM_PKCS11_KEYPAIR_new()::Failed with "
					"code 0x%8.8X", rv );
		};
		if ( bn ) BN_free ( bn );
		if ( esp ) PKI_Free ( esp );
		return ( NULL );
	}

	/* Clean up the Memory we are not using anymore */
	if ( bn ) BN_free ( bn );
	if ( esp ) PKI_Free ( esp );

	/* Generate a new RSA container */
	if((ret = RSA_new()) == NULL ) {
		goto err;
	};
	
	if( HSM_PKCS11_get_attribute ( handler_pubkey, &lib->session,
			CKA_PUBLIC_EXPONENT, (void **) &data, 
						&size, lib ) != PKI_OK ) {
		goto err;
	};

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
	RSA_set0_key(ret, NULL, BN_bin2bn( data, (int) size, NULL), NULL);
#else
	ret->e = BN_bin2bn( data, (int) size, NULL );
#endif
	PKI_Free ( data );
	data = NULL;

	if( HSM_PKCS11_get_attribute ( handler_pubkey, &lib->session,
			CKA_MODULUS, (void **) &data, &size, lib ) != PKI_OK ) {
		goto err;
	};

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
	RSA_set0_key(ret, BN_bin2bn(data, (int) size, NULL), NULL, NULL);
#else
	ret->n = BN_bin2bn( data, (int) size, NULL );
#endif
	PKI_Free ( data );
	data = NULL;

	/* Let's get the Attributes from the Keypair and store into the
	   key's pointer */
	RSA_set_method( ret, HSM_PKCS11_get_rsa_method());

#ifdef RSA_FLAG_SIGN_VER
# if OPENSSL_VERSION_NUMBER >= 0x1010000fL 
	RSA_set_flags( ret, RSA_FLAG_SIGN_VER);
# else
	ret->flags |= RSA_FLAG_SIGN_VER;
# endif
#endif

	/* Push the priv and pub key handlers to the rsa->ex_data */
	RSA_set_ex_data( ret, KEYPAIR_DRIVER_HANDLER_IDX, driver );
	RSA_set_ex_data( ret, KEYPAIR_PRIVKEY_HANDLER_IDX, handler_privkey );
	RSA_set_ex_data( ret, KEYPAIR_PUBKEY_HANDLER_IDX, handler_pubkey );

	/* Cleanup the memory for Templates */
	HSM_PKCS11_clean_template ( pubTemp, (int) n );
	HSM_PKCS11_clean_template ( privTemp, (int) i );

	/* Let's return the RSA_KEY infrastructure */
	return (ret);

err:
	if( ret ) RSA_free ((RSA *) ret );

	if ( handler_pubkey ) {
		if((rv = lib->callbacks->C_DestroyObject( lib->session, 
					*handler_pubkey )) != CKR_OK ) {
		PKI_log_debug ("HSM_PKCS11_KEYPAIR_new()::Failed to delete "
			"pubkey object");
		};
		PKI_Free ( handler_pubkey );
	}

	if( handler_privkey ) {
		if((rv = lib->callbacks->C_DestroyObject( lib->session, 
					*handler_privkey)) != CKR_OK ) {
		PKI_log_debug ("HSM_PKCS11_KEYPAIR_new()::Failed to delete "
			"privkey object");
		};
		PKI_Free ( handler_privkey );
	}

	PKI_log_debug("HSM_PKCS11_KEYPAIR_new()::Key material DELETED!");

	return ( NULL );

}

PKI_DSA_KEY * _pki_pkcs11_dsakey_new( PKI_KEYPARAMS *kp, URL *url,
					PKCS11_HANDLER *lib, void *driver ) {
	PKI_DSA_KEY *k = NULL;
	// unsigned char seed[20];

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED, NULL);


	return( k );
}

#ifdef ENABLE_ECDSA
PKI_EC_KEY * _pki_pkcs11_ecdsakey_new(PKI_KEYPARAMS  * kp,
                                      URL            * url,
                                      PKCS11_HANDLER * lib,
                                      void           * driver) {

	PKI_EC_KEY * ret = NULL;

	CK_OBJECT_HANDLE *handler_pubkey = NULL;
	CK_OBJECT_HANDLE *handler_privkey = NULL;

	CK_ATTRIBUTE privTemp[32];
	CK_ATTRIBUTE pubTemp[32];

	CK_RV rv;

	CK_MECHANISM EC_MECH = {
		CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };

	CK_ULONG i = 0;
	CK_ULONG n = 0;

	CK_ULONG bits = 0;

	size_t label_len = 0;

	unsigned char *data = NULL;
	CK_BYTE *esp = NULL;
	CK_ULONG size = 0;

	BIGNUM *bn = NULL;
	BIGNUM *id_num = NULL;

	char *id     = NULL;
	int   id_len = 8; 

	if ( !url || !url->addr ) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return ( NULL );
	}

	label_len = strlen( url->addr );

	/* Check the min size for the key */
	if ( kp ) {
		if( kp->bits < PKI_EC_KEY_MIN_SIZE ) {
			PKI_ERROR(PKI_ERR_X509_KEYPAIR_SIZE_SHORT, NULL);
		};
	} else {
		bits = PKI_EC_KEY_DEFAULT_SIZE;
	}

PKI_DEBUG("BITS FOR KEY GENERATION %lu (def: %lu)", bits, PKI_EC_KEY_DEFAULT_SIZE);

	if ( kp && kp->rsa.exponent > 3) {
		// TO be Implemented
	} else {
		if( BN_hex2bn(&bn, "10001") == 0 ) {
			PKI_log_debug("ERROR, can not convert 10001 to BIGNUM");
			return ( NULL );
		}
	}

	if( url->path != NULL ) {
		if((BN_hex2bn(&id_num, url->path )) == 0 ) {
			PKI_log_debug("ERROR, can not convert %s to BIGNUM",
						url->path );
			return ( NULL );
		}
		if((id_len = BN_num_bytes(id_num)) < 0 ) {
			if ( bn ) BN_free ( bn );
			if ( id_num ) BN_free ( id_num );
			return ( NULL );
		}
		id = PKI_Malloc ( (size_t ) id_len );
		BN_bn2bin( id_num, (unsigned char *) id );
	} else {
		id_len = 10;
		if((id = PKI_Malloc ( (size_t) id_len )) == NULL ) {
			if ( bn ) BN_free ( bn );
			return ( NULL );
		}

		if( RAND_bytes( (unsigned char *) id, id_len) == 0 ) {
			PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not generate RAND bytes");
			if( bn ) BN_free ( bn );
        	        return ( NULL );
        	}
	}

	PKI_DEBUG("Setting the Bits to %lu", bits);

	/* Setting Attributes for the public Key Template */
	n = 0;
	//HSM_PKCS11_set_attr_int( CKA_CLASS, CKO_PUBLIC_KEY, &pubTemp[n++]);
	//HSM_PKCS11_set_attr_int( CKA_KEY_TYPE, CKK_RSA, &pubTemp[n++]);
	HSM_PKCS11_set_attr_int( CKA_MODULUS_BITS, bits, &pubTemp[n++]);

	HSM_PKCS11_set_attr_bool( CKA_TOKEN, CK_TRUE, &pubTemp[n++]);
	HSM_PKCS11_set_attr_bool( CKA_ENCRYPT, CK_TRUE, &pubTemp[n++]);
	HSM_PKCS11_set_attr_bool( CKA_VERIFY, CK_TRUE, &pubTemp[n++]);
	HSM_PKCS11_set_attr_bool( CKA_WRAP, CK_TRUE, &pubTemp[n++]);

	HSM_PKCS11_set_attr_bn(CKA_PUBLIC_EXPONENT, bn, &pubTemp[n++]);
	HSM_PKCS11_set_attr_sn(CKA_LABEL, url->addr, label_len, &pubTemp[n++]);
	HSM_PKCS11_set_attr_sn(CKA_ID, id, (size_t) id_len, &pubTemp[n++]);

	/* Setting Attributes for the private Key Template */
	i = 0;
	//HSM_PKCS11_set_attr_int( CKA_CLASS, CKO_PRIVATE_KEY, &privTemp[i++]);
	//HSM_PKCS11_set_attr_int( CKA_KEY_TYPE, CKK_RSA, &privTemp[i++]);
	//HSM_PKCS11_set_attr_int( CKA_MODULUS_BITS, bits, &privTemp[i++]);

	HSM_PKCS11_set_attr_bool( CKA_TOKEN, CK_TRUE, &privTemp[i++]);
	HSM_PKCS11_set_attr_bool( CKA_PRIVATE, CK_TRUE, &privTemp[i++]);
	HSM_PKCS11_set_attr_bool( CKA_SENSITIVE, CK_TRUE, &privTemp[i++]);
	HSM_PKCS11_set_attr_bool( CKA_DECRYPT, CK_TRUE, &privTemp[i++]);
	HSM_PKCS11_set_attr_bool( CKA_SIGN, CK_TRUE, &privTemp[i++]);
	// HSM_PKCS11_set_attr_bool( CKA_NEVER_EXTRACTABLE, CK_TRUE, 
	// 						&privTemp[i++]);
	// HSM_PKCS11_set_attr_bool( CKA_EXTRACTABLE, CK_FALSE, &privTemp[i++]);
	HSM_PKCS11_set_attr_bool( CKA_UNWRAP, CK_TRUE, &privTemp[i++]);

	// HSM_PKCS11_set_attr_bn(CKA_PUBLIC_EXPONENT, bn, &privTemp[i++]);
	HSM_PKCS11_set_attr_sn(CKA_LABEL, url->addr, label_len, &privTemp[i++]);
	HSM_PKCS11_set_attr_sn(CKA_ID, id, (size_t) id_len, &privTemp[i++]);

	/* Allocate the handlers for pub and priv keys */
	handler_pubkey = (CK_OBJECT_HANDLE *) PKI_Malloc ( 
						sizeof( CK_OBJECT_HANDLE ));
	handler_privkey = (CK_OBJECT_HANDLE *) PKI_Malloc ( 
						sizeof( CK_OBJECT_HANDLE ));

	if( !handler_pubkey || !handler_privkey ) {
		if ( bn ) BN_free ( bn );
		if ( esp ) PKI_Free ( esp );
		return ( NULL );
	}

	PKI_log_debug("Generating a new Key ... ");
	rv = lib->callbacks->C_GenerateKeyPair (
			lib->session, &EC_MECH, 
			pubTemp, n,
			privTemp, i,
			handler_pubkey, 
			handler_privkey);

	if( rv != CKR_OK ) {

		if ( rv == CKR_MECHANISM_INVALID ) {
			PKI_ERROR(PKI_ERR_HSM_SET_ALGOR, 
				"EC Algorithm is not supported by the Token");
		} else {
			PKI_log_debug ("Failed with code 0x%8.8X", rv );
		}

		if ( bn ) BN_free ( bn );
		if ( esp ) PKI_Free ( esp );

		return ( NULL );
	}

	/* Clean up the Memory we are not using anymore */
	if ( bn ) BN_free ( bn );
	if ( esp ) PKI_Free ( esp );

	/* Generate a new RSA container */
	if((ret = EC_KEY_new()) == NULL ) goto err;
	
	if( HSM_PKCS11_get_attribute(handler_pubkey,
                                 &lib->session,
                                 CKA_PUBLIC_EXPONENT,
                                 (void **) &data, 
						         &size,
						         lib) != PKI_OK ) {
		goto err;
	}

	EC_KEY_set_private_key(ret, BN_bin2bn( data, (int) size, NULL));
	PKI_Free(data);
	data = NULL;

	if( HSM_PKCS11_get_attribute(handler_pubkey,
                                 &lib->session,
                                 CKA_MODULUS,
                                 (void **) &data,
                                 &size,
                                 lib) != PKI_OK ) {
		goto err;
	}

	EC_KEY_set_public_key(ret, (const EC_POINT *) NULL);
	PKI_Free ( data );
	data = NULL;

/*
	ECDSA_set_method(ret, HSM_PKCS11_get_ecdsa_method());

#ifdef RSA_FLAG_SIGN_VER
# if OPENSSL_VERSION_NUMBER >= 0x1010000fL 
	RSA_set_flags( ret, RSA_FLAG_SIGN_VER);
# else
	ret->flags |= RSA_FLAG_SIGN_VER;
# endif
#endif

	// Push the priv and pub key handlers to the rsa->ex_data
	EC_KEY_set_ex_data( ret, KEYPAIR_DRIVER_HANDLER_IDX, driver );
	EC_KEY_set_ex_data( ret, KEYPAIR_PRIVKEY_HANDLER_IDX, handler_privkey );
	EC_KEY_set_ex_data( ret, KEYPAIR_PUBKEY_HANDLER_IDX, handler_pubkey );

	// Cleanup the memory for Templates
	HSM_PKCS11_clean_template ( pubTemp, (int) n );
	HSM_PKCS11_clean_template ( privTemp, (int) i );
*/

	// Let's return the RSA_KEY infrastructure
	return (ret);

err:
	if (ret) EC_KEY_free(ret);

	if ( handler_pubkey ) {
		if((rv = lib->callbacks->C_DestroyObject( lib->session, 
					*handler_pubkey )) != CKR_OK ) {
			PKI_log_debug ("Failed to delete pubkey object");
		}
		PKI_Free(handler_pubkey);
	}

	if( handler_privkey ) {
		if((rv = lib->callbacks->C_DestroyObject(lib->session, 
					                             *handler_privkey)) != CKR_OK) {
			PKI_log_debug ("Failed to delete privkey object");
		}
		PKI_Free(handler_privkey);
	}

	return NULL;
}

#else /* EVP_PKEY_EC */

void * _pki_pkcs11_ecdsakey_new( PKI_KEYPARAMS *kp,
			URL *url, PKCS11_HANDLER *lib, void *driver ) {
	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED, NULL);
	return ( NULL );
}

#endif


PKI_X509_KEYPAIR *HSM_PKCS11_KEYPAIR_new( PKI_KEYPARAMS *kp,
			URL *url, PKI_CRED *cred, HSM *driver ) {

	PKCS11_HANDLER *lib = NULL;
	int type = PKI_SCHEME_DEFAULT;

	/*
	CK_MECHANISM DSA_MECH = {
		CKM_DSA_KEY_PAIR_GEN, NULL_PTR, 0 };

	CK_MECHANISM ECDSA_MECH = {
		CKM_ECDSA_KEY_PAIR_GEN, NULL_PTR, 0 };
	*/

	/* Return EVP Key */
	PKI_X509_KEYPAIR *ret = NULL;
	PKI_X509_KEYPAIR_VALUE *val = NULL;

	/* If a RSA Key is generated we use the RSA pointer*/
	PKI_RSA_KEY *rsa = NULL;

	/* If a DSA Key is generated we use the DSA pointer*/
	PKI_DSA_KEY *dsa = NULL;

#ifdef ENABLE_ECDSA
	/* If an ECDSA Key is generated we use the DSA pointer*/
	PKI_EC_KEY *ecdsa = NULL;
#endif

	PKI_log_debug("HSM_PKCS11_KEYPAIR_new()::Start!");

	if ((lib = _hsm_get_pkcs11_handler ( driver )) == NULL ) {
		PKI_log_debug("HSM_PKCS11_KEYPAIR_new()::Can not get handler");
		return NULL;
	}
	/*
	if((val = (PKI_X509_KEYPAIR *) EVP_PKEY_new()) == NULL ) {
		return NULL;
	}
	*/

	/*
	if( _pki_pkcs11_rand_seed() == 0 ) {
		PKI_log_debug("WARNING, low rand available!");
	}
	*/

	if ( kp && kp->scheme != PKI_SCHEME_UNKNOWN ) type = kp->scheme;

	switch (type) {
		case PKI_SCHEME_RSA:
			break;
		case PKI_SCHEME_DSA:
		case PKI_SCHEME_ECDSA:
		default:
			PKI_ERROR(PKI_ERR_HSM_SCHEME_UNSUPPORTED, "Scheme %d", type );
			return ( NULL );
	}

	/*
	PKI_log_debug("HSM_PKCS11_KEYPAIR_new()::Closing existing key session");
	rv = lib->callbacks->C_CloseSession( lib->session );
	*/

	if(( HSM_PKCS11_session_new( lib->slot_id, &lib->session,
		CKF_SERIAL_SESSION | CKF_RW_SESSION, lib )) == PKI_ERR ) {

		PKI_log_debug("HSM_PKCS11_KEYPAIR_new()::Failed in opening a "
				"new session (R/W) with the token" );
		return ( NULL );
	};

	/*
	PKI_log_debug("HSM_PKCS11_KEYPAIR_new()::Opening new R/W key session");
	if((rv = lib->callbacks->C_OpenSession (lib->slot_id, 
			CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, 
						&(lib->session))) != CKR_OK ) {
		PKI_log_debug("HSM_PKCS11_KEYPAIR_new()::Failed in opening a "
				"new session (R/W) with the token" );
		return ( NULL );
	}
	*/

	if( HSM_PKCS11_login ( driver, cred ) == PKI_ERR ) {
		HSM_PKCS11_session_close ( &lib->session, lib );
		return ( PKI_ERR );
	}

	/*
	PKI_log_debug("HSM_PKCS11_KEYPAIR_new()::Logging in" );
	rv = lib->callbacks->C_Login(lib->session, CKU_USER, 
		(CK_UTF8CHAR *) cred->password, 
			cred->password ? strlen(cred->password) : 0);
	*/

	/*
	if ( rv == CKR_USER_ALREADY_LOGGED_IN ) {
		PKI_log_debug( "HSM_PKCS11_SLOT_select()::User Already logged "
								"in!");
	} else if( rv == CKR_PIN_INCORRECT ) {
		PKI_log_err ( "HSM_PKCS11_SLOT_select()::Can not login "
			"- Pin Incorrect (0X%8.8X) [%s]", rv, cred->password);
		return ( PKI_ERR );
	} else if ( rv != CKR_OK ) {
		PKI_log_err ( "HSM_PKCS11_SLOT_select()::Can not login "
			"- General Error (0X%8.8X)", rv);
		return ( PKI_ERR );
	}
	*/

	/* Generate the EVP_PKEY that will allow it to make use of it */
	if((val = (PKI_X509_KEYPAIR_VALUE *) EVP_PKEY_new()) == NULL ) {
		HSM_PKCS11_session_close ( &lib->session, lib );
		PKI_ERROR(PKI_ERR_OBJECT_CREATE, "KeyPair value");
		return NULL;
	}

	switch( type ) {

		case PKI_SCHEME_RSA:
			if ((rsa = _pki_pkcs11_rsakey_new ( kp, url, 
					lib, driver)) == NULL ) {
				HSM_PKCS11_session_close ( &lib->session, lib );
				return ( NULL );
			};
			if(!EVP_PKEY_assign_RSA( (EVP_PKEY *) val, rsa)) {	
				PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not assign RSA key");
				if( rsa ) RSA_free ( rsa );
				if( val ) EVP_PKEY_free( (EVP_PKEY *) val );
				HSM_PKCS11_session_close ( &lib->session, lib );
				return ( NULL );
			}
			break;

		case PKI_SCHEME_DSA:
			if ((dsa = _pki_pkcs11_dsakey_new ( kp, url, 
					lib, driver)) == NULL ) {
				HSM_PKCS11_session_close ( &lib->session, lib );
				return ( NULL );
			};
			if(!EVP_PKEY_assign_DSA( (EVP_PKEY *) val, dsa)) {	
				PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not assign DSA key");
				if( dsa ) DSA_free ( dsa );
				if( val ) EVP_PKEY_free( (EVP_PKEY *) val );
				HSM_PKCS11_session_close ( &lib->session, lib );
				return ( NULL );
			}
			break;

#ifdef ENABLE_ECDSA
		case PKI_SCHEME_ECDSA:
			if ((ecdsa = _pki_pkcs11_ecdsakey_new ( kp, url, 
					lib, driver)) == NULL ) {
				HSM_PKCS11_session_close ( &lib->session, lib );
				return ( NULL );
			};
			if(!EVP_PKEY_assign_EC_KEY( (EVP_PKEY *) val, ecdsa)) {	
				PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not assign ECDSA key");
				if( ecdsa ) EC_KEY_free ( ecdsa );
				if( val ) EVP_PKEY_free( (EVP_PKEY *) val );
				HSM_PKCS11_session_close ( &lib->session, lib );
				return ( NULL );
			}
			break;
#endif
		default:
			PKI_ERROR(PKI_ERR_HSM_SCHEME_UNSUPPORTED, "%d", type);
			if ( val ) EVP_PKEY_free ( (EVP_PKEY *) val );
			HSM_PKCS11_session_close ( &lib->session, lib );
			return ( NULL );
	}

	HSM_PKCS11_session_close ( &lib->session, lib );

	if (( ret = PKI_X509_new ( PKI_DATATYPE_X509_KEYPAIR, driver)) == NULL){
			PKI_ERROR(PKI_ERR_OBJECT_CREATE, NULL );
			if ( val ) EVP_PKEY_free ( (EVP_PKEY *) val );
		if ( val ) EVP_PKEY_free ( val );
		return NULL;
	}

	ret->value = val;

	/* Let's return the PKI_X509_KEYPAIR infrastructure */
	return ( ret );

}

/* Key Free function */
void HSM_PKCS11_KEYPAIR_free ( PKI_X509_KEYPAIR *pkey ) {

	if( !pkey ) return;

	PKI_X509_free (pkey);

	return;
}

/* ----------------------------- RSA Callback Methods ----------------- */

const RSA_METHOD * HSM_PKCS11_get_rsa_method ( void ) {

#if OPENSSL_VERSION_NUMBER < 0x1010000fL

	static RSA_METHOD ret;

	ret = *RSA_get_default_method();

	// Sets the name
	ret.name = "LibPKI PKCS#11 RSA";

	// Implemented Methods
	ret.rsa_sign = HSM_PKCS11_rsa_sign;

	// Not Implemented Methods
	ret.rsa_priv_enc = NULL;
	ret.rsa_priv_dec = NULL;

	return &ret;

#else

	static RSA_METHOD * r_pnt = NULL;
		// Static Pointer to the new PKCS11 RSA Method

	// If the pointer is empty, let's get a new method
	if (!r_pnt) {

		// Duplicate the default method
		if ((r_pnt = RSA_meth_dup(RSA_get_default_method())) != NULL) {

			// Sets the name
			RSA_meth_set1_name(r_pnt, "LibPKI PKCS#11 RSA");

			// Sets the sign to use the PKCS#11 version
			RSA_meth_set_sign(r_pnt, HSM_PKCS11_rsa_sign);

			// Sets not implemented calls
			RSA_meth_set_priv_enc(r_pnt, NULL);
			RSA_meth_set_priv_dec(r_pnt, NULL);
		}
	}

	// All Done
	return r_pnt;

#endif

}

const EC_KEY_METHOD * HSM_PKCS11_get_ecdsa_method ( void ) {

#if OPENSSL_VERSION_NUMBER < 0x1010000fL

	static EC_KEY_METHOD ret;

	/*
	// ECDSA METHOD - it is required since OpenSSL is
	// actually missing the duplication of the METHOD
	static ECDSA_METHOD ret = {
	    "PKCS#11 ECDSA method",      // const char *name;
	    HSM_PKCS11_ecdsa_sign,       // ECDSA_SIG *(*ecdsa_do_sign)(const unsigned char *dgst, int dgst_len, const BIGNUM *inv,
	                                 //             const BIGNUM *rp, EC_KEY *eckey);
	    HSM_PKCS11_ecdsa_sign_setup, // int (*ecdsa_sign_setup)(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv, BIGNUM **r);
	    NULL,                        // int (*ecdsa_do_verify)(const unsigned char *dgst, int dgst_len, const ECDSA_SIG *sig,
	                                 //      EC_KEY *eckey);
	    0,                           // int flags;
	    NULL                         // char *app_data;
	};
	*/

	ret = * ECDSA_get_default_method();

	ECDSA_METHOD_set_name(&ret, "LibPKI PKCS#11 ECDSA");

	ECDSA_METHOD_set_sign(&ret, HSM_PKCS11_ecdsa_sign);
	ECDSA_METHOD_set_sign_setup(&ret, HSM_PKCS11_ecdsa_sign_setup);

	// ECDSA_METHOD_set_verify(&ret, NULL);

#else

	static EC_KEY_METHOD * r_pnt = NULL;

	if (!r_pnt) {

		if ((r_pnt = EC_KEY_METHOD_new(EC_KEY_get_default_method())) == NULL)
			return NULL;

		// Sets the sign method
		EC_KEY_METHOD_set_sign(r_pnt, 
			                   HSM_PKCS11_ecdsa_sign, //int (*sign)(int type, const unsigned char *dgst,
                                                      //            int dlen, unsigned char *sig,
                                                      //            unsigned int *siglen,
                                                      //            const BIGNUM *kinv, const BIGNUM *r,
                                                      //            EC_KEY *eckey)
			                   NULL,                  //int (*sign_setup)(EC_KEY *eckey, BN_CTX *ctx_in,
                                                      //                  BIGNUM **kinvp, BIGNUM **rp)
			                   NULL                   //ECDSA_SIG *(*sign_sig)(const unsigned char *dgst,
                                                      //                       int dgst_len,
                                                      //                       const BIGNUM *in_kinv,
                                                      //                       const BIGNUM *in_r,
                                                      //                       EC_KEY *eckey)
			                   );
	}

	return r_pnt;

#endif

}

int HSM_PKCS11_rsa_sign ( int type, const unsigned char *m, unsigned int m_len,
	unsigned char *sigret, unsigned int *siglen, const RSA *rsa ) {

	PKCS11_HANDLER *lib = NULL;
	CK_OBJECT_HANDLE *pHandle = NULL;
	HSM *driver = NULL;

	CK_MECHANISM RSA_MECH = { CKM_RSA_PKCS, NULL_PTR, 0 };

	unsigned char *p = NULL;
	unsigned char *s = NULL;
	unsigned char *tmps = NULL;

#if OPENSSL_VERSION_NUMBER < 0x1010000fL
	X509_SIG sig;
	X509_SIG * sig_pnt = &sig;
#else
	X509_SIG * sig_pnt = X509_SIG_new();
#endif

	
	int i, j, rc;

	int keysize = 0;
	CK_ULONG ck_sigsize = 0;

	CK_RV rv = CKR_OK;

	unsigned char *buf = NULL;

	/* Default checks for mis-passed pointers */
	if (!m || !sigret || !siglen || !rsa || !sig_pnt) goto err;

	/* Retrieves the reference to the hsm */
	if((driver = (HSM *) RSA_get_ex_data (rsa, KEYPAIR_DRIVER_HANDLER_IDX))
								== NULL ) {
		PKI_ERROR(PKI_ERR_POINTER_NULL, "Can't get PKCS#11 Driver Handle");
		goto err;
	}

	/* Retrieves the privkey object handler */
	if((pHandle = (CK_OBJECT_HANDLE *) RSA_get_ex_data (rsa, 
				KEYPAIR_PRIVKEY_HANDLER_IDX)) == NULL ) {
		PKI_ERROR(PKI_ERR_POINTER_NULL, "Can't get PrivateKey Handle");
		goto err;
	}

	if ((lib = _hsm_get_pkcs11_handler ( driver )) == NULL ) {
		PKI_ERROR(PKI_ERR_POINTER_NULL, "Can not get PKCS#11 Library handler");
        goto err;
    }

	if(( HSM_PKCS11_session_new( lib->slot_id, &lib->session,
				CKF_SERIAL_SESSION, lib )) == PKI_ERR ) {
		PKI_log_debug("Failed to open a new session (R/W) with the token");
		goto err;
	}

	/* Now we need to check the real encoding */
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
	ASN1_OCTET_STRING digest;
	ASN1_TYPE parameter;
	X509_ALGOR algor;

	sig.algor = &algor;
	if((sig.algor->algorithm = OBJ_nid2obj(type)) == NULL ) {
		PKI_log_debug("HSM_PKCS11_rsa_sign()::Algor not recognized");
		return ( 0 );
	}

	if( algor.algorithm->length == 0 ) {
		PKI_log_debug("HSM_PKCS11_rsa_sign()::Algor length is 0");
		return ( 0 );
	}

	parameter.type = V_ASN1_NULL;
	parameter.value.ptr = NULL;
	sig.algor->parameter = &parameter;

	sig.digest = &digest;
	sig.digest->data = (unsigned char *) m;
	sig.digest->length = (int) m_len;

	i = i2d_X509_SIG(sig_pnt, NULL);

#else
	X509_ALGOR * alg = NULL;
	ASN1_OCTET_STRING * data = NULL;

	// Allocates a new signature
	if ((sig_pnt = X509_SIG_new()) == NULL) goto err;

	// Gets the modifiable algorithm and digest pointers
	X509_SIG_getm(sig_pnt, &alg, &data);

	// Sets the algorithm
	if (!X509_ALGOR_set0(alg, OBJ_nid2obj(type), V_ASN1_NULL, NULL)) goto err;

	// Sets the digest data
	if (!ASN1_OCTET_STRING_set(data, (unsigned char *)m, (int) m_len)) goto err;

	// Gets the size of the DER encoded signature
	i = i2d_X509_SIG(sig_pnt, NULL);
#endif

	if((keysize = RSA_size ( rsa )) == 0 ) {
		PKI_log_debug("HSM_PKCS11_rsa_sign()::KEY size is 0");
		goto err;
	}

	j=RSA_size(rsa);
	if( i > ( j - RSA_PKCS1_PADDING_SIZE )) {
		PKI_log_debug("HSM_PKCS11_rsa_sign()::Digest too big");
		goto err;
	}

	if((tmps = ( unsigned char *) PKI_Malloc ((unsigned int) j + 1 ))
								== NULL ) {
		PKI_log_debug("HSM_PKCS11_rsa_sign()::Memory alloc error!");
		return (0);
	}
	
	p = tmps;
	i2d_X509_SIG(sig_pnt, &p);
	s = tmps;

	rc = pthread_mutex_lock( &lib->pkcs11_mutex );
	PKI_log_debug( "pthread_mutex_lock()::RC=%d", rc );

	while(( rv = lib->callbacks->C_SignInit(lib->session, 
			&RSA_MECH, *pHandle)) == CKR_OPERATION_ACTIVE ) {
		int rc = 0;

		rc = pthread_cond_wait( &lib->pkcs11_cond, &lib->pkcs11_mutex );
		PKI_log_debug( "pthread_cond_wait()::RC=%d", rc );
	}

	if( rv != CKR_OK ) {
		PKI_log_debug("HSM_PKCS11_rsa_sign()::SignInit "
					"(2) failed with code 0x%8.8X", rv );
		pthread_cond_signal( &lib->pkcs11_cond );
		pthread_mutex_unlock( &lib->pkcs11_mutex );

		goto err;
	}

	ck_sigsize = *siglen;
	PKI_log_debug("HSM_PKCS11_rsa_sign()::i = %d, siglen = %d, "
		"sigret = %d (%p)", i, ck_sigsize, sizeof(sigret), sigret );

	/* Let's exagerate for now... */
	buf = PKI_Malloc (RSA_SIGNATURE_MAX_SIZE);
	PKI_log_debug("HSM_PKCS11_rsa_sign():: DEBUG %d", __LINE__ );

	ck_sigsize = RSA_SIGNATURE_MAX_SIZE;

	PKI_log_debug("HSM_PKCS11_rsa_sign():: DEBUG %d", __LINE__ );
	// if((rv = lib->callbacks->C_Sign( lib->session, (CK_BYTE *) m, 
	// 			m_len, sigret, &ck_sigsize)) != CKR_OK ) {
	if((rv = lib->callbacks->C_Sign( lib->session, (CK_BYTE *) s, 
				(CK_ULONG) i, buf, &ck_sigsize)) != CKR_OK ) {
		PKI_log_err("HSM_PKCS11_rsa_sign()::Sign failed with 0x%8.8X",
									rv);
		if( rv == CKR_BUFFER_TOO_SMALL ) {
			/* The sign session has to be terminated */
			/* To Be Done (TBD) */
			PKI_log_err("HSM_PKCS11_rsa_sign()::Buffer too ",
				"small (%s:%d)", __FILE__, __LINE__ );
		}

		pthread_cond_signal( &lib->pkcs11_cond );
		pthread_mutex_unlock( &lib->pkcs11_mutex );

		PKI_log_debug("HSM_PKCS11_rsa_sign():: DEBUG %d", __LINE__ );

		goto err;
	}

	pthread_cond_signal( &lib->pkcs11_cond );
	pthread_mutex_unlock( &lib->pkcs11_mutex );

	PKI_log_debug("HSM_PKCS11_rsa_sign():: DEBUG %d", __LINE__ );
	*siglen = (unsigned int) ck_sigsize;
	PKI_log_debug("HSM_PKCS11_rsa_sign():: DEBUG %d", __LINE__ );

	PKI_log_debug("HSM_PKCS11_rsa_sign():: BUF Written = %d", ck_sigsize );
	memcpy(sigret, buf, *siglen);

	// Free allocated memory
	if (tmps) PKI_Free ( tmps );
	if (buf) PKI_Free ( buf );

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
	if (sig_pnt) X509_SIG_free(sig_pnt);
#endif

	// Returns Success (1 is success in OpenSSL)
	return 1;

err:
	// Frees associated memory
	if (tmps) PKI_Free(tmps);
	if (buf) PKI_Free(buf);

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
	if (sig_pnt) X509_SIG_free(sig_pnt);
#endif


	// Returns the error (0 is error in OpenSSL)
	return 0;
}

int HSM_PKCS11_ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv, BIGNUM **r) {

	return PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED, NULL);
}

int HSM_PKCS11_ecdsa_sign ( int type, const unsigned char *dgst, int dlen,
	unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r,
    EC_KEY *eckey ) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED, NULL);
	return 0;

/*
int HSM_PKCS11_ecdsa_sign ( int type, const unsigned char *m, unsigned int m_len,
	unsigned char *sigret, unsigned int *siglen, const RSA *rsa ) {

	PKCS11_HANDLER *lib = NULL;
	CK_OBJECT_HANDLE *pHandle = NULL;
	HSM *driver = NULL;

	CK_MECHANISM RSA_MECH = { CKM_RSA_PKCS, NULL_PTR, 0 };

	unsigned char *p = NULL;
	unsigned char *s = NULL;
	unsigned char *tmps = NULL;

#if OPENSSL_VERSION_NUMBER < 0x1010000fL
	X509_SIG sig;
	X509_SIG * sig_pnt = &sig;
#else
	X509_SIG * sig_pnt = X509_SIG_new();
#endif

	
	int i, j, rc;

	int keysize = 0;
	CK_ULONG ck_sigsize = 0;

	CK_RV rv = CKR_OK;

	unsigned char *buf = NULL;

	// Default checks for mis-passed pointers
	if (!m || !sigret || !siglen || !rsa || !sig_pnt) goto err;

	// Retrieves the reference to the hsm
	if((driver = (HSM *) RSA_get_ex_data (rsa, KEYPAIR_DRIVER_HANDLER_IDX))
								== NULL ) {
		PKI_ERROR(PKI_ERR_POINTER_NULL, "Can't get PKCS#11 Driver Handle");
		goto err;
	}

	// Retrieves the privkey object handler
	if((pHandle = (CK_OBJECT_HANDLE *) RSA_get_ex_data (rsa, 
				KEYPAIR_PRIVKEY_HANDLER_IDX)) == NULL ) {
		PKI_ERROR(PKI_ERR_POINTER_NULL, "Can't get PrivateKey Handle");
		goto err;
	}

	if ((lib = _hsm_get_pkcs11_handler ( driver )) == NULL ) {
		PKI_ERROR(PKI_ERR_POINTER_NULL, "Can not get PKCS#11 Library handler");
        goto err;
    }

	if(( HSM_PKCS11_session_new( lib->slot_id, &lib->session,
				CKF_SERIAL_SESSION, lib )) == PKI_ERR ) {
		PKI_log_debug("Failed to open a new session (R/W) with the token");
		goto err;
	}

	// Now we need to check the real encoding
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
	ASN1_OCTET_STRING digest;
	ASN1_TYPE parameter;
	X509_ALGOR algor;

	sig.algor = &algor;
	if((sig.algor->algorithm = OBJ_nid2obj(type)) == NULL ) {
		PKI_log_debug("HSM_PKCS11_rsa_sign()::Algor not recognized");
		return ( 0 );
	}

	if( algor.algorithm->length == 0 ) {
		PKI_log_debug("HSM_PKCS11_rsa_sign()::Algor length is 0");
		return ( 0 );
	}

	parameter.type = V_ASN1_NULL;
	parameter.value.ptr = NULL;
	sig.algor->parameter = &parameter;

	sig.digest = &digest;
	sig.digest->data = (unsigned char *) m;
	sig.digest->length = (int) m_len;

	i = i2d_X509_SIG(sig_pnt, NULL);

#else
	X509_ALGOR * alg = NULL;
	ASN1_OCTET_STRING * data = NULL;

	// Allocates a new signature
	if ((sig_pnt = X509_SIG_new()) == NULL) goto err;

	// Gets the modifiable algorithm and digest pointers
	X509_SIG_getm(sig_pnt, &alg, &data);

	// Sets the algorithm
	if (!X509_ALGOR_set0(alg, OBJ_nid2obj(type), V_ASN1_NULL, NULL)) goto err;

	// Sets the digest data
	if (!ASN1_OCTET_STRING_set(data, (unsigned char *)m, (int) m_len)) goto err;

	// Gets the size of the DER encoded signature
	i = i2d_X509_SIG(sig_pnt, NULL);
#endif

	if((keysize = RSA_size ( rsa )) == 0 ) {
		PKI_log_debug("HSM_PKCS11_rsa_sign()::KEY size is 0");
		goto err;
	}

	j=RSA_size(rsa);
	if( i > ( j - RSA_PKCS1_PADDING_SIZE )) {
		PKI_log_debug("HSM_PKCS11_rsa_sign()::Digest too big");
		goto err;
	}

	if((tmps = ( unsigned char *) PKI_Malloc ((unsigned int) j + 1 ))
								== NULL ) {
		PKI_log_debug("HSM_PKCS11_rsa_sign()::Memory alloc error!");
		return (0);
	}
	
	p = tmps;
	i2d_X509_SIG(sig_pnt, &p);
	s = tmps;

	rc = pthread_mutex_lock( &lib->pkcs11_mutex );
	PKI_log_debug( "pthread_mutex_lock()::RC=%d", rc );

	while(( rv = lib->callbacks->C_SignInit(lib->session, 
			&RSA_MECH, *pHandle)) == CKR_OPERATION_ACTIVE ) {
		int rc = 0;

		rc = pthread_cond_wait( &lib->pkcs11_cond, &lib->pkcs11_mutex );
		PKI_log_debug( "pthread_cond_wait()::RC=%d", rc );
	}

	if( rv != CKR_OK ) {
		PKI_log_debug("HSM_PKCS11_rsa_sign()::SignInit "
					"(2) failed with code 0x%8.8X", rv );
		pthread_cond_signal( &lib->pkcs11_cond );
		pthread_mutex_unlock( &lib->pkcs11_mutex );

		goto err;
	}

	ck_sigsize = *siglen;
	PKI_log_debug("HSM_PKCS11_rsa_sign()::i = %d, siglen = %d, "
		"sigret = %d (%p)", i, ck_sigsize, sizeof(sigret), sigret );

	// Let's exagerate for now... 
	buf = PKI_Malloc (RSA_SIGNATURE_MAX_SIZE);
	PKI_log_debug("HSM_PKCS11_rsa_sign():: DEBUG %d", __LINE__ );

	ck_sigsize = RSA_SIGNATURE_MAX_SIZE;

	PKI_log_debug("HSM_PKCS11_rsa_sign():: DEBUG %d", __LINE__ );
	// if((rv = lib->callbacks->C_Sign( lib->session, (CK_BYTE *) m, 
	// 			m_len, sigret, &ck_sigsize)) != CKR_OK ) {
	if((rv = lib->callbacks->C_Sign( lib->session, (CK_BYTE *) s, 
				(CK_ULONG) i, buf, &ck_sigsize)) != CKR_OK ) {
		PKI_log_err("HSM_PKCS11_rsa_sign()::Sign failed with 0x%8.8X",
									rv);
		if( rv == CKR_BUFFER_TOO_SMALL ) {
			// The sign session has to be terminated
			// To Be Done (TBD)
			PKI_log_err("HSM_PKCS11_rsa_sign()::Buffer too ",
				"small (%s:%d)", __FILE__, __LINE__ );
		}

		pthread_cond_signal( &lib->pkcs11_cond );
		pthread_mutex_unlock( &lib->pkcs11_mutex );

		PKI_log_debug("HSM_PKCS11_rsa_sign():: DEBUG %d", __LINE__ );

		goto err;
	}

	pthread_cond_signal( &lib->pkcs11_cond );
	pthread_mutex_unlock( &lib->pkcs11_mutex );

	PKI_log_debug("HSM_PKCS11_rsa_sign():: DEBUG %d", __LINE__ );
	*siglen = (unsigned int) ck_sigsize;
	PKI_log_debug("HSM_PKCS11_rsa_sign():: DEBUG %d", __LINE__ );

	PKI_log_debug("HSM_PKCS11_rsa_sign():: BUF Written = %d", ck_sigsize );
	memcpy(sigret, buf, *siglen);

	// Free allocated memory
	if (tmps) PKI_Free ( tmps );
	if (buf) PKI_Free ( buf );

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
	if (sig_pnt) X509_SIG_free(sig_pnt);
#endif

	// Returns Success (1 is success in OpenSSL)
	return 1;

err:
	// Frees associated memory
	if (tmps) PKI_Free(tmps);
	if (buf) PKI_Free(buf);

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
	if (sig_pnt) X509_SIG_free(sig_pnt);
#endif

	// Returns the error (0 is error in OpenSSL)
	return 0;
*/

}

