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

#define PKI_RSA_KEY_MIN_SIZE		512
#define PKI_DSA_KEY_MIN_SIZE		512
#define PKI_EC_KEY_MIN_SIZE		56

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

	CK_MECHANISM RSA_MECH = {
		CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };

	CK_ULONG i = 0;
	CK_ULONG n = 0;

	int bits = -1;

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
		if( kp->bits < PKI_RSA_KEY_MIN_SIZE ) {
			PKI_ERROR(PKI_ERR_X509_KEYPAIR_SIZE_SHORT, NULL);
		};
	} else {
		bits = PKI_RSA_KEY_DEFAULT_SIZE;
	}

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


	/* Setting Attributes for the public Key Template */
	n = 0;
	//HSM_PKCS11_set_attr_int( CKA_CLASS, CKO_PUBLIC_KEY, &pubTemp[n++]);
	//HSM_PKCS11_set_attr_int( CKA_KEY_TYPE, CKK_RSA, &pubTemp[n++]);
	HSM_PKCS11_set_attr_int( CKA_MODULUS_BITS, (CK_ULONG)bits, &pubTemp[n++]);

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
			lib->session, &RSA_MECH, 
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
PKI_EC_KEY * _pki_pkcs11_ecdsakey_new( PKI_KEYPARAMS *kp,
			URL *url, PKCS11_HANDLER *lib, void *driver ) {

	PKI_EC_KEY *k = NULL;

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED, NULL );

	return ( k );
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

	if ( kp && kp->scheme > -1 ) type = kp->scheme;

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

RSA_METHOD *HSM_PKCS11_get_rsa_method ( void ) {

#if OPENSSL_VERSION_NUMBER < 0x1010000fL
	static RSA_METHOD ret;

	ret = *RSA_get_default_method();

	if (!ret.rsa_priv_enc) {
		// ret.rsa_priv_enc = HSM_PKCS11_rsa_encrypt;
		ret.rsa_priv_enc = NULL;
		// ret.rsa_priv_dec = HSM_PKCS11_rsa_decrypt;
		ret.rsa_priv_dec = NULL;
		ret.rsa_sign = HSM_PKCS11_rsa_sign;
		// ret.rsa_verify = HSM_PKCS11_rsa_verify;
		ret.rsa_verify = NULL;
	}
	return &ret;
#else
	RSA_METHOD * r_pnt = RSA_meth_dup(RSA_get_default_method());
	if (r_pnt != NULL) 
		RSA_meth_set_sign(r_pnt, HSM_PKCS11_rsa_sign);
	return r_pnt;
#endif
}

int HSM_PKCS11_rsa_sign ( int type, const unsigned char *m, unsigned int m_len,
	unsigned char *sigret, unsigned int *siglen, const RSA *rsa ) {

	PKCS11_HANDLER *lib = NULL;
	CK_OBJECT_HANDLE *pHandle = NULL;
	HSM *driver = NULL;

	CK_MECHANISM RSA_MECH = { CKM_RSA_PKCS, NULL_PTR, 0 };

	ASN1_TYPE parameter;
	X509_ALGOR algor;

	X509_SIG sig;

	unsigned char *p = NULL;
	unsigned char *s = NULL;
	unsigned char *tmps = NULL;

	int i, j, rc;

	ASN1_OCTET_STRING digest;

	int keysize = 0;
	CK_ULONG ck_sigsize = 0;

	CK_RV rv = CKR_OK;

	unsigned char *buf = NULL;

	PKI_log_debug("RSA::SIGN::PKCS#11::START");

	/* Default checks for mis-passed pointers */
	if (!m | !sigret | !siglen | !rsa ) 
			return (0 /* 0 = PKI_ERR in OpenSSL */ );

	/* Retrieves the reference to the hsm */
	if((driver = (HSM *) RSA_get_ex_data (rsa, KEYPAIR_DRIVER_HANDLER_IDX))
								== NULL ) {
		PKI_log_err ("HSM_PKCS11_rsa_sign()::Can't get Driver Handle");
		return ( 0 /* 0 = PKI_ERR in OpenSSL */ );
	}

	/* Retrieves the privkey object handler */
	if((pHandle = (CK_OBJECT_HANDLE *) RSA_get_ex_data (rsa, 
				KEYPAIR_PRIVKEY_HANDLER_IDX)) == NULL ) {
		PKI_log_err ("HSM_PKCS11_rsa_sign()::Can't get pKey Handle");
		return ( 0 /* 0 = PKI_ERR in OpenSSL */ );
	}

	if ((lib = _hsm_get_pkcs11_handler ( driver )) == NULL ) {
                PKI_log_err("HSM_PKCS11_rsa_sign()::Can not get lib handler");
                return ( 0 /* 0 = PKI_ERR in OpenSSL */ );
        }

	if(( HSM_PKCS11_session_new( lib->slot_id, &lib->session,
				CKF_SERIAL_SESSION, lib )) == PKI_ERR ) {

		PKI_log_debug("HSM_PKCS11_KEYPAIR_new()::Failed in opening a "
				"new session (R/W) with the token" );
		return ( 0 );
	};

	/* Now we need to check the real encoding */
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

	i = i2d_X509_SIG( &sig, NULL);

	if((keysize = RSA_size ( rsa )) == 0 ) {
		PKI_log_debug("HSM_PKCS11_rsa_sign()::KEY size is 0");
		return ( 0 );
	}

	j=RSA_size(rsa);
	if( i > ( j - RSA_PKCS1_PADDING_SIZE )) {
		PKI_log_debug("HSM_PKCS11_rsa_sign()::Digest too big");
		return ( 0 );
	}

	if((tmps = ( unsigned char *) PKI_Malloc ((unsigned int) j + 1 ))
								== NULL ) {
		PKI_log_debug("HSM_PKCS11_rsa_sign()::Memory alloc error!");
		return (0);
	};
	
	p = tmps;
	i2d_X509_SIG( &sig, &p );
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

		return ( 0 /* 0 = PKI_ERR in OpenSSL */ );
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
		if( buf ) PKI_Free ( buf );

		PKI_log_debug("HSM_PKCS11_rsa_sign():: DEBUG %d", __LINE__ );

		return ( 0 /* 0 = PKI_ERR in OpenSSL */ );
	}

	pthread_cond_signal( &lib->pkcs11_cond );
	pthread_mutex_unlock( &lib->pkcs11_mutex );

	PKI_log_debug("HSM_PKCS11_rsa_sign():: DEBUG %d", __LINE__ );
	*siglen = (unsigned int) ck_sigsize;
	PKI_log_debug("HSM_PKCS11_rsa_sign():: DEBUG %d", __LINE__ );

	PKI_log_debug("HSM_PKCS11_rsa_sign():: BUF Written = %d", ck_sigsize );
	memcpy( sigret, buf, *siglen );

	PKI_log_debug("HSM_PKCS11_rsa_sign():: DEBUG %d", __LINE__ );
	if( tmps ) PKI_Free ( tmps );
	PKI_log_debug("HSM_PKCS11_rsa_sign():: DEBUG %d", __LINE__ );
	if( buf ) PKI_Free ( buf );
	PKI_log_debug("HSM_PKCS11_rsa_sign():: DEBUG %d", __LINE__ );

	return ( 1 /* 1 = PKI_OK in OpenSSL */ );
}

