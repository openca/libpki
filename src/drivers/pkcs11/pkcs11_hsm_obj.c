/* drivers/pkcs11/pkcs11_hsm_obj.c */

#include <libpki/pki.h>

/* -------------------- Internal Function --------------------------------- */
int _get_der ( void *data, int objType, int type, unsigned char **ret ) {

	int len = 0;

	X509_NAME * name = NULL;
	ASN1_INTEGER * serial = NULL;

	switch (type) {

		case PKI_X509_DATA_SUBJECT: {
			name = X509_get_subject_name((X509 *)data);
			if (name) len = i2d_X509_NAME(name, ret);
		} break;
		
		case PKI_X509_DATA_ISSUER: {
			name = X509_get_issuer_name((X509 *)data);
			if (name) len = i2d_X509_NAME(name, ret);
		} break;	
		
		case PKI_X509_DATA_SERIAL: {
			serial = X509_get_serialNumber((X509 *)data);
			if (serial) i2d_ASN1_INTEGER(serial, ret);
		} break;

		default: {
			return 0;
		}
	}

	return len;
}

/* ------------------ PKCS11 HSM Keypair get/put -------------------------- */

PKI_X509_STACK * HSM_PKCS11_OBJSK_get_url ( PKI_DATATYPE type, URL *url, 
						PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm ) {

	void * ret = NULL;

	if( !url ) return ( NULL );

	switch ( type ) {
		case PKI_DATATYPE_X509_KEYPAIR:
			ret = (void *) HSM_PKCS11_KEYPAIR_get_url ( url,
						format, cred, hsm );
			break;
		default:
			ret = (void *) HSM_PKCS11_STACK_get_url ( type, url,
						format, cred, hsm );
	}

	return ( ret );
}

int HSM_PKCS11_OBJSK_add_url ( PKI_X509_STACK *sk,
					URL *url, PKI_CRED *cred, HSM *hsm ) {

	int ret = PKI_OK;
	PKI_X509 * x = NULL;

	if( !url ) return ( PKI_ERR );

	if ( !sk || (PKI_STACK_X509_elements ( sk ) <= 0) ) return PKI_ERR;

	if((x = PKI_STACK_X509_get_num ( sk, 0 )) == NULL ) {
		return PKI_ERR;
	}

	switch ( x->type ) {
		case PKI_DATATYPE_X509_KEYPAIR:
			ret = HSM_PKCS11_KEYPAIR_STACK_add_url ( 
						sk, url, cred, hsm );
			break;
		default:
			ret = HSM_PKCS11_STACK_add_url (sk, url, cred, hsm);
	}

	return ( ret );
}

int HSM_PKCS11_OBJSK_del_url ( PKI_DATATYPE type, 
					URL *url, PKI_CRED *cred, HSM *hsm){

	CK_ULONG objClass = CKO_DATA;
	CK_RV rv;

	PKCS11_HANDLER 		*lib = NULL;

	CK_OBJECT_HANDLE 	hObject;
	CK_ULONG	 	ulObjectCount;

	int rc = 0;

	/* Check the Input */
	if( (url == NULL ) || (url->addr == NULL )) return ( PKI_ERR );

	/* We need a valid driver */
	if( !hsm ) {
		PKI_log_debug ( "HSM_PKCS11_OBJSK_del_url()::ERROR, no "
			"hsm driver provided!");
		return ( PKI_ERR );
	}

	if ((lib = _hsm_get_pkcs11_handler ( hsm )) == NULL ) {
		PKI_log_debug ("HSM_PKCS11_OBJSK_del()::No handler");
		return ( PKI_ERR );
	}

	if( url->proto != URI_PROTO_ID ) {
		/* The PKCS11 driver can load only id:// keypairs! */
		return ( PKI_ERR );
	}

	if( HSM_PKCS11_session_new( lib->slot_id, &lib->session, 
			CKF_SERIAL_SESSION | CKF_RW_SESSION, lib ) != PKI_OK ) {
		PKI_log_debug ("Can not get a new Session!");
		return ( PKI_ERR );
	}

	/* Login into the device - do nothing if we are already logged in */
	if(( HSM_PKCS11_login ( hsm, cred )) == PKI_ERR ) {
		PKI_log_debug("HSM_PKCS11_OBJSK_del_url()::ERROR, can not "
					"login to device!");
		return ( PKI_ERR );
	}

	rc = pthread_mutex_lock( &lib->pkcs11_mutex );
	if (rc != 0)
	{
		PKI_log_err("HSM_PKCS11_OBJSK_del()::pthread_mutex_lock() failed with %d", rc);
		return PKI_ERR;
	}

	while ((rv = lib->callbacks->C_FindObjectsInit(lib->session,
				NULL, 0)) == CKR_OPERATION_ACTIVE)
	{
		rc = pthread_cond_wait ( &lib->pkcs11_cond,
						&lib->pkcs11_mutex );

		if (rc != 0)
		{
			PKI_log_err("HSM_PKCS11_OBJSK_del_url(): ERROR %d: wait on cond variable",
				rc);
		}
	}

	if( rv != CKR_OK ) {
		pthread_cond_broadcast( &lib->pkcs11_cond );
		pthread_mutex_unlock( &lib->pkcs11_mutex );

		return ( PKI_ERR );
	}

	while ( 1 ) {
		rv = lib->callbacks->C_FindObjects(lib->session, &hObject, 
							1, &ulObjectCount );

		if( rv != CKR_OK || ulObjectCount == 0 ) {
			PKI_log_debug("[Find] - Find Exiting (rv=0x%8.8X - "
				"ulObjectCount = %lu)", rv, ulObjectCount );
			break;
		}

		if(( url != NULL ) && ( url->addr != NULL ) && 
						(strlen(url->addr) > 0) ) {
			char *buf = NULL;
			char *p = url->addr;

			/* Check the object's ID */
			if((HSM_PKCS11_get_attr_sn( &hObject, &lib->session,
                        	CKA_LABEL, &buf, lib )) > 0) {

				if ( ( !buf ) || (strcmp ( buf, p ) != 0 )) {
					// PKI_log_debug("LABEL::Continue"
					// 	" (%s != %s)", buf, p );
					PKI_Free ( buf );
					continue;
				}
				PKI_Free ( buf );
			} else {
				/* No label found, but user provided one! */
				continue;
			}
		};

		if( (url != NULL) && (url->path != NULL) && 
						(strlen(url->path) > 0)) {
			BIGNUM *bn = NULL;
			char *buf = NULL;

			/* Check the object's ID */
			HSM_PKCS11_get_attr_bn( &hObject, &lib->session,
                        				CKA_ID, &bn, lib );
			if( bn ) {
                        	if( BN_num_bytes ( bn ) > 0 ) {
                        	        buf = BN_bn2hex ( bn );
                        	}
                        	BN_free ( bn );
                	}

			if ( buf ) {
				if ( strcmp ( buf, url->path ) != 0 ) {
					// PKI_log_debug("ID::Continue "
					// 	"(%s != %s)", buf, url->path );
					PKI_Free ( buf );
					continue;
				}
				PKI_Free ( buf );
			} else {
				/* No label found, but user provided one! */
				continue;
			}
		}

		if ( type != PKI_DATATYPE_ANY ) {
			/* Now let's check the Type */
			CK_ULONG objId = 0;

			switch ( type ) {
				case PKI_DATATYPE_X509_CERT:
				case PKI_DATATYPE_X509_CA:
				case PKI_DATATYPE_X509_OTHER:
				case PKI_DATATYPE_X509_TRUSTED:
					break;
				case PKI_DATATYPE_PRIVKEY:
					objClass = CKO_PRIVATE_KEY;
					break;
				case PKI_DATATYPE_PUBKEY:
					objClass = CKO_PUBLIC_KEY;
					break;
				case PKI_DATATYPE_X509_CRL:
				case PKI_DATATYPE_X509_REQ:
				case PKI_DATATYPE_X509_CMS:
				case PKI_DATATYPE_X509_PKCS7:
				case PKI_DATATYPE_X509_PKCS12:
				default:
					objClass = CKO_DATA;
			}

			if((HSM_PKCS11_get_attr_ckulong(&hObject, &lib->session,
                        	CKA_CLASS, &objId, lib )) > 0) {

				if ( objId != objClass ) {
					// PKI_log_debug("CLASS::Continue "
					// 	"(%d != %d)", objId, objClass);
					continue;
				}
			}
		}

		/* Now we should delete the object! */
		if((rv = lib->callbacks->C_DestroyObject(lib->session, hObject))
                                                                != CKR_OK ) {
                        PKI_log_debug("HSM_PKCS11_del_obj()::Can not destroy "
                                "object (0x%8.8X)", rv );
                }
	}
        /* Cleanup the memory for Templates */ 
        // HSM_PKCS11_clean_template ( templ, (int) idx );

	if((rv = lib->callbacks->C_FindObjectsFinal(lib->session)) != CKR_OK ) {
                PKI_log_debug ("Error in Find Finalize (0x%8.8X)", rv);
		pthread_cond_broadcast( &lib->pkcs11_cond );
		pthread_mutex_unlock( &lib->pkcs11_mutex );

                return ( PKI_ERR );
        }

	pthread_cond_signal( &lib->pkcs11_cond );
	pthread_mutex_unlock( &lib->pkcs11_mutex );

	return ( PKI_OK );
		
}
/* ------------------------ Internal Functions -------------------------- */

PKI_X509_STACK *HSM_PKCS11_KEYPAIR_get_url( URL *url,
					PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm ) {

    PKI_X509_KEYPAIR *ret = NULL;
    PKI_X509_KEYPAIR_VALUE *val = NULL;
	PKI_X509_KEYPAIR_STACK *ret_sk = NULL;

	CK_ATTRIBUTE templ[32];
	CK_ULONG idx = 0;

	CK_ULONG keyType = CKK_RSA;
	CK_OBJECT_HANDLE *pubKey = NULL;
	CK_OBJECT_HANDLE *privKey = NULL;

	PKCS11_HANDLER *lib = NULL;

	PKI_RSA_KEY *rsa = NULL;

	/* Check the Input */
	if( !url || !url->addr ) return ( NULL );

	/* We need a valid driver */
	if( !hsm ) {
		PKI_ERROR(PKI_ERR_HSM_POINTER_NULL, NULL);
		return ( NULL );
	}

	if ((lib = _hsm_get_pkcs11_handler ( hsm )) == NULL ) {
		PKI_ERROR(PKI_ERR_HSM_PKCS11_LIB_POINTER_NULL, NULL);
		return NULL;
	}

	/* And valid credentials */
	/*
	if( cred && cred->password ) {
		pp = (char *) cred->password;
	}
	*/

	if( url->proto != URI_PROTO_ID ) {
		/* The PKCS11 driver can load only id:// keypairs! */
		return ( NULL );
	}

	/* We need an R/W session for accessing private keys */
	if( HSM_PKCS11_session_new( lib->slot_id, &lib->session, 
			CKF_SERIAL_SESSION | CKF_RW_SESSION, lib ) != PKI_OK ) {
		return ( PKI_ERR );
	}

	PKI_log_debug("HSM_PKCS11_KEYPAIR_get_url()::Got a New Session");

	/* Login into the device - do nothing if we are already logged in */
	if(( HSM_PKCS11_login ( hsm, cred )) == PKI_ERR ) {
		PKI_log_debug("HSM_PKCS11_KEYPAIR_get_url()::ERROR, can not "
					"login to device!");
		return ( NULL );
	}

	PKI_log_debug("HSM_PKCS11_KEYPAIR_get_url()::Logged In");

	/* Build the template in order to search for the private key
	   we need */
	idx = 0;
	HSM_PKCS11_set_attr_int(CKA_CLASS, CKO_PRIVATE_KEY, &templ[idx++]);	
	PKI_log_debug("HSM_PKCS11_KEYPAIR_get_url()::Adding Label for Search %s (%d)",
						url->addr, strlen(url->addr) );
	HSM_PKCS11_set_attr_sn(CKA_LABEL, url->addr, strlen(url->addr), 
							&templ[idx++]);	
	if ( url->path != NULL ) {
		BIGNUM *bn = NULL;

		if(BN_hex2bn(&bn, url->path) > 0 ) {
			HSM_PKCS11_set_attr_bn(CKA_ID, bn, &templ[idx++]);	
			if( bn ) BN_free (bn);
		}
	}

	if((privKey = HSM_PKCS11_get_obj( templ, (int) idx, lib, 
						&lib->session )) == NULL ) {
		PKI_log_debug("HSM_PKCS11_KEYPAIR_get_url()::Priv Key not Found (%s)!",
						url->addr);
		return ( NULL );
	}

        /* Cleanup the memory for Templates */ 
        HSM_PKCS11_clean_template ( templ, (int) idx );

	PKI_log_debug("HSM_PKCS11_KEYPAIR_get_url()::Private Key found (%s)!",
							url->addr);

	/* Login into the device - do nothing if we are already logged in */
	/*
	if(( HSM_PKCS11_login ( driver, cred )) == PKI_ERR ) {
		PKI_log_debug("HSM_PKCS11_KEYPAIR_get_url()::ERROR, can not "
					"login to device!");
		return ( NULL );
	}
	*/

	if ( url->path == NULL ) {
		BIGNUM *bn = NULL;

		HSM_PKCS11_get_attr_bn(privKey, &lib->session,
                                CKA_ID, &bn, lib );

		if( bn ) {
			if( BN_num_bytes ( bn ) > 0 ) {
				url->path = BN_bn2hex ( bn );
			}
			BN_free ( bn );
		}
	}

	// HSM_PKCS11_session_close ( &lib->session, lib );

	/* We need an R/W session for accessing private keys */
	/*
	if( HSM_PKCS11_session_new( lib->slot_id, &lib->session, 
			CKF_SERIAL_SESSION | CKF_RW_SESSION, lib ) != PKI_OK ) {
		PKI_log_err ( "DEBUG::%s:%d", __FILE__, __LINE__ );
		return ( PKI_ERR );
	}
	*/

	idx = 0;
	HSM_PKCS11_set_attr_int(CKA_CLASS, CKO_PUBLIC_KEY, &templ[idx++]);	
	// HSM_PKCS11_set_attr_sn(CKA_LABEL, url->addr, strlen(url->addr), 
	// 						&templ[idx++]);	
	if ( url->path != NULL ) {
		BIGNUM *bn = NULL;

		if(BN_hex2bn(&bn, url->path)) {

			HSM_PKCS11_set_attr_bn ( CKA_ID, bn, &templ[idx++]);

			/*
			char *str = NULL;
			int str_len = 0;

			str_len = BN_num_bytes( bn );
			if( str_len ) str = PKI_Malloc ( str_len );

			if( str ) {
				HSM_PKCS11_set_attr_sn(CKA_ID, str, str_len,
							&templ[idx++]);
			}
			*/
		}

		if( bn ) BN_free ( bn );
	}

	if((pubKey = HSM_PKCS11_get_obj( templ, (int) idx, 
					lib, &lib->session )) == NULL ) {

		PKI_log_debug("HSM_PKCS11_KEYPAIR_get_url()::Public Key not Found (%s)!",
						url->addr);
		return ( NULL );
	}

	PKI_log_debug("HSM_PKCS11_KEYPAIR_get_url()::Public Key found (%s)!",
						url->addr );

        /* Cleanup the memory for Templates */ 
        HSM_PKCS11_clean_template ( templ, (int) idx );

	HSM_PKCS11_get_attr_ckulong( privKey, &lib->session,
                                	CKA_KEY_TYPE, &keyType, lib );

	if( keyType == CKK_RSA ) {

		BIGNUM *e_bn = NULL;
		BIGNUM *n_bn = NULL;

		if ((rsa = RSA_new()) == NULL) return NULL;

		if( HSM_PKCS11_get_attr_bn(pubKey, 
					   &lib->session,
					   CKA_PUBLIC_EXPONENT, 
					   &e_bn, 
					   lib) == PKI_ERR){
			// Reports the error
			PKI_log_debug("Can not retrieve pub exponent from "
				      "key (%s)", url->addr);
			// Free the memory
			RSA_free ( rsa );

			// Returns NULL
			return NULL;
		}
		
		if( HSM_PKCS11_get_attr_bn( pubKey, &lib->session,
				CKA_MODULUS, &n_bn, lib) == PKI_ERR){
			// Reports the error
			PKI_log_debug ( "Can not retrieve modulus from key %s",
					url->addr);
			// Free Memory
			if (e_bn) BN_free(e_bn);
			RSA_free ( rsa );

			// Returns NULL
			return NULL;
		}

#if OPENSSL_VERSION_NUMBER < 0x1010000fL

		// OpenSSL old assign method
		rsa->n = n_bn;
		rsa->e = e_bn;

		// Sets the Flags
        	rsa->flags |= RSA_FLAG_SIGN_VER;
#else
		// OpenSSL v1.1.x+ assign method
		if (!RSA_set0_key(rsa, n_bn, e_bn, NULL)) {
			PKI_log_debug("Can not assign internal RSA values "
				      "for key %s", url->addr);

			// Free Memory
			if (e_bn) BN_free(e_bn);
			if (n_bn) BN_free(n_bn);
			RSA_free(rsa);

			// Returns NULL
			return NULL;
		}

		// No Setting of the flags as the RSA_FLAG_SIGN_VER
		// has been removed in OpenSSL v1.1.x+
		// RSA_set_flags(rsa, RSA_FLAG_SIGN_VER);
#endif
		
		/* Let's get the Attributes from the Keypair and store into the
        	   key's pointer */
        	RSA_set_method(rsa, HSM_PKCS11_get_rsa_method());

        	/* Push the priv and pub key handlers to the rsa->ex_data */
        	RSA_set_ex_data( rsa, KEYPAIR_DRIVER_HANDLER_IDX, hsm );
        	RSA_set_ex_data( rsa, KEYPAIR_PRIVKEY_HANDLER_IDX, privKey );
        	RSA_set_ex_data( rsa, KEYPAIR_PUBKEY_HANDLER_IDX, pubKey );

		if((val = (PKI_X509_KEYPAIR_VALUE *) EVP_PKEY_new()) == NULL ) {
			PKI_log_debug ( "Memory Error");
			RSA_free ( rsa );
			return ( NULL );
		}

		if(!EVP_PKEY_assign_RSA( (EVP_PKEY *) val, rsa)) {
			PKI_log_debug ( "Can not assing RSA key to Keypair!");
			EVP_PKEY_free ( val );
			RSA_free ( rsa );
			return ( NULL );
		}

	} else if ( keyType == CKK_DSA ) {
		PKI_log_debug("HSM_PKCS11_KEYPAIR_get_url()::"
				"DSA support missing!");
		return NULL;
	} else if ( keyType == CKK_EC ) {
#ifdef ENABLE_ECDSA
		PKI_log_debug("HSM_PKCS11_KEYPAIR_get_url()::"
				"EC support not available, yet!");
#else
		PKI_log_debug("HSM_PKCS11_KEYPAIR_get_url()::"
				"library does not have EC support!");
#endif
		return NULL;
	}

	if ((ret = PKI_X509_new(PKI_DATATYPE_X509_KEYPAIR, hsm)) == NULL) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		if ( val ) EVP_PKEY_free ( val );
		return (NULL);
	}

	ret->value = val;

	/* Allocate the STACK for the return values */
	if((ret_sk = PKI_STACK_X509_KEYPAIR_new()) == NULL ) {
		/* Big trouble! */
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		if (ret) PKI_X509_KEYPAIR_free(ret);
		return ( NULL );
	}

	PKI_STACK_X509_KEYPAIR_push( ret_sk, ret );

	PKI_log_debug( "HSM_PKCS11_KEYPAIR_get_url()::Keypair loaded success!");

        return ( ret_sk );
}

/* --------------------------- General STACK get/put ----------------------- */

PKI_X509_STACK *HSM_PKCS11_STACK_get_url( PKI_DATATYPE type, URL *url, 
						PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm ) {

	PKI_STACK *ret_sk = NULL;

	CK_ATTRIBUTE templ[32];
	CK_ULONG idx = 0;
	CK_ULONG objClass;
	CK_RV rv;

	int rc = 0;

	PKCS11_HANDLER *lib = NULL;

	CK_OBJECT_HANDLE hObject;
	CK_ULONG	 ulObjectCount;

	char myLabel[512];

	if((type == PKI_DATATYPE_X509_KEYPAIR) ||
				(type == PKI_DATATYPE_SECRET_KEY )) {
		return HSM_PKCS11_KEYPAIR_get_url( url, format, cred, hsm );
	}

	/* Check the Input */
	if( !url || !url->addr ) return ( NULL );

	/* We need a valid driver */
	if( !hsm ) {
		PKI_ERROR(PKI_ERR_HSM_POINTER_NULL, NULL);
		return NULL;
	}

	if ((lib = _hsm_get_pkcs11_handler ( hsm )) == NULL ) {
		PKI_ERROR(PKI_ERR_HSM_PKCS11_LIB_POINTER_NULL, NULL);
		return NULL;
	}

	if( url->proto != URI_PROTO_ID ) {
		/* The PKCS11 driver can load only id:// keypairs! */
		return ( NULL );
	}

	/* We need an R/W session only for accessing private keys, AFAIK.
 	 * Therefore now we do not use CKF_RW_SESSION as a flag.         */
	if( HSM_PKCS11_session_new( lib->slot_id, &lib->session, 
			CKF_SERIAL_SESSION, lib ) != PKI_OK ) {
		return ( NULL );
	}

	/* Login into the device - do nothing if we are already logged in */
	if(( HSM_PKCS11_login ( hsm, cred )) == PKI_ERR ) {
		PKI_log_debug("HSM_PKCS11_STACK_get_url()::ERROR, can not "
					"login to device!");
		return ( NULL );
	}

	/* Build the template in order to search for the object
	   we need */
	memset(myLabel, 0x0, sizeof(myLabel));
	strncpy(myLabel, url->addr, sizeof(myLabel) - 1);
	switch ( type ) {
		case PKI_DATATYPE_X509_CERT:
			objClass = CKO_CERTIFICATE;
			ret_sk = PKI_STACK_X509_CERT_new();
			break;
		case PKI_DATATYPE_X509_CRL:
			objClass = CKO_DATA;
			strncat(myLabel, "'s CRL", sizeof(myLabel) - 1);
			ret_sk = PKI_STACK_X509_CRL_new();
			break;
		case PKI_DATATYPE_X509_REQ:
			objClass = CKO_DATA;
			strncat(myLabel, "'s Request", sizeof(myLabel) - 1);
			ret_sk = PKI_STACK_X509_REQ_new();
			break;
		case PKI_DATATYPE_X509_CA:
			objClass = CKO_CERTIFICATE;
			strncat(myLabel, "'s CA", sizeof(myLabel) - 1);
			ret_sk = PKI_STACK_X509_CERT_new();
			break;
		case PKI_DATATYPE_X509_TRUSTED:
			objClass = CKO_CERTIFICATE;
			strncat(myLabel, "'s TA Cert", sizeof(myLabel) - 1);
			ret_sk = PKI_STACK_X509_CERT_new();
			break;
		case PKI_DATATYPE_X509_OTHER:
			objClass = CKO_CERTIFICATE;
			strncat(myLabel, "'s Other Cert", sizeof(myLabel) - 1);
			ret_sk = PKI_STACK_X509_CERT_new();
			break;
		case PKI_DATATYPE_X509_PKCS7:
			objClass = CKO_SECRET_KEY;
			ret_sk = PKI_STACK_X509_KEYPAIR_new();
			break;
		case PKI_DATATYPE_X509_PKCS12:
			objClass = CKO_SECRET_KEY;
			ret_sk = PKI_STACK_X509_KEYPAIR_new();
			break;
		case PKI_DATATYPE_CRED:
		default:
			ret_sk = PKI_STACK_X509_new();
			objClass = CKO_DATA;
			break;
	}

	idx = 0;
	HSM_PKCS11_set_attr_int(CKA_CLASS, objClass, &templ[idx++]);
	HSM_PKCS11_set_attr_sn(CKA_LABEL, myLabel, strlen(myLabel), 
							&templ[idx++]);	
	HSM_PKCS11_set_attr_sn(CKA_APPLICATION, myLabel, strlen(myLabel), 
							&templ[idx++]);	

	if ( url->path != NULL ) {
		HSM_PKCS11_set_attr_sn(CKA_ID, url->path, 
			strlen( url->path ), &templ[idx++]);	
	}

	rc = pthread_mutex_lock( &lib->pkcs11_mutex );
	if (rc != 0)
	{
		PKI_log_err("HSM_PKCS11_STACK_get_url()::pthread_mutex_lock() failed with %d at %s:%d",
			rc, __FILE__, __LINE__);
		return PKI_ERR;
	}

	while(( rv = lib->callbacks->C_FindObjectsInit(lib->session,
			templ, idx)) == CKR_OPERATION_ACTIVE)
	{
		rc = pthread_cond_wait(&lib->pkcs11_cond, &lib->pkcs11_mutex);
		if (rc != 0)
		{
			PKI_log_err("HSM_PKCS11_STACK_get_url(): ERROR %d: wait on cond variable", rc);
		}
	}

	if( rv != CKR_OK ) {
		PKI_log_debug("HSM_PKCS11_STACK_get_url()::"
				"Error in Find Initialization (0x%8.8X)", rv);
		pthread_cond_broadcast( &lib->pkcs11_cond );
		pthread_mutex_unlock( &lib->pkcs11_mutex );

		return ( PKI_ERR );
	}

	while ( 1 ) {
		PKI_MEM *mem = NULL;
		PKI_STACK *tmp_sk = NULL;
		void * x = NULL;
		CK_ULONG size = 0;

		rv = lib->callbacks->C_FindObjects(lib->session, &hObject, 
							1, &ulObjectCount );

		if( rv != CKR_OK || ulObjectCount == 0 ) {
			// PKI_log_debug("[Find] - Find Exiting (rv=0x%8.8X - "
			// 	"ulObjectCount = %lu", rv, ulObjectCount );
			break;
		}

		if(( mem = PKI_MEM_new_null()) == NULL ) {
			return ( NULL );
		}

		HSM_PKCS11_get_attribute (&hObject, &lib->session, 
			CKA_VALUE, (void **) &mem->data, &size, lib );
		mem->size = (size_t) size;

		switch ( type ) {
			case PKI_DATATYPE_X509_OTHER:
			case PKI_DATATYPE_X509_TRUSTED:
			case PKI_DATATYPE_X509_CA:
			case PKI_DATATYPE_X509_CERT:
			//	tmp_sk = PKI_X509_CERT_STACK_get_mem(mem, cred);
			//	break;
			case PKI_DATATYPE_X509_CRL:
			//	tmp_sk = PKI_X509_CRL_STACK_get_mem(mem, cred);
			//	break;
			case PKI_DATATYPE_X509_REQ:
			// 	tmp_sk = PKI_X509_REQ_STACK_get_mem(mem, cred);
			// 	break;
			case PKI_DATATYPE_X509_CMS:
			case PKI_DATATYPE_X509_PKCS7:
			case PKI_DATATYPE_X509_PKCS12:
				tmp_sk = PKI_X509_STACK_get_mem(mem, type,
					format, cred, hsm );
				break;
			case PKI_DATATYPE_CRED:
			default:
				break;
		}

		if ( !tmp_sk ) {
			continue;
		}

		while((x = PKI_STACK_pop(tmp_sk)) != NULL ) {
			PKI_X509 *n_obj = NULL;
			n_obj = PKI_X509_new ( type, hsm );
			if( n_obj ) {
				n_obj->value = x;
				PKI_STACK_push (ret_sk, n_obj );
			}
		}

		if( tmp_sk ) PKI_STACK_free ( tmp_sk );
		if( mem ) PKI_MEM_free ( mem );

	}
        /* Cleanup the memory for Templates */ 
        HSM_PKCS11_clean_template ( templ, (int) idx );

	if((rv = lib->callbacks->C_FindObjectsFinal(lib->session)) != CKR_OK ) {
                PKI_log_debug ("Error in Find Finalize (0x%8.8X)", rv);
		pthread_cond_broadcast( &lib->pkcs11_cond );
		pthread_mutex_unlock( &lib->pkcs11_mutex );

                return ( PKI_ERR );
        }

	pthread_cond_signal( &lib->pkcs11_cond );
	pthread_mutex_unlock( &lib->pkcs11_mutex );

        return ( ret_sk );
}
 
int HSM_PKCS11_STACK_add_url( PKI_X509_STACK *sk, URL *url, 
					PKI_CRED *cred, HSM *hsm ) {

	char myLabel[2048];

	CK_ATTRIBUTE templ[32];

	CK_ULONG idx = 0;
	// CK_ULONG objClass;

	PKCS11_HANDLER *lib = NULL;
	CK_OBJECT_HANDLE *obj = NULL;

	// int	(*func)() = NULL;
	PKI_X509 * x = NULL;
	int path_len = 0;

	if ( !sk || !url ) return ( PKI_ERR );

	/* We need a valid driver */
	if( !hsm ) {
		PKI_log_debug ( "HSM_PKCS11_STACK_add_url()::ERROR, no "
			"hsm driver provided!");
		return ( PKI_ERR );
	}

	if ((lib = _hsm_get_pkcs11_handler ( hsm )) == NULL ) {
		PKI_log_debug ("HSM_PKCS11_STACK_add_url()::No handler");
		return ( PKI_ERR );
	}

	if( url->proto != URI_PROTO_ID ) {
		/* The PKCS11 driver can load only id:// keypairs! */
		PKI_log_debug ("HSM_PKCS11_STACK_add_url()::Wrong protocol!");
		return ( PKI_ERR );
	}

	/* We need an R/W session for creating objects on Token */
	if( HSM_PKCS11_session_new( lib->slot_id, &lib->session, 
			CKF_SERIAL_SESSION | CKF_RW_SESSION, lib ) != PKI_OK ) {
		return ( PKI_ERR );
	}

	/* Login into the device - do nothing if we are already logged in */
	if(( HSM_PKCS11_login ( hsm, cred )) == PKI_ERR ) {
		PKI_log_debug("HSM_PKCS11_STACK_put_url()::ERROR, can not "
					"login to device!");
		return ( PKI_ERR );
	}

	memset(myLabel, 0x0, sizeof(myLabel));
	strncpy(myLabel, url->addr, sizeof(myLabel) - 1);

	if( url->path ) {
		path_len = (int) strlen( url->path );
	}

	while ( ( x = PKI_STACK_pop( sk )) != NULL ) {

		int ret = PKI_OK;
		
		idx = 0;

		switch (x->type)
		{
			case PKI_DATATYPE_X509_CERT:
					idx = (CK_ULONG) 
					HSM_PKCS11_X509_CERT_get_template(templ, x, 
						myLabel, (int) strlen(myLabel), url->path, path_len);
				break;
			case PKI_DATATYPE_X509_CRL:
				// objClass = CKO_DATA;
				// func = i2d_X509_CRL;
				strncat(myLabel, "'s CRL", sizeof(myLabel) - 1);
				break;
			case PKI_DATATYPE_X509_REQ:
				// objClass = CKO_DATA;
				// func = i2d_X509_REQ;
				strncat(myLabel, "'s Request", sizeof(myLabel) - 1);
				break;
			case PKI_DATATYPE_X509_CA:
				idx = (CK_ULONG) 
					HSM_PKCS11_X509_CERT_get_template ( 
						templ, x, myLabel, (int) strlen(myLabel),
						url->path, path_len );
				break;
			case PKI_DATATYPE_X509_TRUSTED:
				idx = (CK_ULONG) 
					HSM_PKCS11_X509_CERT_get_template ( 
						templ, x, 
						myLabel, (int) strlen(myLabel),
						url->path, path_len );
				break;
			case PKI_DATATYPE_X509_OTHER:
				idx = (CK_ULONG) 
					HSM_PKCS11_X509_CERT_get_template ( 
						templ, x, 
						myLabel, (int) strlen(myLabel),
						url->path, path_len );
				break;
			case PKI_DATATYPE_SECRET_KEY:
				// objClass = CKO_SECRET_KEY;
				// func = NULL;
				break;
			case PKI_DATATYPE_X509_PKCS7:
			case PKI_DATATYPE_X509_PKCS12:
			case PKI_DATATYPE_CRED:
			default:
				// objClass = CKO_DATA;
				// func = NULL;
				break;
		}

		if( ret == 0 ) {
			PKI_log_debug ("ERROR, can not get obj template!");
			return ( PKI_ERR );
		}

		if(( obj = HSM_PKCS11_create_obj( &lib->session, templ, 
						(int) idx, lib)) == NULL) {
			PKI_log_debug("HSM_PKCS11_STACK_add_url()::Object "
						"Create Failed!");
			HSM_PKCS11_clean_template ( templ, (int) idx );
			return ( PKI_ERR );
		} else {
			PKI_log_debug("HSM_PKCS11_STACK_add_url()::Object "
					"create successful (%p)", obj );
		}

		/* Let's clean the memory associated with the template */
		HSM_PKCS11_clean_template ( templ, (int) idx );

		/* Let's fix the Object ID */
		if( url->path ) {
			BIGNUM *id_num = NULL;
			unsigned char *tmp_s = NULL;
			int id_num_len = 0;

			if((BN_hex2bn(&id_num, url->path )) == 0 ) {
				PKI_log_debug("ERROR, can not convert %s "
						"to BIGNUM", url->path );
			} else {
				idx = 0;
				if((id_num_len = BN_num_bytes(id_num)) > 0 ) {
					tmp_s = PKI_Malloc((size_t) id_num_len);
					BN_bn2bin( id_num, tmp_s );

					HSM_PKCS11_save_attr_sn ( obj, CKA_ID,
						(char *) tmp_s, id_num_len, 
							&lib->session, lib );
					if( tmp_s ) PKI_Free ( tmp_s );
				}
			}

			if( id_num ) BN_free ( id_num );

		} else if ( x->type == PKI_DATATYPE_X509_CERT ) {
			CK_OBJECT_HANDLE *pKey = NULL;
			char *key_id = NULL;
			int key_id_len = 0;

			if((pKey = HSM_PKCS11_X509_CERT_find_private_key (
				(PKI_X509_CERT *)x, &lib->session, lib )) 
								== NULL ) {
				/* Nothing more to do - let's go to the
				 * next object */
				PKI_Free ( obj );
				continue;
			}

			if((key_id_len = HSM_PKCS11_get_attr_sn( pKey, 
				&lib->session, CKA_ID, &key_id, lib)) > 0) {
				HSM_PKCS11_save_attr_sn( obj, CKA_ID,
					key_id, key_id_len, &lib->session,lib);
			}
		}

		/* Let's free the memory associated to the obj */
		PKI_Free ( obj );

	}

	return ( PKI_OK );
}

int HSM_PKCS11_KEYPAIR_STACK_add_url ( PKI_X509_STACK *sk, URL *url, 
						PKI_CRED *cred, HSM *hsm ) {

	int i = 0;

	if( !sk ) return ( PKI_ERR );

	for( i = 0; i < PKI_STACK_elements( sk ); i++ ) {
		PKI_X509_KEYPAIR *pk = NULL;

		if(( pk = (PKI_X509_KEYPAIR *) PKI_STACK_get_num(sk, i))==NULL){
			return( PKI_ERR );
		}
		if(HSM_PKCS11_KEYPAIR_add_url(pk, url, cred, hsm) == PKI_ERR) {
			return ( PKI_ERR );
		}
	}

	return ( PKI_OK );
};

int HSM_PKCS11_KEYPAIR_add_url ( PKI_X509_KEYPAIR *x_key, URL *url, 
					PKI_CRED *cred, HSM *hsm ) {

	PKI_X509_KEYPAIR_VALUE *pk = NULL;
	RSA *rsa = NULL;
	int n = 0;

	CK_ATTRIBUTE templ[32];
	CK_OBJECT_HANDLE *obj = NULL;

	PKCS11_HANDLER *lib = NULL;

        BIGNUM *id_num = NULL;

        char *id     = NULL;
        int   id_len = 8;

	char *label = NULL;

	if( !x_key || !x_key->value ) return PKI_ERR;

	pk = x_key->value;

	if( !pk || ((rsa = EVP_PKEY_get1_RSA((EVP_PKEY *) pk)) == NULL) ) {
		return ( PKI_ERR );
	}

	/* We need a valid driver */
	if( !hsm ) {
		PKI_log_debug ( "HSM_PKCS11_KEYPAIR_add_url()::ERROR, no "
			"hsm driver provided!");
		return ( PKI_ERR );
	}

	if ((lib = _hsm_get_pkcs11_handler ( hsm )) == NULL ) {
		PKI_log_debug ("HSM_PKCS11_KEYPAIR_add_url()::No handler");
		return ( PKI_ERR );
	}

	if( url->proto != URI_PROTO_ID ) {
		/* The PKCS11 driver can load only id:// keypairs! */
		PKI_log_debug ("HSM_PKCS11_KEYPAIR_add_url()::Wrong protocol!");
		return ( PKI_ERR );
	}

	/* We need an R/W session for creating objects on Token */
	if( HSM_PKCS11_session_new( lib->slot_id, &lib->session, 
			CKF_SERIAL_SESSION | CKF_RW_SESSION, lib ) != PKI_OK ) {
		return ( PKI_ERR );
	}

	/* Login into the device - do nothing if we are already logged in */
	if(( HSM_PKCS11_login ( hsm, cred )) == PKI_ERR ) {
		PKI_log_debug("HSM_PKCS11_KEYPAIR_put_url()::ERROR, can not "
					"login to device!");
		return ( PKI_ERR );
	}

	/* Check for the Label */
	if ( (url->addr) && (strlen(url->addr) > 0) ) {
		label = url->addr;
	}

	/* Check for the ID */
	if ( (url->path) && (strlen(url->path) > 0) ) {
                if((BN_hex2bn(&id_num, url->path )) == 0 ) {
                        PKI_log_debug("ERROR, can not convert %s to BIGNUM",
                                                url->path );
			goto err;
                }
                if((id_len = BN_num_bytes(id_num)) < 0 ) {
			goto err;
                }
                id = PKI_Malloc ( (size_t ) id_len );
                BN_bn2bin( id_num, (unsigned char *) id );
        } else {
                id_len = 10;
                if((id = PKI_Malloc ( (size_t) id_len )) == NULL ) {
			PKI_log_err ("Memory Error");
			goto err;
                }

                if( RAND_bytes( (unsigned char *) id, id_len) == 0 ) {
                        PKI_log_debug("ERROR, can not generate RAND bytes!");
			goto err;
                }
        }

	/* Now set the template for the Private Key */
	n = 0;
	HSM_PKCS11_set_attr_int( CKA_CLASS, CKO_PRIVATE_KEY, &templ[n++]);
	HSM_PKCS11_set_attr_int( CKA_KEY_TYPE, CKK_RSA, &templ[n++]);
	HSM_PKCS11_set_attr_bool( CKA_TOKEN, CK_TRUE, &templ[n++]);
	HSM_PKCS11_set_attr_bool( CKA_SENSITIVE, CK_TRUE, &templ[n++]);
	HSM_PKCS11_set_attr_bool( CKA_PRIVATE, CK_TRUE, &templ[n++]);

	HSM_PKCS11_set_attr_bool( CKA_UNWRAP, CK_TRUE, &templ[n++]);
	HSM_PKCS11_set_attr_bool( CKA_DECRYPT, CK_TRUE, &templ[n++]);
	HSM_PKCS11_set_attr_bool( CKA_SIGN, CK_TRUE, &templ[n++]);
	HSM_PKCS11_set_attr_bool( CKA_SIGN_RECOVER, CK_TRUE, &templ[n++]);

#if OPENSSL_VERSION_NUMBER < 0x1010000fL
	HSM_PKCS11_set_attr_bn(CKA_MODULUS, rsa->n, &templ[n++]);
	HSM_PKCS11_set_attr_bn(CKA_PUBLIC_EXPONENT, rsa->e, &templ[n++]);
	HSM_PKCS11_set_attr_bn(CKA_PRIVATE_EXPONENT, rsa->d, &templ[n++]);
	HSM_PKCS11_set_attr_bn(CKA_PRIME_1, rsa->p, &templ[n++]);
	HSM_PKCS11_set_attr_bn(CKA_PRIME_2, rsa->q, &templ[n++]);
	HSM_PKCS11_set_attr_bn(CKA_EXPONENT_1, rsa->dmp1, &templ[n++]);
	HSM_PKCS11_set_attr_bn(CKA_EXPONENT_2, rsa->dmq1, &templ[n++]);
	HSM_PKCS11_set_attr_bn(CKA_COEFFICIENT, rsa->iqmp, &templ[n++]);
#else
	const BIGNUM * n_bn;
	const BIGNUM * e_bn;
	const BIGNUM * d_bn;

	const BIGNUM * p_bn;
	const BIGNUM * q_bn;
	const BIGNUM * dmp1_bn;
	const BIGNUM * dmq1_bn;
	const BIGNUM * iqmp_bn;

	// Gets the References to the required internal attributes
	RSA_get0_key(rsa, &n_bn, &e_bn, &d_bn);
	RSA_get0_factors(rsa, &p_bn, &q_bn);
	RSA_get0_crt_params(rsa, &dmp1_bn, &dmq1_bn, &iqmp_bn);

	// Sets the attributes
	HSM_PKCS11_set_attr_bn(CKA_MODULUS, n_bn, &templ[n++]);
	HSM_PKCS11_set_attr_bn(CKA_PUBLIC_EXPONENT, e_bn, &templ[n++]);
	HSM_PKCS11_set_attr_bn(CKA_PRIVATE_EXPONENT, d_bn, &templ[n++]);
	HSM_PKCS11_set_attr_bn(CKA_PRIME_1, p_bn, &templ[n++]);
	HSM_PKCS11_set_attr_bn(CKA_PRIME_2, q_bn, &templ[n++]);
	HSM_PKCS11_set_attr_bn(CKA_EXPONENT_1, dmp1_bn, &templ[n++]);
	HSM_PKCS11_set_attr_bn(CKA_EXPONENT_2, dmq1_bn, &templ[n++]);
	HSM_PKCS11_set_attr_bn(CKA_COEFFICIENT, iqmp_bn, &templ[n++]);
#endif

	HSM_PKCS11_set_attr_bool( CKA_EXTRACTABLE, CK_FALSE, &templ[n++]);
	HSM_PKCS11_set_attr_bool( CKA_MODIFIABLE, CK_TRUE, &templ[n++]);
	HSM_PKCS11_set_attr_bool( CKA_DERIVE, CK_FALSE, &templ[n++]);

	if ( label != NULL ) {
		HSM_PKCS11_set_attr_sn(CKA_LABEL, label, 
					strlen(label), &templ[n++]);
	}

	if ( id_len > 0 ) {
		HSM_PKCS11_set_attr_sn(CKA_ID, id, (size_t)id_len, &templ[n++]);
	}

	if((obj = HSM_PKCS11_create_obj( &lib->session, templ, n, lib))==NULL) {
		PKI_log_debug("HSM_PKCS11_store_pub_key()::Object Create "
								"Failed!");
		goto err;
	}

	HSM_PKCS11_clean_template ( templ, n );

	/* This is the template for the Public Key */
	n = 0;
	HSM_PKCS11_set_attr_int( CKA_CLASS, CKO_PUBLIC_KEY, &templ[n++]);
	HSM_PKCS11_set_attr_int( CKA_KEY_TYPE, CKK_RSA, &templ[n++]);

	HSM_PKCS11_set_attr_bool( CKA_TOKEN, CK_TRUE, &templ[n++]);
	HSM_PKCS11_set_attr_bool( CKA_ENCRYPT, CK_TRUE, &templ[n++]);
	HSM_PKCS11_set_attr_bool( CKA_VERIFY, CK_TRUE, &templ[n++]);
	HSM_PKCS11_set_attr_bool( CKA_WRAP, CK_TRUE, &templ[n++]);

#if OPENSSL_VERSION_NUMBER < 0x1010000fL
	HSM_PKCS11_set_attr_bn(CKA_MODULUS, rsa->n, &templ[n++]);
	HSM_PKCS11_set_attr_bn(CKA_PUBLIC_EXPONENT, rsa->e, &templ[n++]);
#else
	HSM_PKCS11_set_attr_bn(CKA_MODULUS, n_bn, &templ[n++]);
	HSM_PKCS11_set_attr_bn(CKA_PUBLIC_EXPONENT, e_bn, &templ[n++]);
#endif

	if (id_len > 0) HSM_PKCS11_set_attr_sn(CKA_ID, id, 
						(size_t)id_len, &templ[n++]);

	if ( label != NULL ) HSM_PKCS11_set_attr_sn(CKA_LABEL, label, 
					strlen(label), &templ[n++]);

	if((obj = HSM_PKCS11_create_obj( &lib->session, templ, n, lib))==NULL) {
		PKI_log_debug("HSM_PKCS11_store_pub_key()::Object Create "
								"Failed!");
		goto err;
	}

	HSM_PKCS11_clean_template ( templ, n );

	if ( id_num ) BN_free ( id_num );
	if ( id ) PKI_Free ( id );

	return ( PKI_OK );

err:
	if ( id_num ) BN_free ( id_num );
	if ( id ) PKI_Free ( id );

	if ( n > 0 ) HSM_PKCS11_clean_template ( templ, n );

	return PKI_ERR;
}

/* ------------------------ get Template(s) functions --------------------- */
int HSM_PKCS11_X509_CERT_get_template (CK_ATTRIBUTE *templ, PKI_X509_CERT *x,
						char *label, int label_len,
						char *id, int id_len ) {

	int     idx = 0;
	int	len = 0;
	PKI_MEM *mem = NULL;
	unsigned char * value = NULL;

	if( !templ || !x || !x->value ) return ( PKI_ERR );

	idx = 0;
	HSM_PKCS11_set_attr_int( CKA_CLASS, CKO_CERTIFICATE, &templ[idx++]);
	HSM_PKCS11_set_attr_int( CKA_CERTIFICATE_TYPE, CKC_X_509, 
							&templ[idx++]); 
	HSM_PKCS11_set_attr_bool( CKA_TOKEN, CK_TRUE, &templ[idx++]);

	if ( label ) {
		HSM_PKCS11_set_attr_sn ( CKA_LABEL, label, strlen(label), 
							&templ[idx++] );
	}

	if((len = _get_der ( x->value, PKI_DATATYPE_X509_CERT, 
				PKI_X509_DATA_SUBJECT, &value )) > 0 ) {
		if( value ) {
			HSM_PKCS11_set_attr_sn( CKA_SUBJECT,
				(char *) value, (size_t) len, &templ[idx++]); 
			PKI_Free ( value );
			value = NULL;
		} else {
			PKI_log_debug("ERROR, can not get the cert Subject!");
			HSM_PKCS11_clean_template( templ, idx );
			return ( 0 );
		}
	}

	if( label ) {
		HSM_PKCS11_set_attr_sn ( CKA_ID, label, (size_t) label_len, 
							&templ[idx++] );
	}

	value = NULL;
	if ( ( mem = PKI_X509_put_mem(x, PKI_DATA_FORMAT_ASN1, 
					NULL, NULL )) != NULL) {
		// if ( (len = i2d_X509( x->value, &value )) > 0 ) {
		//	if( value ) {
		HSM_PKCS11_set_attr_sn(CKA_VALUE, (char *) mem->data, 
				(size_t) mem->size, &templ[idx++]);
		PKI_MEM_free ( mem );
	} else {
		PKI_log_debug("ERROR, can not convert cert to DER!");
       		HSM_PKCS11_clean_template ( templ, idx );
		return ( PKI_ERR );
	}

	return ( idx );
}

CK_OBJECT_HANDLE * HSM_PKCS11_X509_CERT_find_private_key ( PKI_X509_CERT *x,
			CK_SESSION_HANDLE *hSession, PKCS11_HANDLER *lib ) {

	const PKI_X509_KEYPAIR_VALUE *pk = NULL;

	CK_ATTRIBUTE templ[32];
	CK_OBJECT_HANDLE *ret = NULL;

	int idx = 0;
	int key_type;

	if( !x || !x->value || !hSession || !lib || !lib->callbacks )
		return ( NULL );

	if((pk = PKI_X509_CERT_get_data( x, PKI_X509_DATA_PUBKEY )) 
							== NULL ) {
		/* No key - we can not find the private one! */
		return ( NULL );
	}

	/* Let's create the template for searching the Key */
	idx = 0;
	HSM_PKCS11_set_attr_int( CKA_CLASS, CKO_PRIVATE_KEY, &templ[idx++]);

#if OPENSSL_VERSION_NUMBER < 0x1010000fL
	key_type = EVP_PKEY_type ( ((EVP_PKEY*)pk)->type );
#else
	key_type = EVP_PKEY_type(EVP_PKEY_id(pk));
#endif

	if (key_type == EVP_PKEY_RSA)
	{
		PKI_RSA_KEY * rsa = NULL;

		// Set Key Type
		HSM_PKCS11_set_attr_int(CKA_KEY_TYPE, CKK_RSA,&templ[idx++]);

		// Gets the reference to the RSA key
		if ((rsa = EVP_PKEY_get1_RSA((EVP_PKEY *)pk)) == NULL) goto err;

#if OPENSSL_VERSION_NUMBER < 0x1010000fL

		// Sets the parameters in the template
		HSM_PKCS11_set_attr_bn(CKA_MODULUS, rsa->n, &templ[idx++]);
		HSM_PKCS11_set_attr_bn(CKA_PUBLIC_EXPONENT, rsa->e, 
							&templ[idx++]);
#else
		const BIGNUM * n_bn;
		const BIGNUM * e_bn;
		const BIGNUM * d_bn;

		// Gets the RSA public parameters
		RSA_get0_key(rsa, &n_bn, &e_bn, &d_bn);

		// Sets the parameters in the template
		HSM_PKCS11_set_attr_bn(CKA_MODULUS, n_bn, &templ[idx++]);
		HSM_PKCS11_set_attr_bn(CKA_PUBLIC_EXPONENT, e_bn, &templ[idx++]);
#endif
		// Free the memory from the get1 operation
		if (rsa) RSA_free(rsa);

	} 
	else if ( key_type == EVP_PKEY_DSA )
	{
		// PKI_DSA_KEY *dsa = NULL;
		// dsa = EVP_PKEY_get1_DSA ( (EVP_PKEY *) pk );
		PKI_log_debug ( "DEBUG::DSA Code Missing (%s:%d)!", __FILE__, __LINE__ );
#ifdef ENABLE_ECDSA
	} 
	else if ( key_type == EVP_PKEY_EC )
	{
		// PKI_EC_KEY *ecdsa = NULL;
		// ecdsa = EVP_PKEY_get1_EC_KEY ( (EVP_PKEY *) pk );
		PKI_log_debug ("DEBUG::ECDSA Code Missing (%s:%d)!",
							__FILE__, __LINE__ );
#endif
	} 
	else
	{
		PKI_log_debug ("%s:%d::Key format unknown", __FILE__, __LINE__);
		goto err;
	}

	ret = HSM_PKCS11_get_obj ( templ, idx, lib, &lib->session );

	HSM_PKCS11_clean_template( templ, idx );

	return ( ret );
err:
	HSM_PKCS11_clean_template( templ, idx );
	return ( NULL );
}

