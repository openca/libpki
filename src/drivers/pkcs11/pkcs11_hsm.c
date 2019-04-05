/* HSM Object Management Functions */

#include <strings.h>
#include <libpki/pki.h>
#include <libpki/hsm_st.h>
#include <dlfcn.h>

/* Callbacks for Software OpenSSL HSM */
HSM_CALLBACKS pkcs11_hsm_callbacks = {
		/* Errno */
		NULL,
		/* Err Descr */
		NULL,
		/* Init */
		HSM_PKCS11_init,
		/* Free */
		HSM_PKCS11_free,
		/* Login */
		HSM_PKCS11_login,
		/* Logout */
		HSM_PKCS11_logout,
		/* Set Algorithm */
		HSM_PKCS11_sign_algor_set,
		/* Set fips mode */
		HSM_PKCS11_set_fips_mode, 
		/* Fips operation mode */
		HSM_PKCS11_is_fips_mode, 
		/* General Sign */
		NULL, /* HSM_PKCS11_sign, */
		/* General Verify */
		NULL, /* HSM_PKCS11_verify */
		/* Key Generation */
		HSM_PKCS11_KEYPAIR_new,
		/* Free Keypair Function */
		HSM_PKCS11_KEYPAIR_free,
		/* Key Wrapping */
		NULL,
		/* Key Un-Wrapping */
		NULL,
		/* Object stack Get Function */
		HSM_PKCS11_OBJSK_get_url,
		/* Object stack Add (import) Function */
		HSM_PKCS11_OBJSK_add_url,
		/* Object stack Del (remove) Function */
		HSM_PKCS11_OBJSK_del_url,
        /* Get the number of available Slots */
		HSM_PKCS11_SLOT_num,
		/* Get Slot info */
        HSM_PKCS11_SLOT_INFO_get,
		/* Free Slot info */
        HSM_PKCS11_SLOT_INFO_free,
		/* Set the current slot */
		HSM_PKCS11_SLOT_select,
		/* Cleans up the current slot */
		HSM_PKCS11_SLOT_clear,
		/* Gets X509 Callbacks */
		HSM_OPENSSL_X509_get_cb,
};

/* Structure for PKI_TOKEN definition */
HSM pkcs11_hsm = {

	/* Version of the HSM */
	1,

	/* Description of the HSM */
	"PKCS11 Generic HSM",

	/* Manufacturer */
	"OpenCA Project",

	/* Pointer to the HSM config file and parsed structure*/
	NULL, 

	/* One of PKI_HSM_TYPE value */
	HSM_TYPE_PKCS11,

	/* URL for the ID of the driver, this is filled at load time */
	NULL,

	/* Pointer to the driver structure */
	NULL,

	/* Pointer to the session */
	NULL,

	/* Pointer to the credentials */
	NULL,

	/* Callbacks Structures */
	&pkcs11_hsm_callbacks
};


/* ------------- PKCS11 LIBPKI Callbacks Functions --------------------- */

HSM *HSM_PKCS11_new ( PKI_CONFIG *conf ) {

	HSM *hsm = NULL;
	char *cryptoki_id = NULL;

	if ((hsm = (HSM *) PKI_Malloc ( sizeof( HSM ))) == NULL)
		return NULL;

	memcpy( hsm, &pkcs11_hsm, sizeof( HSM));

	/* Not really needed! */
	hsm->callbacks = &pkcs11_hsm_callbacks;

	/* Now we want to load the lib - this should exists, at least!!! */

	/* Let's get the ID for the HSM */
	if((cryptoki_id = PKI_CONFIG_get_value( conf, "/hsm/id" )) == NULL ) {
		PKI_log_debug("ERROR, Can not get ENGINE id from conf!\n");
		goto err;
	}

	if((hsm->id = URL_new ( cryptoki_id )) == NULL ) {
		PKI_log_debug("ERROR, Can not convert id into URI (%s)", 
								cryptoki_id);
		goto err;
	}

	/* cryptoki_id is no more of use, let's free the memory */
	PKI_Free ( cryptoki_id );
	cryptoki_id = NULL;
	
	if((hsm->driver = (void *)
			_pki_pkcs11_load_module( hsm->id->addr, conf))==NULL) {
		PKI_log_err("Can not init PKCS11 lib");
		goto err;
	}

	/* The PKCS11 interface need to be initialized */
	if(( HSM_PKCS11_init ( hsm, conf )) == PKI_ERR ) {
		PKI_log_err("Can not initialize PKCS11 (%s)", hsm->id->addr );
		goto err;
	};

	if((hsm->session = (void *) PKI_Malloc ( sizeof (CK_SESSION_HANDLE)))
								== NULL ) {
		PKI_log_err("HSM_PKCS11_new()::Memory Allocation error for"
				"CK_SESSION_HANDLE");
		goto err;
	}

	return( hsm );

err:

	if (cryptoki_id) PKI_Free(cryptoki_id);
	if (hsm) HSM_PKCS11_free(hsm, conf);

	return NULL;
}

int HSM_PKCS11_free ( HSM *hsm, PKI_CONFIG *conf ) {

	PKCS11_HANDLER *handle = NULL;
	CK_RV rv = CKR_OK;
	int ret = PKI_OK;

	if (hsm == NULL) return (PKI_OK);

	ret = HSM_PKCS11_logout(hsm);
	if (ret != PKI_OK)
	{
		// This is a non-fatal error, so let's just log it and continue
		PKI_log_debug("HSM_PKCS11_free()::Failed to logout from the HSM");
	}

	if((handle = _hsm_get_pkcs11_handler(hsm)) != NULL ) {

		// Check if the Finalize function is available
		if (handle->callbacks && handle->callbacks->C_Finalize)
		{
			rv = handle->callbacks->C_Finalize( NULL_PTR );
			if (!rv) PKI_log_debug("HSM_PKCS11_free()::Failed to call C_Finalize");
			if (rv != CKR_OK) PKI_log_debug("%s()::Failed to call C_Finalize(0X%8.8X)", __PRETTY_FUNCTION__, rv);
		}

		// Close reference to shared lib
		dlclose(handle->sh_lib);

		// Free list of callbacks
		if( handle->callbacks ) {
			// PKI_Free ( handle->callbacks );
		}

		// Free list of mechanisms
		if (handle->mech_list) PKI_Free(handle->mech_list);

	} else {
                PKI_log_debug("HSM_PKCS11_free():: Can't get handler!");
        }

	// Free the Session Info
	if (hsm->session) PKI_Free(hsm->session);

	// Free the ID
	if (hsm->id) URL_free(hsm->id);

	// Free the Driver
	if (hsm->driver) PKI_Free(hsm->driver);

	// Set the mutex to an invalid value
	// NOTE: The call to pthread_mutext_destroy() seem
	// to cause issues on some platforms, need investigation
	// pthread_mutex_destroy ( &handle->pkcs11_mutex );
	// pthread_cond_destroy ( &handle->pkcs11_cond );

	// Free the Memory
	PKI_Free(handle);
	
	// All Done
	return (PKI_OK);
}

int HSM_PKCS11_login(HSM *hsm, PKI_CRED *cred) {

	PKCS11_HANDLER *lib = NULL;
	CK_RV rv;

	unsigned char *pwd = NULL;

	if (!hsm) return ( PKI_OK );

	if ((lib = _hsm_get_pkcs11_handler(hsm)) == NULL )
	{
		PKI_log_debug("HSM_PKCS11_login():: Can't get handler!");
		return PKI_ERR;
	}

	if (lib->logged_in == 1)
	{
		PKI_log_debug ( "HSM_PKCS11_login()::Already Logged in");
		return PKI_OK;
	}

	if (cred == NULL)
	{
		pwd = (unsigned char *) getpass("Please enter your password: ");
	}
	else if ((pwd = (unsigned char *) cred->password) == NULL)
	{
		PKI_log_debug("No Password Provided for Login");
	}

	if (pwd && strlen((const char*) pwd) > 0)
	{
		unsigned char *tmp_s = NULL;
		size_t tmp_s_len = 0;

		tmp_s = pwd;
		tmp_s_len = strlen ( (const char *) pwd );

		rv = lib->callbacks->C_Login(lib->session, CKU_USER, 
					(CK_UTF8CHAR *) tmp_s, tmp_s_len );
	} else {
		char *tmp_s = NULL;
		CK_ULONG tmp_s_len = 0;

		rv = lib->callbacks->C_Login(lib->session, CKU_USER, 
			(CK_UTF8CHAR *) tmp_s, tmp_s_len );
	}

	if ( rv == CKR_USER_ALREADY_LOGGED_IN ) {
		PKI_log_debug( "User Already logged in!");
	} else if( rv == CKR_PIN_INCORRECT ) {
		PKI_log_err ( "ERROR, Pin '%s' Incorrect (0X%8.8X)", pwd, rv);
		return ( PKI_ERR );
	} else if ( rv != CKR_OK ) {
		PKI_log_err ( "ERROR, Unknown (0X%8.8X)", rv);
		return ( PKI_ERR );
	}

	lib->logged_in = 1;

	return PKI_OK;
}

int HSM_PKCS11_logout(HSM *hsm) {

	PKCS11_HANDLER *lib = NULL;
	CK_RV rv;

	if (!hsm) return(PKI_OK);

        if((lib = _hsm_get_pkcs11_handler(hsm)) == NULL ) {
                PKI_log_debug("%s():: Can't get handler!", __PRETTY_FUNCTION__);
                return PKI_ERR;
        }

	rv = lib->callbacks->C_Logout(lib->session);
	if( rv && rv != CKR_SESSION_CLOSED         && 
	          rv != CKR_SESSION_HANDLE_INVALID && 
	          rv != CKR_USER_NOT_LOGGED_IN     &&
		  rv != CKR_CRYPTOKI_NOT_INITIALIZED ) {

		PKI_log_err("%s()::can't logout from current session "
			    "(0x%8.8X)", __PRETTY_FUNCTION__, rv );
		return PKI_ERR;
	} else {
		lib->logged_in = 0;
	}

	return PKI_OK;
}

int HSM_PKCS11_init( HSM *hsm, PKI_CONFIG *conf ) {

	CK_RV rv = CKR_OK;
	PKCS11_HANDLER *handle = NULL;
	CK_INFO info;

	char *tmp = NULL;

	if (hsm == NULL) {
		return PKI_ERROR(PKI_ERR_PARAM_NULL, "Missing Driver argument");
	}

	// Gets the pkcs11 hander
	handle = (PKCS11_HANDLER *) hsm->driver;

	// Initialize MUTEX for non-atomic operations
	if (pthread_mutex_init( &handle->pkcs11_mutex, NULL ) != 0 ) {
		return PKI_ERROR(PKI_ERR_HSM_INIT, "Error while initializing mutex (%s:%d)");
	}

	// Initialize COND variable for non-atomic operations
	if (pthread_cond_init( &handle->pkcs11_cond, NULL ) != 0 ) {
		return PKI_ERROR(PKI_ERR_HSM_INIT, "Error while initializing cond variable");
	}

	rv = (handle->callbacks->C_Initialize)(NULL_PTR);
	if ((rv != CKR_OK) && (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)) {
		return PKI_ERROR(PKI_ERR_HSM_INIT, "C_Initialize failed with 0x%8.8X", rv);
	}

	/* Let's get Info for the Current Loaded Module */
	if((rv = (handle->callbacks->C_GetInfo)(&info)) != CKR_OK ) {
		return PKI_ERROR(PKI_ERR_HSM_INIT, "C_GetInfo failed with 0x%8.8X", rv);
	}
	
	// Sets the Info for the version
	handle->hsm_info.version_major = info.cryptokiVersion.major;
	handle->hsm_info.version_minor = info.cryptokiVersion.minor;

	// Gets the Manufacturer Info
	strncpy(handle->hsm_info.manufacturerID, 
			(const char *) info.manufacturerID, 
				sizeof( handle->hsm_info.manufacturerID) );
	handle->hsm_info.manufacturerID[sizeof(handle->hsm_info.manufacturerID)-1] = '\x0';

	// Gets the HSM description
	strncpy(handle->hsm_info.description, 
			(const char *) info.libraryDescription, 
				sizeof( handle->hsm_info.description) );
	handle->hsm_info.description[sizeof(handle->hsm_info.description)-1] =
			'\x0';

	// Let's remove the ugly spaces at the end of the maufacturerID
	tmp = handle->hsm_info.manufacturerID +
			sizeof(handle->hsm_info.manufacturerID) - 2;

	while( tmp > handle->hsm_info.manufacturerID ) {
		if( tmp[0] == ' ' ) {
			tmp[0] = '\x0';
		} else {
			break;
		}
		tmp--;
	}

	/* Let's remove the ugly spaces at the end of the description */
	tmp = handle->hsm_info.description +
			sizeof(handle->hsm_info.description) - 2;

	while( tmp > handle->hsm_info.description ) {
		if( tmp[0] == ' ' ) {
			tmp[0] = '\x0';
		} else {
			break;
		}
		tmp--;
	}

	// Gets the Library Info
	handle->hsm_info.lib_version_major = info.libraryVersion.major;
	handle->hsm_info.lib_version_minor = info.libraryVersion.minor;

	PKI_log_debug("HSM INFO::Manufacturer %s (v%d.%d)", 
					handle->hsm_info.manufacturerID,
					handle->hsm_info.version_major, 
					handle->hsm_info.version_minor );

	PKI_log_debug("HSM INFO::Library %s (v%d.%d)", 
					handle->hsm_info.description,
					handle->hsm_info.lib_version_major, 
					handle->hsm_info.lib_version_minor );

	return PKI_OK;
}

int HSM_PKCS11_sign_algor_set (HSM *hsm, PKI_ALGOR *algor) {

	PKCS11_HANDLER *lib = NULL;

	PKI_ALGOR_ID id;

	int ret = PKI_OK;

	if (!algor || !hsm) {
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
	}

    if ((id = PKI_ALGOR_get_id(algor)) == PKI_ALGOR_UNKNOWN ) {
    	return PKI_ERROR(PKI_ERR_ALGOR_UNKNOWN, NULL);
    }

	/* Get a VALID PKCS11_HANDLER pointer */
    if((lib = _hsm_get_pkcs11_handler ( hsm )) == NULL ) {
    	return PKI_ERROR(PKI_ERR_HSM_INIT, "Can't get PKCS#11 handler!");
    }

	switch ( id ) {

#ifdef ENABLE_DSA_SHA1
		case PKI_ALGOR_DSA_SHA1:
			if((ret = HSM_PKCS11_check_mechanism ( lib,
					CKM_DSA_SHA1 )) == PKI_OK ) {
				lib->mech_curr = CKM_DSA_SHA1;
			}
			break;
#endif

#ifdef ENABLE_DSA_SHA224
		case PKI_ALGOR_DSA_SHA224:
			if((ret = HSM_PKCS11_check_mechanism ( lib,
					CKM_DSA_SHA224 )) == PKI_OK ) {
				lib->mech_curr = CKM_DSA_SHA224;
			}
			break;
#endif

#ifdef ENABLE_DSA_SHA256
		case PKI_ALGOR_DSA_SHA256:
			if((ret = HSM_PKCS11_check_mechanism ( lib,
					CKM_DSA_SHA256 )) == PKI_OK ) {
				lib->mech_curr = CKM_DSA_SHA256;
			}
			break;
#endif

#ifdef ENABLE_DSA_SHA384
		case PKI_ALGOR_DSA_SHA384:
			if((ret = HSM_PKCS11_check_mechanism ( lib,
					CKM_DSA_SHA384 )) == PKI_OK ) {
				lib->mech_curr = CKM_DSA_SHA384;
			}
			break;
#endif

#ifdef ENABLE_DSA_SHA512
		case PKI_ALGOR_DSA_SHA512:
			if((ret = HSM_PKCS11_check_mechanism ( lib,
					CKM_DSA_SHA512 )) == PKI_OK ) {
				lib->mech_curr = CKM_DSA_SHA512;
			}
			break;
#endif

#ifdef ENABLE_MD5
		case PKI_ALGOR_RSA_MD5:
			if((ret = HSM_PKCS11_check_mechanism( lib,
					CKM_MD5_RSA_PKCS)) == PKI_OK ) {
				lib->mech_curr = CKM_MD5_RSA_PKCS;
			}
			break;
#endif

#ifdef ENABLE_SHA2
		case PKI_ALGOR_RSA_SHA224:
			if((ret = HSM_PKCS11_check_mechanism( lib,
					CKM_SHA224_RSA_PKCS)) == PKI_OK ) {
				lib->mech_curr = CKM_SHA224_RSA_PKCS;
			}
			break;

		case PKI_ALGOR_RSA_SHA256:
			if((ret = HSM_PKCS11_check_mechanism( lib,
					CKM_SHA256_RSA_PKCS)) == PKI_OK ) {
				lib->mech_curr = CKM_SHA256_RSA_PKCS;
			}
			break;

		case PKI_ALGOR_RSA_SHA384:
			if((ret = HSM_PKCS11_check_mechanism( lib,
					CKM_SHA384_RSA_PKCS)) == PKI_OK ) {
				lib->mech_curr = CKM_SHA384_RSA_PKCS;
			}
			break;
		case PKI_ALGOR_RSA_SHA512:
			if((ret = HSM_PKCS11_check_mechanism( lib,
					CKM_SHA512_RSA_PKCS)) == PKI_OK ) {
				lib->mech_curr = CKM_SHA512_RSA_PKCS;
			}
			break;
#endif

#ifdef ENABLE_RSA_RIPEMD128
		case PKI_ALGOR_RSA_RIPEMD128:
			if((ret = HSM_PKCS11_check_mechanism( lib,
					CKM_RIPEMD128_RSA_PKCS)) == PKI_OK ) {
				lib->mech_curr = CKM_RIPEMD128_RSA_PKCS;
			}
			break;
#endif

#ifdef ENABLE_RSA_RIPEMD160
		case PKI_ALGOR_RSA_RIPEMD160:
			if((ret = HSM_PKCS11_check_mechanism( lib,
					CKM_RIPEMD160_RSA_PKCS)) == PKI_OK ) {
				lib->mech_curr = CKM_RIPEMD160_RSA_PKCS;
			}
			break;
#endif

#ifdef ENABLE_ECDSA_SHA1
		case PKI_ALGOR_ECDSA_SHA1:
			if((ret = HSM_PKCS11_check_mechanism ( lib,
						CKM_ECDSA_SHA1)) == PKI_OK ) {
				lib->mech_curr = CKM_ECDSA_SHA1;
			}
			break;
#endif // ENABLE_ECDSA_SHA1

#ifdef ENABLE_SHA_2
		case PKI_ALGOR_ECDSA_SHA224:
			if((ret = HSM_PKCS11_check_mechanism ( lib,
						CKM_ECDSA_SHA224)) == PKI_OK ) {
				lib->mech_curr = CKM_ECDSA_SHA224;
			}
			break;

		case PKI_ALGOR_ECDSA_SHA256:
			if((ret = HSM_PKCS11_check_mechanism ( lib,
						CKM_ECDSA_SHA256)) == PKI_OK ) {
				lib->mech_curr = CKM_ECDSA_SHA256;
			}
			break;

		case PKI_ALGOR_ECDSA_SHA384:
			if((ret = HSM_PKCS11_check_mechanism ( lib,
						CKM_ECDSA_SHA384)) == PKI_OK ) {
				lib->mech_curr = CKM_ECDSA_SHA384;
			}
			break;

		case PKI_ALGOR_ECDSA_SHA512:
			if((ret = HSM_PKCS11_check_mechanism ( lib,
						CKM_ECDSA_SHA512)) == PKI_OK ) {
				lib->mech_curr = CKM_ECDSA_SHA512;
			}
			break;
#endif // ENABLE_SHA_2

		default:
			ret = PKI_ERR;
			break;
	}

	/*
	if( ret == PKI_ERR ) {
		PKI_log_debug("HSM_PKCS11_algor_set():: ERROR :: End "
			"(Algor = %d - ret = %d)", lib->mech_curr, ret );
	}
	*/

	return ( ret );
}

int HSM_PKCS11_set_fips_mode(const HSM *driver, int k)
{
	PKCS11_HANDLER *lib = NULL;
	if (!driver) return PKI_ERR;

	if ((lib = _hsm_get_pkcs11_handler ((HSM *)driver)) == NULL)
	{
		PKI_log_err("HSM_PKCS11_set_fips_mode()::Can't get a valid "
			"PKCS11 handler from driver!");
			return (PKI_ERR);
	}

	PKI_log_debug("PKCS11: set_fips_mode() not implemented, yet.");
	return PKI_ERR;
}

int HSM_PKCS11_is_fips_mode(const HSM *driver)
{
	PKCS11_HANDLER *lib = NULL;
	if (!driver) return PKI_ERR;

	if ((lib = _hsm_get_pkcs11_handler((HSM *)driver)) == NULL)
	{
		PKI_log_err("HSM_PKCS11_set_fips_mode()::Can't get a valid "
			"PKCS11 handler from driver!");
			return (PKI_ERR);
	}
	PKI_log_debug("PKCS11: is_fips_mode() not implemented, yet.");
	return PKI_ERR;
}

/* -------------------------- Sign/Verify Functions ----------------------- */

/*
int HSM_PKCS11_sign (PKI_OBJTYPE type, 
				void *x, 
				void *it_pp, 
				PKI_ALGOR *alg,
				PKI_STRING *bit,
				PKI_X509_KEYPAIR *key, 
				PKI_DIGEST_ALG *digest, 
				HSM *driver ) {

	int ret = 0;
	ASN1_ITEM *it = NULL;

	if( !x || !key ) {
		PKI_log_debug("Missing required param for signature generation "
				"(Software HSM)");

		if( !x ) PKI_log_debug ( "Missing data to sign!");
		if( !key ) PKI_log_debug( "Missing Key to sign with!");

		return ( PKI_ERR );
	}

	if( !digest ) digest = PKI_DIGEST_ALG_SHA1;

	ERR_clear_error();

	switch ( type ) {
		case PKI_OBJTYPE_X509_REQ:
			ret = X509_REQ_sign( (X509_REQ *) x, 
				(EVP_PKEY *) key, (EVP_MD *) digest );
			break;
		case PKI_OBJTYPE_X509_CERT:
			ret = X509_sign( (X509 *) x, (EVP_PKEY *) key, 
				(EVP_MD *) digest );
			break;
		case PKI_OBJTYPE_X509_CRL:
			ret = X509_CRL_sign( (X509_CRL *) x, (EVP_PKEY *) key, 
				(EVP_MD *) digest );
			break;
		case PKI_OBJTYPE_PKCS7:
		case PKI_OBJTYPE_PKCS12:
		case PKI_OBJTYPE_PKI_MSG:
		case PKI_OBJTYPE_SCEP_MSG:
		case PKI_OBJTYPE_CMS_MSG:
			PKI_log_debug("HSM::DRIVER::PKCS11::OBJ sign not "
					"supported for this type, yet!");
			ret = 0;
			break;
		default:
			if( !it_pp || !bit || !alg ) {
				PKI_log_debug("Missing required params to "
					"complete the generic signature");
				return ( PKI_ERR );
			}

			it = (ASN1_ITEM *) it_pp;
			ret = ASN1_item_sign(it, alg, NULL,
				bit, x, (EVP_PKEY *) key, (EVP_MD *) digest );
			break;
	}
			
	if( ret == 0 ) {
		PKI_log_debug("ERROR::Software::sign()::%s", 
				ERR_error_string(ERR_get_error(), NULL));
		return( PKI_ERR );
	}

	PKI_log_debug("Signature successful ( Software HSM )");

	return ( PKI_OK );
}

int HSM_PKCS11_verify ( PKI_OBJTYPE type, void *x, 
				PKI_X509_KEYPAIR *key, HSM *hsm ) {

        int ret = 0;
        EVP_PKEY *pp = NULL;
	X509_ALGOR *alg = NULL;

	void * sig = NULL;
	void * data = NULL;

	ASN1_ITEM *it = NULL;

        if( !x || !key ) {
                PKI_log_debug("PKI_verify() - Missing resp or key!");
                return (PKI_ERR);
        }

        pp = (EVP_PKEY *) key;

        ERR_clear_error();

	switch ( type ) {
		case PKI_OBJTYPE_X509_REQ:
			it = (ASN1_ITEM *) ASN1_ITEM_rptr(X509_REQ_INFO);
			sig = ((X509_REQ *) x)->signature;
			data = ((X509_REQ *) x)->req_info;
			alg = ((X509_REQ *) x)->sig_alg;
			break;
		case PKI_OBJTYPE_X509_CERT:
			it = (ASN1_ITEM *) ASN1_ITEM_rptr(X509_CINF);
			sig = ((X509 *)x)->signature;
			data = ((X509 *)x)->cert_info;
			alg = ((X509 *)x)->sig_alg;
			break;
		case PKI_OBJTYPE_X509_CRL:
			it = (ASN1_ITEM *) ASN1_ITEM_rptr(X509_CRL_INFO);
			sig = ((X509_CRL *)x)->signature;
			data = ((X509_CRL *)x)->crl;
			alg = ((X509_CRL *)x)->sig_alg;
			break;
		case PKI_OBJTYPE_PKI_PRQP_REQ:
			it = (ASN1_ITEM *) ASN1_ITEM_rptr(TBS_REQ_DATA);
			sig = ((PKI_PRQP_REQ *)x)->prqpSignature->signature;
			data = ((PKI_PRQP_REQ *)x)->requestData;
			alg = ((PKI_PRQP_REQ *)x)->prqpSignature->signatureAlgorithm;
			break;
		case PKI_OBJTYPE_PKI_PRQP_RESP:
			it = (ASN1_ITEM *) ASN1_ITEM_rptr(TBS_RESP_DATA);
			sig = ((PKI_PRQP_RESP *)x)->prqpSignature->signature;
			data = ((PKI_PRQP_RESP *)x)->respData;
			alg = ((PKI_PRQP_RESP *)x)->prqpSignature->signatureAlgorithm;
			break;
		case PKI_OBJTYPE_PKCS7:
		case PKI_OBJTYPE_PKCS12:
		case PKI_OBJTYPE_PKI_MSG:
		case PKI_OBJTYPE_SCEP_MSG:
		case PKI_OBJTYPE_CMS_MSG:
			PKI_log_debug("HSM::DRIVER::PKCS11::OBJ verify not "
					"supported for this type, yet!");
			return( PKI_ERR );
			break;
		default:
			return ( PKI_ERR );
	}

	if( !it || !alg || !sig || !data || !pp ) return ( PKI_ERR );

        if(( ret = ASN1_item_verify((const ASN1_ITEM *)it, alg, sig, data, 
							pp )) == 0 ) {

                PKI_log_debug( "PKI_verify() - [%d] ERROR:%s", ret,
                        ERR_error_string(ERR_get_error(), NULL ));

                return ( PKI_ERR );
        }

        PKI_log_debug( "PKI_verify() - OK");

        return ( PKI_OK );

}
*/

/*--------------------------- SLOT Management Functions --------------- */

unsigned long HSM_PKCS11_SLOT_num ( HSM * hsm ) {

	PKCS11_HANDLER *lib = NULL;
	CK_RV rv = CKR_OK;

	CK_ULONG ret = 0;

	PKI_log_debug( "HSM_PKCS11_SLOT_num()::start (%p)", hsm );

	/* Get a VALID PKCS11_HANDLER pointer */
	if((lib = _hsm_get_pkcs11_handler ( hsm )) == NULL ) {
		return ( 0 );
	}
 
	/* Checks that the library implements the callback */
	if( lib->callbacks->C_GetSlotList == NULL ) {
		PKI_log_debug( "HSM_PKCS11_SLOT_num()::no C_GetSlotList" );
		return( 1 );
	}

	/* Get the number of Slots available */
	if((rv = lib->callbacks->C_GetSlotList( (CK_BYTE) 1, 
						NULL, &ret )) != CKR_OK) {
		PKI_log_debug("C_GetSlotList failed with 0%8.8X", rv );
		return( 0 );
	}

	return ( (unsigned long) ret );

}

HSM_SLOT_INFO * HSM_PKCS11_SLOT_INFO_get(unsigned long num, HSM *hsm) {

	PKCS11_HANDLER *lib = NULL;
	CK_RV rv = CKR_OK;

	CK_MECHANISM_TYPE_PTR mech_list = NULL;

	CK_SLOT_INFO info;
	HSM_SLOT_INFO *ret = NULL;

	CK_ULONG slot_num = 0;

	PKI_log_debug("HSM_PKCS11_SLOT_info()::start");

	/* Get a VALID PKCS11_HANDLER pointer */
	if((lib = _hsm_get_pkcs11_handler(hsm)) == NULL ) {
		return ( NULL );
	}
 
	/* Let's get Info for the Current Loaded Module */
	slot_num = (CK_ULONG) num;
	if((rv = lib->callbacks->C_GetSlotInfo(slot_num, &info)) != CKR_OK ) {
		PKI_log_debug("Can not get Info from PKCS11 library" );
		PKI_log_debug("Returned Value is 0x%8.8X (OK is 0x%8.8X)", rv, CKR_OK );
		return ( PKI_ERR );
	};
	
	if((ret = PKI_Malloc ( sizeof( HSM_SLOT_INFO ))) == NULL )
		return ( NULL );

	ret->hw_version_major = info.hardwareVersion.major;
	ret->hw_version_minor = info.hardwareVersion.minor;
	ret->fw_version_major = info.firmwareVersion.major;
	ret->fw_version_minor = info.firmwareVersion.minor;

	_strncpyClip(ret->manufacturerID, (char *) info.manufacturerID, 
			MANUFACTURER_ID_SIZE );
	_strncpyClip(ret->description, (char *) info.slotDescription, 
			DESCRIPTION_SIZE );

	ret->present   = 0;
	ret->removable = 0;
	ret->hardware  = 0;

	if( info.flags & CKF_TOKEN_PRESENT ) ret->present = 1;
	if( info.flags & CKF_REMOVABLE_DEVICE ) ret->removable = 1;
	if( info.flags & CKF_HW_SLOT ) ret->hardware = 1;

	if( ret->present == 0 ) {
		PKI_log_err("HSM SLOT [%ld]::Token not Present!", num);
		goto err;
	}

	if((_hsm_pkcs11_get_token_info(num, &(ret->token_info), 
							lib)) != PKI_OK ) {
		PKI_log_debug("HSM SLOT INFO [%ld]::"
			"Error in getting token information", num);

		return ( ret );
	}

	/* Get the number of Supported Mechanisms */
	/*
	if((rv = lib->callbacks->C_GetSlotInfo( slot_num, &slot_info )) 
								!= CKR_OK ) {
		PKI_log_err ( "HSM SLOT INFO [%d]::Can not get slot details "
					"(C_GetSlotInfo failed with %d)", 
						slot_num, rv );
		goto err;
	}

	if((rv = lib->callbacks->C_GetMechanismList( slot_num, NULL_PTR, 
						&mech_num )) != CKR_OK ) {
		PKI_log_err( "HSM SLOT INFO [%d]::Can not get the number of"
			" algorithms (C_GetMechanismList failed with %d)", 
				slot_num, rv);
		goto err;
	}

	PKI_log_debug("HSM_SLOT_INFO [%d]::Mech Num is %d (rv = %d)",
				slot_num, mech_num, rv );

	if(( mech_list = PKI_Malloc( mech_num * 
				sizeof(CK_MECHANISM_TYPE))) == NULL ) {
		PKI_log_err("HSM SLOT INFO [%d]::Memory allocation!", slot_num);
		goto err;
	}

	rv = lib->callbacks->C_GetMechanismList(slot_num,
					mech_list, &mech_num );
	if( rv != CKR_OK ) {
		PKI_log_debug("C_GetMechanismList::Failed (%d::%d)", 
				slot_num, rv );
		goto err;
	}

	for ( i = 0; i < mech_num ; i++ ) {
		PKI_log_debug("HSM SLOT INFO [%d]:: MECH %d is 0x%8.8X\n", 
			slot_num, i, mech_list[i] );
	}
	*/

	return ( ret );

err:
	PKI_log_debug( "HSM SLOT INFO::CALLED ERROR - Returning NULL" );
	if ( mech_list ) PKI_Free ( mech_list );
	if ( ret ) PKI_Free ( ret );
	return ( NULL );

}

void HSM_PKCS11_SLOT_INFO_free ( HSM_SLOT_INFO *sl_info, HSM *hsm ) {
	if (!sl_info ) return;

	PKI_Free ( sl_info );

	return;
}

int HSM_PKCS11_SLOT_select (unsigned long num, PKI_CRED *cred, HSM *hsm) {

	CK_RV rv = CKR_OK;
	PKCS11_HANDLER *lib = NULL;

	/* Get a VALID PKCS11_HANDLER pointer */
        if((lib = _hsm_get_pkcs11_handler ( hsm )) == NULL ) {
		PKI_log_debug("HSM_PKCS11_SLOT_select()::Can't get a valid "
			"PKCS11 handler from driver!");
                return ( PKI_ERR );
        }

	/* Get a new session */
	if( HSM_PKCS11_session_new( num, &lib->session,
                			CKF_SERIAL_SESSION, lib ) != PKI_OK ) {
		PKI_log_debug("%s()::Can not initiate a new session",
				__PRETTY_FUNCTION__);
                return ( PKI_ERR );
        }

	/* Sets the Slot ID */
	lib->slot_id = num;

	/* Get the Mechanism List */
	if((rv = lib->callbacks->C_GetMechanismList( lib->slot_id, NULL_PTR, 
						&lib->mech_num )) != CKR_OK ) {
		PKI_log_debug("%s()::PKCS11/C_GetMechanismList failed with "
				"0x%8.8X", __PRETTY_FUNCTION__, rv );
		return PKI_ERR;
	}

	if(( lib->mech_list = PKI_Malloc( lib->mech_num * 
				sizeof(CK_MECHANISM_TYPE))) == NULL ) {
		return PKI_ERR_MEMORY_ALLOC;
	}

	rv = lib->callbacks->C_GetMechanismList(lib->slot_id,
						lib->mech_list,
						&lib->mech_num);
	if( rv != CKR_OK ) {
		PKI_log_debug("C_GetMechanismList::Failed (%d::0x%8.8X)", 
				lib->slot_id, rv );
		goto end;
	}

end:
	return ( PKI_OK );
}

int HSM_PKCS11_SLOT_clear (unsigned long slot_id, PKI_CRED *cred, HSM *driver){

	PKCS11_HANDLER *lib = NULL;

	CK_OBJECT_HANDLE hObject;
	CK_ULONG	 ulObjectCount;

	CK_RV rv;

	CK_SESSION_HANDLE *session = NULL;

	if( !driver ) return (PKI_ERR);

	if(( lib = _hsm_get_pkcs11_handler ( driver)) == NULL ) {
		return ( PKI_ERR );
	}

	if( HSM_PKCS11_session_new( slot_id, &lib->session, 
		CKF_SERIAL_SESSION | CKF_RW_SESSION, lib ) != PKI_OK ) {
		return ( PKI_ERR );
	}

	session = &lib->session;

	if ( HSM_PKCS11_login ( driver, cred ) == PKI_ERR )  {
		return ( PKI_ERR );
	}

	/*
	rv = lib->callbacks->C_Login(lib->key, CKU_USER, 
		(CK_UTF8CHAR *) cred->password, 
			cred->password ? strlen(cred->password) : 0);

	if ( rv == CKR_USER_ALREADY_LOGGED_IN ) {
		PKI_log_debug("[Get Info] User Already Logged in");
	} else if ( rv != CKR_OK ) {
		PKI_log_debug("[Get Info] Login Failed with 0x%8.8X", rv );
		return ( PKI_ERR );
	}
	*/

	if((rv = lib->callbacks->C_FindObjectsInit(*session, NULL, 0)) 
								!= CKR_OK ) {
		PKI_log_debug("C_FindObjectsInit::Failed with 0x%8.8X", rv );
		return ( PKI_ERR );
	}

	while ( 1 ) {
		rv = lib->callbacks->C_FindObjects(lib->session, &hObject, 
							1, &ulObjectCount );
		if( rv != CKR_OK || ulObjectCount == 0 ) {
			PKI_log_debug("C_FindObjects::Failed with 0x%8.8X", rv);
			break;
		}

		if((rv = lib->callbacks->C_DestroyObject(lib->session, hObject))
								!= CKR_OK ) {
			PKI_log_debug("HSM_PKCS11_clear()::Can not destroy "
				"object (0x%8.8X)", rv );
			continue;
		}
	}

	if(( rv = lib->callbacks->C_FindObjectsFinal(lib->session)) != CKR_OK){
		PKI_log_debug("HSM_PKCS11_clear()::Can not destroy "
				"object (0x%8.8X)", rv );
	}

	HSM_PKCS11_session_close ( &lib->session, lib );

	return ( PKI_OK );
}

int HSM_PKCS11_SLOT_elements (unsigned long slot_id, PKI_CRED *cred, 
							HSM *driver){

	PKCS11_HANDLER *lib = NULL;

	CK_OBJECT_HANDLE hObject;
	CK_ULONG	 ulObjectCount;

	CK_RV rv;

	CK_SESSION_HANDLE *session = NULL;
	int count = 0;

	if( !driver ) return (PKI_ERR);

	if(( lib = _hsm_get_pkcs11_handler ( driver)) == NULL ) {
		return ( PKI_ERR );
	}

	if( HSM_PKCS11_session_new( slot_id, &lib->session, 
		CKF_SERIAL_SESSION | CKF_RW_SESSION, lib ) != PKI_OK ) {
		return ( PKI_ERR );
	}

	session = &lib->session;

	if ( HSM_PKCS11_login ( driver, cred ) == PKI_ERR )  {
		return ( PKI_ERR );
	}

	if((rv = lib->callbacks->C_FindObjectsInit(*session, NULL, 0)) 
								!= CKR_OK ) {
		PKI_log_debug("C_FindObjectsInit::Failed with 0x%8.8X", rv );
		return ( PKI_ERR );
	}

	while ( 1 ) {
		rv = lib->callbacks->C_FindObjects(lib->session, &hObject, 
							1, &ulObjectCount );
		if( rv != CKR_OK || ulObjectCount == 0 ) {
			PKI_log_debug("C_FindObjects::Failed with 0x%8.8X", rv);
			break;
		}
		count++;
	}

	if(( rv = lib->callbacks->C_FindObjectsFinal(lib->session)) != CKR_OK){
		PKI_log_debug("HSM_PKCS11_clear()::Can not destroy "
				"object (0x%8.8X)", rv );
	}

	HSM_PKCS11_session_close ( &lib->session, lib );

	return ( count );
}
