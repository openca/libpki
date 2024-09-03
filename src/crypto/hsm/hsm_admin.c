/* HSM Object Management Functions */

#include <libpki/crypto/hsm/hsm_admin.h>

// Small Hack - taps into OpenSSL internals.. needed for setting the right
// algorithm for signing

#ifdef EVP_MD_FLAG_PKEY_METHOD_SIGNATURE
# define ENABLE_AMETH	1
#endif

#ifdef ENABLE_AMETH
typedef struct my_meth_st {
  int pkey_id;
  int pkey_base_id;
  unsigned long pkey_flags;
  char *pem_str;
  char *info;
} LIBPKI_METH;
#endif

/* --------------------------- Static function(s) ------------------------- */

/*
static int __set_algIdentifier (PKI_X509_ALGOR_VALUE   * alg, 
	                            const PKI_DIGEST_ALG   * digest,
	                            const PKI_X509_KEYPAIR * key) {

	PKI_X509_KEYPAIR_VALUE *pkey = NULL;
	  // KeyPair Pointer

	int def_nid;

	int pkey_type = 0;
	int param_type = V_ASN1_UNDEF;
	  // Parameter Type for Signature

	PKI_DIGEST_ALG * md = NULL;
	  // Digest to use

	EVP_MD_CTX *ctx = NULL;
	EVP_PKEY_CTX *pkctx = NULL;
	  // EVP_PKEY_CTX for signing

	// Input Checks
	if (!key || !key->value || !digest || !alg ) 
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// Gets the KeyPair Pointer from the X509 structure
	pkey = key->value;

    if (EVP_PKEY_get_default_digest_nid(pkey, &def_nid) == 2
            && def_nid == NID_undef) {
        // The signing algorithm requires there to be no digest
        md = NULL;
    }

    if ((ctx = EVP_MD_CTX_new()) == NULL) {
		PKI_log_err("Cannot Allocate Digest Context");
        return 0;
	}

    if (!EVP_MD_CTX_init(ctx) || !EVP_DigestSignInit(ctx, &pkctx, md, NULL, pkey)) {
    	PKI_log_err("Cannot Initialize DigestSignInit");
        return 0;
    }

    pkey_type = EVP_MD_CTX_type(ctx);
    PKI_log_err("DEBUG: pkey_type (new) = %d (%s)",
    	pkey_type, PKI_ALGOR_ID_txt(pkey_type));

    
    // if (EVP_PKEY_get_default_digest_nid(pkey, &def_nid) == 2
    // 		&& def_nid == NID_undef) {
    //
    //  // The signing algorithm requires there to be no digest
    //    digest = NULL;
    //
    //	    PKI_log_err("DIGEST ALGORITHM => %p", digest);
    // } else {
    //      PKI_log_err("DIGEST ALGORITHM => %s", 
    //    	PKI_DIGEST_ALG_get_parsed(digest));
    // }

	// Gets the Signature Algorithm
	pkey_type = EVP_MD_pkey_type(digest);
	PKI_log_err("DEBUG: pkey_type (old) = %d", pkey_type);

#ifdef ENABLE_AMETH

	struct my_meth_st *ameth     = NULL;
	  // Pointer to the aMeth structure

	// Gets the Reference to the Key's Method
	if ((ameth = (struct my_meth_st *) pkey->ameth) == NULL)
		return PKI_ERROR(PKI_ERR_POINTER_NULL, "Missing aMeth pointer.");

	// Gets the right parameter
	if (ameth->pkey_flags & ASN1_PKEY_SIGPARAM_NULL) param_type = V_ASN1_NULL;
	else param_type = V_ASN1_UNDEF;

#else // Else for aMeth

	// Special Case for RFC 2459 (Omit Parameters)
	if (pkey_type == PKI_ALGOR_DSA_SHA1) param_type = V_ASN1_NULL;
	else param_type = V_ASN1_UNDEF;

	if (alg->parameter) ASN1_TYPE_free(alg->parameter);
	alg->parameter = NULL;

#endif // End of aMeth

	PKI_log_err("Set Algorithm: pkey_type = %d (%s)",
		pkey_type, PKI_ALGOR_ID_txt(pkey_type));

	// Sets the Algorithms details
	if (!X509_ALGOR_set0(alg, OBJ_nid2obj(pkey_type), param_type, NULL))
		return PKI_ERROR(PKI_ERR_ALGOR_SET, "Cannot set the algorithm");

	// All Done
	return PKI_OK;

}
*/


/*! \brief Returns the errno from the crypto layer */

unsigned long HSM_get_errno (const HSM *hsm )
{
	const HSM *my_hsm = NULL;

	if (!hsm) my_hsm = (HSM *) HSM_OPENSSL_get_default();
	else my_hsm = hsm;

	if ( my_hsm && my_hsm->callbacks && my_hsm->callbacks->get_errno)
	{
		return my_hsm->callbacks->get_errno();
	}

	return 0;
}

/*! \brief Returns the description of the passed error number from the
 *         crypto layer */

char *HSM_get_errdesc ( unsigned long err, const HSM *hsm )
{
	const HSM *my_hsm = NULL;

	// If no hsm was provided, let's get the default one
	if (!hsm) my_hsm = (HSM *) HSM_OPENSSL_get_default();
	else my_hsm = hsm;
	
	// If no error number was provided, let's get the latest
	if (err == 0) err = HSM_get_errno(my_hsm);

	if (my_hsm && my_hsm->callbacks && my_hsm->callbacks->get_errdesc)
	{
		return my_hsm->callbacks->get_errdesc(err, NULL, 0);
	}

	return NULL;
}

/*! \brief Returns the default HSM structure (software)
 *
 * The returned HSM * points to a static structure that does not need
 * to be freed.
 */
 
const HSM *HSM_get_default( void ) {
	return HSM_OPENSSL_get_default();
}

/*! \brief Allocates a new HSM structure
 *
 * Allocates a new HSM structure and initialize the callbacks functions.
 * The driver is the crypto driver to be used (e.g., openssl or kmf),
 * while the name is the name of the HSM (e.g., LunaCA3)
 */

HSM *HSM_new( const char * const dir,
			  const char * const name ) {

	HSM  * hsm   = NULL;
	char * url_s = NULL;
	char * buff  = NULL;

	PKI_CONFIG *conf = NULL;
	char *type = NULL;

	PKI_init_all();

	if( !name ) {
		/* If no name is passed, we generate a new software token */
		return HSM_OPENSSL_new( NULL );
	}

	if((url_s = PKI_CONFIG_find_all( dir, name, PKI_DEFAULT_HSM_DIR )) 
								== NULL ) {
		PKI_log_debug( "Can not find config file (%s/%s)\n", dir, name);
		return (NULL);
	}

	if((conf = PKI_CONFIG_load( url_s )) == NULL ) {
		PKI_log_debug( "Can not load config from %s", url_s );
		goto err;
	}

	if((buff = PKI_Malloc ( BUFF_MAX_SIZE )) == NULL ) {
		goto err;
	}

	/* Let's generate the right searching string with the namespace
	   prefix */
	if((type = PKI_CONFIG_get_value ( conf, "/hsm/type")) == NULL ) {
		/* No type in the config! */
		PKI_log_debug("ERROR, No HSM type in the config!");
		type = strdup("software");
	}

	if( strcmp_nocase(type,"software") == 0 ) {
		if((hsm = HSM_OPENSSL_new( conf )) == NULL ) {
			PKI_log_debug("ERROR, Can not generate software HSM object!");
		} else {
			hsm->type = HSM_TYPE_SOFTWARE;
		}
#ifdef HAVE_ENGINE
	} else if( strcmp_nocase(type,"engine") == 0 ) {
		if((hsm = HSM_ENGINE_new( conf )) == NULL ) {
			PKI_log_debug("ERROR, Can not generate engine HSM object!");
		} else {
			hsm->type = HSM_TYPE_ENGINE;
		}
#endif
	} else if( strcmp_nocase(type,"pkcs11") == 0 ) {
		if((hsm = HSM_PKCS11_new( conf )) == NULL ) {
			PKI_log_debug("ERROR, Can not generate engine HSM object!");
		} else {
			hsm->type = HSM_TYPE_PKCS11;
		}
#ifdef ENABLE_KMF
	} else if( strcmp_nocase(type,"kmf") == 0 ) {
		if((hsm = HSM_KMF_new( conf )) == NULL ) {
			PKI_log_debug("ERROR, Can not generate kmf HSM object!\n");
		} else {
			hsm->type = HSM_TYPE_KMF;
		}
#endif
	} else {
		PKI_log_debug( "Unknown HSM type (%s)", type );
		goto err;
	}

	if ( ( hsm != NULL ) && (HSM_init ( hsm ) != PKI_OK) ) {
		goto err;
	}

	// Let' see if we can enforce the FIPS mode (optional, therefore
	// errors are not fatal if PKI_is_fips_mode return PKI_ERR)
	if (PKI_is_fips_mode() == PKI_OK)
	{
			if (HSM_set_fips_mode(hsm, 1) == PKI_OK)
			{
				PKI_log_debug("HSM created in FIPS mode");
			}
			else
			{
				PKI_log_err("Can not create HSM in FIPS mode");
				goto err;
			}
	}
	else
	{
		PKI_log_debug("HSM created in non-FIPS mode");
	}

	// Free memory
	if (type) PKI_Free(type);
	if (conf) PKI_CONFIG_free(conf);
	if (url_s) PKI_Free(url_s);

	// Returns the value
	return (hsm);

err:

	// Free used memory
	if (conf) PKI_CONFIG_free(conf);
	if (url_s) PKI_Free(url_s);
	if (hsm) HSM_free(hsm);
	if (type) PKI_Free(type);

	// Returns a NULL pointer
	return NULL;
}

/*! \brief Allocates a new HSM structure and initializes it in FIPS mode
 *
 * Allocates a new HSM structure and initialize the callbacks functions
 * in FIPS mode. The driver is the crypto driver to be used (e.g., openssl
 * or kmf), while the name is the name of the HSM (e.g., LunaCA3)
 *
 * If the HSM does not support FIPS mode or other errors occur, this function
 * returns NULL
 */

HSM *HSM_new_fips(const char * const dir,
				  const char * const name) {
	HSM *ret = NULL;

	// Let's invoke the normal initialization
	ret = HSM_new(dir, name);
	if (!ret) return NULL;

	// Checks if the HSM is operating in FIPS mode
	if (PKI_is_fips_mode() == PKI_OK && HSM_is_fips_mode(ret) == PKI_ERR)
	{
		// Since this init requires FIPS mode, let's return an error
		PKI_log_err("Can not create HSM in FIPS mode");
		HSM_free(ret);
		return NULL;
	}

	// Return the HSM
	return ret;
}

int HSM_free ( HSM *hsm ) {

	if( !hsm ) return (PKI_ERR);

	if( hsm && hsm->callbacks && hsm->callbacks->free )
	{
		hsm->callbacks->free ( (void *) hsm, hsm->config );
	}
	else
	{
		/* Error! The driver should provide a free callback! */
		PKI_log_err("hsm (%s) does not provide a free function!", hsm->description );
		if ( hsm ) PKI_Free ( hsm );

		return (PKI_ERR);
	}

	return (PKI_OK);
}

/* -------------------------- HSM Initialization ----------------------- */


/*!
 * \brief Initializes the HSM
 */
int HSM_init( HSM *hsm ) {

	if( !hsm || !hsm->callbacks ) return (PKI_ERR);

	/* Call the init function provided by the hsm itself */
	if( hsm->callbacks->init )
	{
		return (hsm->callbacks->init(hsm, hsm->config ));
	}
	else
	{
		/* No init function is provided (not needed ??!?!) */
		PKI_log_debug("hsm (%s) does not provide an init "
				"function!\n", hsm->description );
	}

	return(PKI_OK);
}

/*!
 * \brief Initializes the HSM in FIPS mode, returns an error if FIPS
 *        mode is not available for the HSM
 */
int HSM_init_fips (HSM *hsm)
{
	// Let's do the normal initialization
	if (HSM_init(hsm) == PKI_ERR) return PKI_ERR;

	// Now let's set the fips mode
	if (!HSM_set_fips_mode(hsm, 1)) return PKI_ERR;

	return (PKI_OK);
}

/* -------------------------- Access control to HSM ----------------------- */

int HSM_login ( HSM *hsm, PKI_CRED *cred ) {

	if (!hsm) return (PKI_ERR);

	if ( hsm->callbacks->login ) {
		return ( hsm->callbacks->login(hsm, cred ));
	} else {
		/* No login required by the HSM */
		PKI_log_debug("No login function for selected HSM");
	}

	return ( PKI_OK );
}

int HSM_logout ( HSM *hsm ) {

	if (!hsm || !hsm->callbacks ) return (PKI_ERR);

	if ( hsm->callbacks && hsm->callbacks->logout ) {
		return ( hsm->callbacks->logout( hsm ));
	} else {
		/* No login required by the HSM */
		PKI_log_debug("No login function for selected HSM");
	}

	return ( PKI_OK );
}


/* -------------------------- FIPS mode for HSM ----------------------- */

int HSM_set_fips_mode(const HSM *hsm, int k)
{
	if (!hsm) hsm = HSM_get_default();
	if (!hsm) return PKI_ERR;

	if (hsm->callbacks && hsm->callbacks->set_fips_mode)
	{
		return hsm->callbacks->set_fips_mode(hsm, k);
	}
	else
	{
		// If no FIPS mode is available, let's return 0 (false)
		return PKI_ERR;
	}
}

int HSM_is_fips_mode(const HSM *hsm)
{
	if (!hsm) hsm = HSM_get_default();
	if (!hsm) return PKI_ERR;

	if (hsm->callbacks && hsm->callbacks->is_fips_mode)
	{
		return hsm->callbacks->is_fips_mode(hsm);
	}
	else
	{
		return PKI_ERR;
	}
}

/* -------------------------- General Crypto HSM ----------------------- */

int HSM_set_sign_algor ( PKI_X509_ALGOR_VALUE *alg, HSM *hsm ) {

	int ret = PKI_OK;

	// Input Checks
	if (!alg) return PKI_ERROR(PKI_ERR_PARAM_NULL, "No algorithm passed!");

	// Sets the algorithm if it is an hardware token
	if (hsm && hsm->callbacks && hsm->callbacks->sign_algor) {

		// Using the HSM callback
		PKI_log_debug("Setting the signature algorithm for selected HSM");
		ret = hsm->callbacks->sign_algor(hsm, alg);
	}

	// All Done
	return (ret);
}


