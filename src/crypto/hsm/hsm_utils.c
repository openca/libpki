/* HSM Object Management Functions */

#include <libpki/crypto/hsm/hsm_utils.h>

/*! \brief Allocates a new HSM structure
 *
 * Allocates a new HSM structure and initialize the callbacks functions.
 * The driver is the crypto driver to be used (e.g., openssl or kmf),
 * while the name is the name of the HSM (e.g., LunaCA3)
 */

HSM * CRYPTO_HSM_new(const char * const dir,
                     const char * const name ) {

    HSM  * hsm   = NULL;
    char * url_s = NULL;
    char * buff  = NULL;

    PKI_CONFIG *conf = NULL;
    char *type = NULL;

    if( !name ) {
        /* If no name is passed, we generate a new software token */
        return CRYPTO_HSM_get_default();
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

void CRYPTO_HSM_free ( HSM *hsm ) {

    if( !hsm ) return (PKI_ERR);

    if (hsm->driver && hsm->admin_callbacks && hsm->admin_callbacks->free) {
        hsm->admin_callbacks->free(hsm->driver);
    }

    PKI_Free(hsm);

    return;
}

/*! \brief Returns the default HSM structure (software)
 *
 * The returned HSM * points to a static structure that does not need
 * to be freed.
 */
 
const HSM *CRYPTO_HSM_get_default( void ) {
    return HSM_OPENSSL_get_default();
}


// /* -------------------------- HSM Initialization ----------------------- */


// /*!
//  * \brief Initializes the HSM
//  */
// int HSM_init( HSM *hsm ) {

// 	if( !hsm || !hsm->callbacks ) return (PKI_ERR);

// 	/* Call the init function provided by the hsm itself */
// 	if( hsm->callbacks->init )
// 	{
// 		return (hsm->callbacks->init(hsm, hsm->config ));
// 	}
// 	else
// 	{
// 		/* No init function is provided (not needed ??!?!) */
// 		PKI_log_debug("hsm (%s) does not provide an init "
// 				"function!\n", hsm->description );
// 	}

// 	return(PKI_OK);
// }

// /*!
//  * \brief Initializes the HSM in FIPS mode, returns an error if FIPS
//  *        mode is not available for the HSM
//  */
// int HSM_init_fips (HSM *hsm)
// {
// 	// Let's do the normal initialization
// 	if (HSM_init(hsm) == PKI_ERR) return PKI_ERR;

// 	// Now let's set the fips mode
// 	if (!HSM_set_fips_mode(hsm, 1)) return PKI_ERR;

// 	return (PKI_OK);
// }

// /* -------------------------- Access control to HSM ----------------------- */

// int HSM_login ( HSM *hsm, PKI_CRED *cred ) {

// 	if (!hsm) return (PKI_ERR);

// 	if ( hsm->callbacks->login ) {
// 		return ( hsm->callbacks->login(hsm, cred ));
// 	} else {
// 		/* No login required by the HSM */
// 		PKI_log_debug("No login function for selected HSM");
// 	}

// 	return ( PKI_OK );
// }

// int HSM_logout ( HSM *hsm ) {

// 	if (!hsm || !hsm->callbacks ) return (PKI_ERR);

// 	if ( hsm->callbacks && hsm->callbacks->logout ) {
// 		return ( hsm->callbacks->logout( hsm ));
// 	} else {
// 		/* No login required by the HSM */
// 		PKI_log_debug("No login function for selected HSM");
// 	}

// 	return ( PKI_OK );
// }


// /* -------------------------- FIPS mode for HSM ----------------------- */

// int HSM_set_fips_mode(const HSM *hsm, int k)
// {
// 	if (!hsm) hsm = HSM_get_default();
// 	if (!hsm) return PKI_ERR;

// 	if (hsm->callbacks && hsm->callbacks->set_fips_mode)
// 	{
// 		return hsm->callbacks->set_fips_mode(hsm, k);
// 	}
// 	else
// 	{
// 		// If no FIPS mode is available, let's return 0 (false)
// 		return PKI_ERR;
// 	}
// }

// int HSM_is_fips_mode(const HSM *hsm)
// {
// 	if (!hsm) hsm = HSM_get_default();
// 	if (!hsm) return PKI_ERR;

// 	if (hsm->callbacks && hsm->callbacks->is_fips_mode)
// 	{
// 		return hsm->callbacks->is_fips_mode(hsm);
// 	}
// 	else
// 	{
// 		return PKI_ERR;
// 	}
// }

// /* -------------------------- General Crypto HSM ----------------------- */

// int HSM_set_sign_algor ( PKI_X509_ALGOR_VALUE *alg, HSM *hsm ) {

// 	int ret = PKI_OK;

// 	// Input Checks
// 	if (!alg) return PKI_ERROR(PKI_ERR_PARAM_NULL, "No algorithm passed!");

// 	// Sets the algorithm if it is an hardware token
// 	if (hsm && hsm->callbacks && hsm->callbacks->sign_algor) {

// 		// Using the HSM callback
// 		PKI_log_debug("Setting the signature algorithm for selected HSM");
// 		ret = hsm->callbacks->sign_algor(hsm, alg);
// 	}

// 	// All Done
// 	return (ret);
// }


