/* TOKEN Object Management Functions */

#include <strings.h>
#include <libpki/pki.h>
#include <sys/types.h>
#include <dirent.h>
#include <libpki/pki_log.h>


// ==========================
// Auxillary Static Functions
// ==========================

static int __check_token_status_range(PKI_TOKEN_STATUS status) {
	switch(status) {
		case PKI_TOKEN_STATUS_OK:
		case PKI_TOKEN_STATUS_INIT_ERR:
		case PKI_TOKEN_STATUS_LOGIN_ERR:
		case PKI_TOKEN_STATUS_KEYPAIR_LOAD:
		case PKI_TOKEN_STATUS_KEYPAIR_CHECK_ERR:
		case PKI_TOKEN_STATUS_KEYPAIR_MISSING_ERR:
		case PKI_TOKEN_STATUS_CERT_MISSING_ERR:
		case PKI_TOKEN_STATUS_CACERT_MISSING_ERR:
		case PKI_TOKEN_STATUS_OTHERCERTS_MISSING_ERR:
		case PKI_TOKEN_STATUS_TRUSTEDCERTS_MISSING_ERR:
		case PKI_TOKEN_STATUS_MEMORY_ERR:
		case PKI_TOKEN_STATUS_UNKNOWN:
		case PKI_TOKEN_STATUS_HSM_ERR:
			// Accepted status
			break;

		default:
			return PKI_ERROR(PKI_ERR_PARAM_RANGE, NULL);
	}
	return PKI_OK;
}

// =========
// Functions
// =========

PKI_CRED *PKI_TOKEN_cred_cb_stdin ( char * prompt ) {

	PKI_CRED *ret = NULL;
	char *pwd = NULL;

	if( !prompt ) {
		prompt = "Please enter Token password: ";
	}

	if((ret = PKI_CRED_new_null()) == NULL ) {
		return ( NULL );
	}

	if((pwd = getpass( prompt )) != NULL ) {
		if( strlen(pwd) > 0 ) ret->password = pwd;
	}

	return ( ret );
}

PKI_CRED *PKI_TOKEN_cred_cb_env ( char * env ) {

	PKI_CRED *ret = NULL;
	char * tmp_pwd = NULL;

	if( !env ) return ( NULL );

	if((ret = PKI_CRED_new_null()) == NULL ) {
		return ( NULL );
	}

	tmp_pwd = getenv( env );
	if( tmp_pwd ) {
		ret->password = strdup( tmp_pwd);
	} else {
		ret->password = strdup( "" );
	}

	ret->username = NULL;

	return ( ret );
}

/*! \brief Returns credentials attached to the token */

const PKI_CRED *PKI_TOKEN_cred_get(const PKI_TOKEN * const tk) {

	if (!tk)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return ( NULL );
	}

	return tk->cred;
}

/*! \brief Retrieves the credentials from the registered callback function */

int PKI_TOKEN_cred_prompt(PKI_TOKEN *tk, char *st) {

	// Input Checks
	if (!tk) { 
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
	}

	// Clears the current credentials
	if (tk->cred) PKI_CRED_free(tk->cred);
	tk->cred = NULL; // Safety

	// If the creds are already set,
	// let's just return it
	if (tk->cred_cb) {
		tk->cred = NULL;
		tk->isCredSet = 1;
	}
	else
	{
		if (!st) st = tk->cred_prompt;
		tk->cred = tk->cred_cb(st);
	}

	// Checks the error condition
	if (!tk->cred) return PKI_ERR;

	// All done.
	return PKI_OK;
}

/*!
 * \brief Create a new PKI_TOKEN structure.
 *
 * Reserves the memory for a new PKI_TOKEN data structure. The returned
 * memory is already zeroize. No token configuration is performed. If
 * you need to configure the token by using a configuration file, please
 * use the PKI_TOKEN_new() function.
 *
 */

PKI_TOKEN *PKI_TOKEN_new_null( void )
{
	PKI_TOKEN *tk = NULL;

	tk = (PKI_TOKEN *) PKI_Malloc (sizeof(PKI_TOKEN));
	if(!tk)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return (NULL);
	}
	
	memset(tk, 0, sizeof(PKI_TOKEN));

	if ((tk->otherCerts = PKI_STACK_X509_CERT_new()) == NULL)
	{
		PKI_ERROR(PKI_ERR_OBJECT_CREATE, NULL);
		PKI_Free( tk );
		return NULL;
	}

	if ((tk->trustedCerts = PKI_STACK_X509_CERT_new()) == NULL)
	{
		PKI_ERROR(PKI_ERR_OBJECT_CREATE, NULL);
		PKI_Free( tk );
		return NULL;
	}

	if (PKI_TOKEN_set_config_dir(tk, NULL) != PKI_OK)
	{
		PKI_log_debug("ERROR, can not set config_dir for TOKEN!\n");
	}

	/* Initialize the library so that it adds all the needed algor and dgst */
	if (PKI_get_init_status() == PKI_STATUS_NOT_INIT) PKI_init_all();

	// Sets the default callback for getting the credentials
	PKI_TOKEN_cred_set_cb(tk, PKI_TOKEN_cred_cb_stdin, NULL);

	// Initializes the token
	PKI_TOKEN_init( tk, NULL, NULL );

	// Sets the status
	tk->status = PKI_TOKEN_STATUS_OK;

	// Sets the login status
	tk->isLoggedIn = 0;

	// Sets the credentials status
	tk->isCredSet = 0;

	return ( tk );
}


/*!
 * \brief Create a new PKI_TOKEN structure and initialize it.
 *
 * Reserves the memory for a new PKI_TOKEN data structure. The returned
 * memory is already zeroize. If the first passed argument is null, the
 * default configuration directory is used (PREFIX/etc). If the second
 * argument is not NULL, the library will try to load the specified config
 * for the token.
 *
 * It returns the pointer to the memory region or NULL in case of error.
*/

PKI_TOKEN *PKI_TOKEN_new( const char * const config_dir, const char * const tokenName )
{
	PKI_TOKEN *tk = NULL;
		// Token data structure

	if((tk = PKI_TOKEN_new_null()) == NULL )
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	/* Initialize OpenSSL so that it adds all the needed algor and dgst */
	if (PKI_get_init_status() == PKI_STATUS_NOT_INIT ) PKI_init_all();

	if ((PKI_TOKEN_init(tk, config_dir, tokenName)) != PKI_OK)
	{
		PKI_log_err("can not initialize token, config loading error.\n");
		tk->status = PKI_TOKEN_STATUS_INIT_ERR;
	}
	else
	{
		tk->status = PKI_TOKEN_STATUS_OK;
	}

	if (tk->hsm) {

		switch (tk->hsm->type) {

			// Known HSM types that need
			// logging in (no auto-login)
			case HSM_TYPE_ENGINE:
			case HSM_TYPE_PKCS11:
			case HSM_TYPE_OTHER: {
				// Nothing to do
			};

			// Overrides Software Token (no prompt)
			case HSM_TYPE_SOFTWARE: {
				// Auto Log-in and Creds set
				tk->isCredSet = 1;
				tk->isLoggedIn = 1;
			} break;

			default: {
				// Unknown Type, assumes it requires login
				// so there is nothing to do here
			}
		}

	} 

	return tk;
}

int PKI_TOKEN_set_hsm(PKI_TOKEN * tk, HSM * hsm ) {

	// Input Checks
	if (!tk || !hsm) return PKI_ERR;

	// Free the token's HSM (if any)
	if (tk->hsm) HSM_free(hsm);

	// Assigns the new HSM to the token
	tk->hsm = hsm;

	// All Done.
	return PKI_OK;
}

int PKI_TOKEN_set_hsm_name(PKI_TOKEN  * tk, 
						   const char * const config_dir,
						   const char * const hsmName) {

	HSM * hsm = NULL;
		// HSM structure

	// Input Checks
	if (!tk || !config_dir || !hsmName) return PKI_ERR;

	// Initializes the HSM
	if ((hsm = HSM_new(config_dir, hsmName)) == NULL) {
		PKI_DEBUG("Cannot Instantiate a new HSM (dir: %s, name: %s)",
			config_dir, hsmName);
		return PKI_ERR;
	}

	// Free the HSM if one is present
	if (tk->hsm) HSM_free(hsm);

	// Assigns the new hsm to the token
	tk->hsm = hsm;

	// All done
	return PKI_OK;
}

/*! \brief Checks the integrity of a PKI_TOKEN
 */

int PKI_TOKEN_check(PKI_TOKEN *tk )
{
	if (!tk) return PKI_TOKEN_STATUS_MEMORY_ERR;

	if (tk->hsm == NULL && tk->type != HSM_TYPE_SOFTWARE)
		PKI_TOKEN_status_add_error(tk, PKI_TOKEN_STATUS_HSM_ERR);

	if (tk->keypair == NULL) {
		// If there is no key, the error condition is triggered if the
		// TOKEN is not a software token or the reported status is
		// a successful login
		PKI_TOKEN_status_add_error(tk, PKI_TOKEN_STATUS_KEYPAIR_MISSING_ERR);
	}

	if (PKI_X509_CERT_check_pubkey(tk->cert, tk->keypair) != PKI_OK)
		PKI_TOKEN_status_add_error(tk, PKI_TOKEN_STATUS_KEYPAIR_CHECK_ERR);

	if (!tk->cert) 
		PKI_TOKEN_status_add_error(tk, PKI_TOKEN_STATUS_CERT_MISSING_ERR);

	if (!tk->cacert) 
		PKI_TOKEN_status_add_error(tk, PKI_TOKEN_STATUS_CACERT_MISSING_ERR);

	if (!tk->otherCerts)
		PKI_TOKEN_status_add_error(tk, PKI_TOKEN_STATUS_OTHERCERTS_MISSING_ERR);

	if (!tk->trustedCerts)
		PKI_TOKEN_status_add_error(tk, PKI_TOKEN_STATUS_TRUSTEDCERTS_MISSING_ERR);

	// There are issues, let's return an error
	if (tk->status != 0) return PKI_ERR;

	// All Ok
	return PKI_OK;

}

/*!
 * \brief Returns a PKI_TOKEN object from a url pointing to a PKCS#12 object.
 */

PKI_TOKEN *PKI_TOKEN_new_p12 ( char *url, char *config_dir, PKI_CRED *cred ) {

	PKI_TOKEN *tk = NULL;
	PKI_X509_PKCS12 *p12 = NULL;

	if( !url ) return ( NULL );

	if((tk = PKI_TOKEN_new_null()) == NULL ) {
		return ( NULL );
	}

	/* Initialize OpenSSL so that it adds all the needed algor and dgst */
	if( PKI_get_init_status() == PKI_STATUS_NOT_INIT ) PKI_init_all();

	PKI_TOKEN_init ( tk, config_dir, NULL );

	if ( cred ) {
		PKI_TOKEN_set_cred ( tk, cred );
	}

	/* Let's get the PKCS12 */
	if ((p12 = PKI_X509_PKCS12_get ( url, PKI_DATA_FORMAT_UNKNOWN, cred, NULL )) == NULL ) {
		if ( tk ) PKI_TOKEN_free ( tk );
		return ( NULL );
	}

	/* Now Copy the data from the p12 to the TOKEN data structures */
	if((tk->keypair = PKI_X509_PKCS12_get_keypair ( p12, cred )) == NULL ) {
		PKI_log_err ( "Can not find keypair in PKCS12 file");
		goto err;
	}

	if((tk->cert = PKI_X509_PKCS12_get_cert ( p12, cred )) == NULL ) {
		PKI_log_err ( "Can not find certificate in PKCS12 file!");
		goto err;
	}

	/* These are optional, let's not be picky if a value is returned
 	 * or not */
	tk->cacert = PKI_X509_PKCS12_get_cacert ( p12, cred);
	tk->otherCerts = PKI_X509_PKCS12_get_otherCerts ( p12, cred );
	// tk->name = PKI_X509_PKCS12_get_name ( p12 );

	/* Let's free the p12 */
	if ( p12 ) PKI_X509_PKCS12_free ( p12 );

	/* Return the Token */
	return ( tk );

err:
	
	if( tk ) PKI_TOKEN_free (tk);
	if( p12 ) PKI_X509_PKCS12_free (p12);
	return ( NULL );
}

/*!
 * \brief Set the configuration directory to be used for the TOKEN operations.
 */

int PKI_TOKEN_set_config_dir ( PKI_TOKEN *tk, char * dir ) {

	if( tk->config_dir ) PKI_Free ( tk->config_dir );

	if( dir ) {
		tk->config_dir = strdup( dir );
	} else {
		tk->config_dir = strdup( PKI_DEFAULT_CONF_DIR );
	}

	return (PKI_OK);
}

/*!
 * \brief Get the configuration directory used for the TOKEN operations.
 */

char * PKI_TOKEN_get_config_dir ( PKI_TOKEN *tk ) {

	if( !tk || !tk->config_dir ) return ("");

	return( tk->config_dir );
}

/*!
 * \brief Get TOKEN name.
 */

char * PKI_TOKEN_get_name ( PKI_TOKEN *tk ) {

	if( !tk || !tk->name ) return ("");

	return( tk->name );
}

void PKI_TOKEN_free_void ( void *tk ) {

	PKI_TOKEN_free ( (PKI_TOKEN *) tk );

	return;
}

/*!
 * \brief Frees a PKI_TOKEN data structure
 *
 * This function Frees a PKI_TOKEN memory region. In case the PKI_TOKEN has
 * already initialized pointers, the pointed data is freed.
 */

int PKI_TOKEN_free( PKI_TOKEN *tk )
{
	if (tk == NULL)
		return PKI_ERROR( PKI_ERR_PARAM_NULL, NULL);

	if (tk->req)
	{
		PKI_X509_REQ_free(tk->req);
		tk->req = NULL;
	}

	if(tk->cacert)
	{
		PKI_X509_CERT_free(tk->cacert);
		tk->cacert = NULL;
	}

	if (tk->keypair)
	{
		PKI_X509_KEYPAIR_free( tk->keypair );
		tk->keypair = NULL;
	}

	if (tk->otherCerts)
	{
		PKI_X509_CERT *x = NULL;

		while ((x = PKI_STACK_X509_CERT_pop( tk->otherCerts )) != NULL)
		{
			PKI_X509_CERT_free( x );
		}

		PKI_STACK_X509_CERT_free( tk->otherCerts );
		tk->otherCerts = NULL;
	}

	if (tk->trustedCerts)
	{
		PKI_X509_CERT *x = NULL;

		while ((x = PKI_STACK_X509_CERT_pop( tk->trustedCerts )) != NULL)
		{
			PKI_X509_CERT_free( x );
		}

		PKI_STACK_X509_CERT_free( tk->trustedCerts );
		tk->trustedCerts = NULL;
	}

	if (tk->crls)
	{
		PKI_X509_CRL *x = NULL;

		while ((x = PKI_STACK_X509_CRL_pop( tk->crls )) != NULL)
		{
			PKI_X509_CRL_free( x );
		}

		PKI_STACK_X509_CRL_free( tk->crls );
		tk->crls = NULL;
	}

	if (tk->profiles)
	{
		PKI_X509_PROFILE *pr = NULL;
		while ((pr = PKI_STACK_X509_PROFILE_pop ( tk->profiles )) != NULL)
		{
			PKI_X509_PROFILE_free ( pr );
		}
		PKI_Free(tk->profiles);
		tk->profiles = NULL;
	}

	if (tk->cert)
	{
		PKI_X509_CERT_free( tk->cert );
		tk->cert = NULL;
	}

	if (tk->config_dir)
	{
		PKI_Free (tk->config_dir);
		tk->config_dir = NULL;
	}

	if (tk->name)
	{
		PKI_Free (tk->name);
		tk->name = NULL;
	}

	if (tk->config)
	{
		PKI_CONFIG_free ( tk->config );
		tk->config = NULL;
	}

	if (tk->algor)
	{
		X509_ALGOR_free(tk->algor);
		tk->algor = NULL;
	}

	if (tk->key_id)
	{
		PKI_Free(tk->key_id);
		tk->key_id = NULL;
	}

	if (tk->cert_id)
	{
		PKI_Free(tk->cert_id);
		tk->cert_id = NULL;
	}

	if (tk->cacert_id)
	{
		PKI_Free(tk->cacert_id);
		tk->cacert_id = NULL;
	}

	if (tk->cred)
	{
		PKI_CRED_free(tk->cred);
		tk->cred = NULL;
	}

	if (tk->hsm)
	{
		HSM_free(tk->hsm);
		tk->hsm = NULL;
	}

	PKI_Free( tk );

	return (PKI_OK);
}

/*! \brief Login into the token (triggers keypair loading) */

int PKI_TOKEN_login(PKI_TOKEN * const tk) {

	// Input Check
	if (!tk) {
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
	}

	// Checks if the Token requires logging in
	if (tk->hsm && tk->hsm->isLoginRequired)

	// Logs into the HSM, if any is configured for the token
	if (tk->hsm // We have an HSM 
	    && tk->hsm->isLoginRequired // Login is Required
		&& !tk->isLoggedIn /* No Login Yet */ ) {
		// Prompts for the credentials if we have none
		if (!tk->isCredSet && PKI_ERR == PKI_TOKEN_cred_prompt ( tk, NULL )) {
			return PKI_ERROR(PKI_ERR_TOKEN_LOGIN, NULL);
		}
		// Login into the HSM
		if (HSM_login(tk->hsm, tk->cred) != PKI_OK) {
			// Sets the error condition
			PKI_TOKEN_status_add_error(tk, PKI_TOKEN_STATUS_LOGIN_ERR);
			// Returns the error
			return PKI_ERROR( PKI_ERR_HSM_LOGIN, NULL);
		} else {
			// Sets the success status for the login
			PKI_TOKEN_set_login_success(tk);
			// Resets the login error condition, if any
			PKI_TOKEN_status_del_error(tk, PKI_TOKEN_STATUS_LOGIN_ERR);
		}
	}

	// Loads the Keypair - this will trigger login for the token
	if (!tk->keypair && tk->key_id) {

		if ((PKI_TOKEN_load_keypair(tk, tk->key_id)) != PKI_OK) {
			tk->status |= PKI_TOKEN_STATUS_KEYPAIR_CHECK_ERR;
			return PKI_ERROR(PKI_ERR_TOKEN_KEYPAIR_LOAD, tk->key_id );
		}
	}

	// Sets the login success
	PKI_TOKEN_set_login_success(tk);

	// All Done
	return PKI_OK;
};

int PKI_TOKEN_set_login_success(PKI_TOKEN * const tk) {
	// Input Checks
	if (!tk) return PKI_ERR;
	// Clears the error
	PKI_TOKEN_status_del_error(tk, PKI_TOKEN_STATUS_LOGIN_ERR);
	// Sets the login status
	tk->isLoggedIn = 1;
	// All Done
	return PKI_OK;
};

int PKI_TOKEN_is_logged_in(const PKI_TOKEN * const tk) {
	// Input Checks & Get operation
	if (!tk || tk->isLoggedIn != 1) return PKI_ERR;
	// All Done
	return PKI_OK;
};

int PKI_TOKEN_is_creds_set(const PKI_TOKEN * const tk) {
	// Input Checks & Get operation
	if (!tk || tk->isCredSet != 1) return PKI_ERR;
	// All Done
	return PKI_OK;
};

int PKI_TOKEN_status_clear_errors(PKI_TOKEN * const tk) {
	// Input Checks
	if (!tk) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
	// Set Operation
	tk->status = PKI_TOKEN_STATUS_OK;
	// All Done
	return PKI_OK;
};

int PKI_TOKEN_status_set(PKI_TOKEN * const tk, const PKI_TOKEN_STATUS status) {
	// Input Checks
	if (!tk || !__check_token_status_range(status)) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
	// Set operation
	tk->status = status;
	// All Done
	return PKI_OK;
};

int PKI_TOKEN_status_del_error(PKI_TOKEN * const tk, const PKI_TOKEN_STATUS status) {
	// Input Checks
	if (!tk || !__check_token_status_range(status)) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
	// Set Operation
	if (tk->status & status) tk->status ^= status;
	// All Done
	return PKI_OK;
};

int PKI_TOKEN_status_add_error(PKI_TOKEN * const tk, const PKI_TOKEN_STATUS status) {
	// Input Checks
	if (!tk || !__check_token_status_range(status)) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
	// Set Operation
	if (!(tk->status & status)) tk->status |= status;
	// All Done.
	return PKI_OK;
};

int PKI_TOKEN_status_has_error(PKI_TOKEN * const tk, const PKI_TOKEN_STATUS status) {
	// Input Checks
	if (!tk || !__check_token_status_range(status)) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
	// Return the condition
	if ((tk->status & status) == 0) {
		return PKI_ERR;
	}
	// All Done
	return PKI_OK;
};

PKI_TOKEN_STATUS PKI_TOKEN_status_get(const PKI_TOKEN * const tk) {
	// Input Checks
	if (!tk) return PKI_TOKEN_STATUS_UNKNOWN;
	// Returns the status value
	return tk->status;
};

/*!
 * \brief Loads a configuration file from the token.d directory.
 *
 * Loads the configuration to be used by the Token. The second parameter is
 * checked against the name of the configuration (not the filename, but the
 * <pki:name></pki:name> field in the file), and the matching is loaded.
 * Each file which filename ends with .xml is checked in the token.d/ dir.
 * The name comparison is case insensitive.
 *
 * The function returns PKI_OK in case of success, or PKI_ERR in case of an
 * error.
 */

int PKI_TOKEN_load_config ( PKI_TOKEN * const tk, const char * const tk_name ) {

	char buff[BUFF_MAX_SIZE];

	char *hsm_name = NULL;
	char *config_file = NULL;
	char *tmp_s = NULL;

	int ret = PKI_ERR;

	const PKI_X509_ALGOR_VALUE * alg = NULL;

	/* Check input */
	if(!tk || !tk_name)
	{
		return PKI_ERROR ( PKI_ERR_PARAM_NULL, "Missing Token or Token name" );
	}

	if (tk->config_dir) snprintf(buff, BUFF_MAX_SIZE,"%s", tk->config_dir );
	else snprintf(buff,BUFF_MAX_SIZE, "%s", PKI_DEFAULT_CONF_DIR );

	// Copies the Name Early so that it is available
	// even when errors occur
	tk->name = strdup(tk_name);

	if ((config_file = PKI_CONFIG_find_all(buff, tk_name, PKI_DEFAULT_TOKEN_DIR)) == NULL)
	{
		return PKI_ERROR ( PKI_ERR_CONFIG_MISSING, buff );
	}

	// If a config was already there, let's free it before continuing
	if (tk->config != NULL) PKI_CONFIG_free(tk->config);

	if ((tk->config = PKI_CONFIG_load(config_file)) == NULL)
	{
		PKI_ERROR( PKI_ERR_CONFIG_LOAD, config_file );
		goto end;
	}

	if ((tmp_s = PKI_CONFIG_get_value(tk->config, "/tokenConfig/type")) != NULL)
	{
		if( strncmp_nocase( tmp_s, "software", 8 ) == 0 ) {
			tk->type = HSM_TYPE_SOFTWARE;
		} else if( strncmp_nocase( tmp_s, "engine", 6 ) == 0 ) {
			tk->type = HSM_TYPE_ENGINE;
		} else if( strncmp_nocase( tmp_s, "kmf", 3 ) == 0 ) {
			tk->type = HSM_TYPE_KMF;
		} else if( strncmp_nocase( tmp_s, "pkcs11", 6) == 0 ) {
			tk->type = HSM_TYPE_PKCS11;
		} else {
			tk->type = HSM_TYPE_OTHER;
		}
	}
	else
	{
		tk->type = HSM_TYPE_SOFTWARE;
	}

	if ((tk->type != HSM_TYPE_SOFTWARE) && ((hsm_name = 
			PKI_CONFIG_get_value( tk->config, "/tokenConfig/hsm")) != NULL))
	{
		PKI_log_debug("TK: Hardware Token: Name is %s", hsm_name );

		if( tk->config_dir )
		{
			snprintf(buff, BUFF_MAX_SIZE,"%s", tk->config_dir );
			if ((tk->hsm = HSM_new ( buff, hsm_name )) == NULL)
			{
				PKI_ERROR(PKI_ERR_HSM_INIT, hsm_name);
				if (tmp_s) PKI_Free(tmp_s);

				// return PKI_ERROR ( PKI_ERR_HSM_INIT, hsm_name );
				goto end;
			}
		}
		else
		{
			if ((tk->hsm = HSM_new( NULL, hsm_name)) == NULL)
			{
				PKI_ERROR(PKI_ERR_HSM_INIT, hsm_name);
				if (tmp_s) PKI_Free(tmp_s);
				goto end;
			}
		}
	}
	else if (tk->type != HSM_TYPE_SOFTWARE)
	{
		PKI_log_debug("TK:: Non-software token selected (%s), but no <pki:hsm>"
			" entry found in token config (%s)", tmp_s, config_file);
	}

	if (tmp_s) PKI_Free ( tmp_s );
	tmp_s = NULL;

	// Load the Passwd - this is used for loading the private
	// key or login into the HSM

	if(( tmp_s = PKI_CONFIG_get_value(tk->config, "/tokenConfig/password")) == NULL)
	{
		char *passin = NULL;

		if ((passin = PKI_CONFIG_get_value(tk->config,"/tokenConfig/passin")) != NULL)
		{
			if (strncmp_nocase( passin, "env:", 4) == 0)
			{
				PKI_TOKEN_cred_set_cb(tk, PKI_TOKEN_cred_cb_env, passin+4);
			}
			else if (strncmp_nocase( passin, "stdin", 5) == 0)
			{
				PKI_TOKEN_cred_set_cb(tk, PKI_TOKEN_cred_cb_stdin, NULL);
			}
			else if (strncmp_nocase(passin, "none", 4) == 0)
			{
				PKI_TOKEN_cred_set_cb(tk, NULL, NULL);
			}
			else if (strlen(passin) < 1)
			{
				PKI_TOKEN_cred_set_cb(tk, NULL, NULL);
			}
			else 
			{
				/* PASSIN not understood! */
				PKI_log_err("passin (%s) not supported!", passin );
			}
		}
		else
		{
			PKI_log_debug("No PassIn found, using stdin.");
			PKI_TOKEN_cred_set_cb(tk, PKI_TOKEN_cred_cb_stdin, NULL);
		}

		if (passin) PKI_Free(passin);
		passin = NULL;
	}
	else
	{
		if (tk->cred == NULL)
		{
			tk->cred = PKI_CRED_new(NULL, tmp_s);
			PKI_Free(tmp_s);
		}
		PKI_TOKEN_cred_set_cb ( tk, NULL, NULL );
	}

	if (tk->type != HSM_TYPE_PKCS11)
	{
		tk->slot_id = 0;

	}
	else
	{
		char *tmp_slotid = NULL;

		if(( tmp_slotid = PKI_CONFIG_get_value( tk->config, "/tokenConfig/slot")) != NULL)
		{
			/* Get the Slot Id */
			tk->slot_id = strtol(tmp_slotid, NULL, 0);
			PKI_Free ( tmp_slotid );
		}

		if ((PKI_TOKEN_use_slot(tk, tk->slot_id)) == PKI_ERR) {
			PKI_ERROR ( PKI_ERR_HSM_SET_SLOT, NULL);
			goto end;
		}
	}

	if ((tmp_s = PKI_CONFIG_get_value( tk->config, "/tokenConfig/keypair")) != NULL)
	{
		// Make sure the libraty is initialized
		// to get all the needed OIDs
		PKI_init_all();

		// Duplicates the Key ID
		tk->key_id = strdup(tmp_s);

		// Frees the temporary memory
		PKI_Free ( tmp_s );

		// We do not load the key as this would trigger the login procedure.
		// Key loading is delayed until the call to the PKI_TOKEN_login()
		// function
		
	}
	else PKI_log_debug("TOKEN::Warning::No Key Provided!");

	if ((tmp_s = PKI_CONFIG_get_value(tk->config, "/tokenConfig/cert")) != NULL)
	{
		if ((tk->cert = PKI_X509_CERT_get(tmp_s, PKI_DATA_FORMAT_UNKNOWN, 
													tk->cred, tk->hsm)) == NULL) {
			PKI_Free(tmp_s);
			PKI_ERROR(PKI_ERR_TOKEN_CERT_LOAD, NULL);
			goto end;
		} 

		// The init function already assigned and algorithm to the token, we
		// might want to free it before re-assigning the algorithm
		if (tk->algor) PKI_X509_ALGOR_VALUE_free(tk->algor);

		// Assign the algorithm from the certificate
		alg = PKI_X509_CERT_get_data(tk->cert, PKI_X509_DATA_ALGORITHM);
		if (alg) PKI_TOKEN_set_algor(tk, PKI_X509_ALGOR_VALUE_get_id(alg));

		// Assign the name
		tk->cert_id = strdup( tmp_s );
		PKI_Free ( tmp_s );
	}

	if ((tmp_s = PKI_CONFIG_get_value ( tk->config, "/tokenConfig/cacert")) != NULL)
	{
		if((tk->cacert = PKI_X509_CERT_get(tmp_s, PKI_DATA_FORMAT_UNKNOWN,
													tk->cred, tk->hsm )) == NULL) {
			PKI_ERROR(PKI_ERR_TOKEN_CACERT_LOAD, NULL);
		}
		else
		{
			tk->cacert_id = strdup( tmp_s );
		}
		PKI_Free(tmp_s);
	}

	if ((tmp_s = PKI_CONFIG_get_value(tk->config, "/tokenConfig/otherCerts")) != NULL)
	{
		tk->otherCerts = PKI_X509_CERT_STACK_get(tmp_s, 
												 PKI_DATA_FORMAT_UNKNOWN, tk->cred, tk->hsm );

		if (tk->otherCerts == NULL)
			PKI_ERROR(PKI_ERR_TOKEN_OTHERCERTS_LOAD, tmp_s);

		PKI_Free ( tmp_s );
	}

	if ((tmp_s = PKI_CONFIG_get_value(tk->config, "/tokenConfig/trustedCerts")) != NULL)
	{
		tk->trustedCerts = PKI_X509_CERT_STACK_get(tmp_s, 
												   PKI_DATA_FORMAT_UNKNOWN, tk->cred, tk->hsm);

		if (!tk->trustedCerts) 
			PKI_ERROR(PKI_ERR_TOKEN_TRUSTEDCERTS_LOAD, tmp_s);

		PKI_Free ( tmp_s );
	}

	ret = PKI_OK;

end:
	if (tk_name) tk->name = strdup(tk_name);
	if (config_file) PKI_Free(config_file);
	return ret;
}

/*!
 * \brief Register the callback function for asking password to access Token
 *
 * The function to be registered should accept only one parameter (prompt)
 * and should return a pointer to an allocated PKI_CRED structure.
 */

int PKI_TOKEN_cred_set_cb(PKI_TOKEN *tk, PKI_CRED * (*cb)(char *), char *prompt)
{
	if (!tk) return PKI_ERROR( PKI_ERR_TOKEN_SET_CRED, NULL );

	if ((tk->cred_cb = cb) == NULL) return PKI_OK;

	if (tk->cred_prompt) PKI_Free(tk->cred_prompt);

	if( prompt ) tk->cred_prompt = strdup( prompt );

	return ( PKI_OK );
};

/*!
 * \brief Sets the slot of the current token, in PKCS#11 this is
          equivalent to the login
 */

int PKI_TOKEN_use_slot( PKI_TOKEN *tk, long num )
{
	if( !tk || num < 0 ) return PKI_ERROR( PKI_ERR_TOKEN_USE_SLOT, NULL );

	return HSM_SLOT_select ( (unsigned long) num, tk->cred, tk->hsm );
}

/*!
 * \brief Initialize Token properties (load OIDs and PROFILES)
 */

int PKI_TOKEN_init(PKI_TOKEN  * const tk,
				   const char * const conf_dir,
				   const char * const tk_name) {

	char buff[2048];

	PKI_CONFIG *oids = NULL;
	char * homedir = NULL;

	if (!tk) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL );

	if( tk->config_dir ) {
		PKI_Free ( tk->config_dir );
		tk->config_dir = NULL;
	}

	if (conf_dir) {
		/* Set the new Config Dir */
		tk->config_dir = strdup ( conf_dir );
	} else {
		if ((homedir = getenv("HOME")) != NULL) {
			snprintf( buff, sizeof( buff), "%s/.libpki", homedir);
		} else {
			snprintf( buff, sizeof( buff ), "%s", PKI_DEFAULT_CONF_DIR );
		}

		tk->config_dir = strdup ( buff );
	}

	/* Load Configuration Files */
	snprintf( buff, sizeof(buff), "%s/%s", tk->config_dir, 
		PKI_DEFAULT_CONF_OID_FILE);

	/* Load the external object Identifiers file */
	if ((oids = PKI_CONFIG_load( buff )) != NULL) tk->oids = oids;

	/* Load Configuration Files */
	snprintf( buff, BUFF_MAX_SIZE, "%s/%s", tk->config_dir, 
		PKI_DEFAULT_PROFILE_DIR);

	if (PKI_TOKEN_load_profiles( tk, buff ) != PKI_OK) {
		// If the failure happens when we were passed
		// a directory name, we need to inform the caller,
		// otherwise there is no need to use an error message
		// for the default config directory
		if (conf_dir) {
			/* We should check why... */
			PKI_ERROR(PKI_ERR_CONFIG_LOAD, "Can not load profiles (%s)", buff);
		}
	}

	/* Now let's try to load the HSM configuration file */
	if (tk_name) {
		if ((PKI_TOKEN_load_config(tk, tk_name)) != PKI_OK)	{
			return PKI_ERROR ( PKI_ERR_TOKEN_PROFILE_LOAD, tk_name );
		}
	}

	/* This sets the algorithm */
	if (!tk->algor) {
		// We set the algorithm only if we have a key, otherwise
		// we would get an error
		if (PKI_TOKEN_set_algor(tk, PKI_ALGOR_DEFAULT) != PKI_OK) {
			return PKI_ERROR ( PKI_ERR_TOKEN_SET_ALGOR, NULL );
		}
	}

	return PKI_OK;
}

/*!
 * \brief Returns a pointer to an Object Identifier structure
 *
 * This function returns a pointer to an Object Identifier if the
 * OID is identified among the ones in the crypto library used or
 * among the configured ones in the objectIdentifiers.xml file that
 * is loaded when the PKI_TOKEN_init() function is used.
 */

PKI_OID *PKI_TOKEN_OID_new ( PKI_TOKEN *tk, char *oid_s )
{
	PKI_OID *ret = NULL;

	/* Here every library should provide it's own function
	   for oid generation: PKI_OID_new() and PKI_OID_free() */

	ret = PKI_OID_get( oid_s );

	if (!ret) ret = PKI_CONFIG_OID_search ( tk->oids, oid_s );

	return (ret);
}

/*!
 * \brief Set the TOKEN's scheme algorithm via its PKI_ALGOR_ID.
 *
 * When generating signatures (e.g., when issuing a new request or certificate)
 * by using the PKI_TOKEN facility, a signature algorithm has to be chosen. The
 * default one is sha1withRSA, but, depending on the capabilities of the system
 * you may be able to use differnt ones as well. This algorithm is used in 
 * combination with the signature scheme (e.g., sha1withRSA or md5withDSA), 
 * therefore it must be consistent with it.
 *
 * Possible algoritms are: 
 * -PKI_ALGOR_RSA_MD5
 * -PKI_ALGOR_RSA_MD2
 * -PKI_ALGOR_RSA_SHA1
 * -PKI_ALGOR_DSA_SHA1
 * -PKI_ALGOR_RSA_SHA224
 * -PKI_ALGOR_RSA_SHA256
 * -PKI_ALGOR_RSA_SHA512
 * -PKI_ALGOR_RSA_RIPEMD160
 * -PKI_ALGOR_ECDSA_SHA1
 *
 */

int PKI_TOKEN_set_algor(PKI_TOKEN *tk, PKI_ALGOR_ID algId)
{
	PKI_X509_ALGOR_VALUE *al = NULL;

	if (!tk) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL );

	if(algId <= 0) algId = PKI_ALGOR_DEFAULT;

	// Now let's get the algor
	if ((al = PKI_X509_ALGOR_VALUE_get(algId)) == NULL) {
		PKI_ERROR(PKI_ERR_ALGOR_UNKNOWN, NULL);
		return PKI_ERR;
	}

	// If already set, let's free the memory first
	if (tk->algor) PKI_X509_ALGOR_VALUE_free(tk->algor);
	
	// Now we can safely assign the algorithm to the token
	tk->algor = al;
	
	/* Check that the HSM capabilities */
	if (tk->hsm) return HSM_set_sign_algor(tk->algor, tk->hsm);

	return PKI_OK;
};

/*!
 * \brief Set the TOKEN's scheme algorithm via its name.
 *
 * When generating signatures (e.g., when issuing a new request or certificate)
 * by using the PKI_TOKEN facility, a signature algorithm has to be chosen. The
 * default one is sha1withRSA, but, depending on the capabilities of the system you
 * may be able to use differnt ones as well. This algorithm is used in combination
 * with the signature scheme (e.g., sha1withRSA or md5withDSA), therefore it must
 * be consistent with it.
 *
 * Possible algoritms names are: 
 *   RSA-MD2
 *   RSA-MD4
 *   RSA-MD5
 *   RSA-SHA1
 *   DSA-SHA1
 *   RSA-SHA224
 *   RSA-SHA256
 *   RSA-SHA512
 *   RSA-RIPEMD160
 */

int PKI_TOKEN_set_algor_by_name(PKI_TOKEN  * tk,
	                              const char * alg_name) {

	PKI_X509_ALGOR_VALUE *al = NULL;

	if (!tk) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if ((al = PKI_X509_ALGOR_VALUE_get_by_name(alg_name)) == NULL)
		return PKI_ERROR(PKI_ERR_TOKEN_SET_ALGOR, alg_name);

	// Check and assign the new algorithm
	if (tk->algor) PKI_X509_ALGOR_VALUE_free(tk->algor);
	tk->algor = al;

	/* Check that the HSM capabilities */
	if (tk->hsm) return HSM_set_sign_algor(tk->algor, tk->hsm);

	return( PKI_OK );
}

/*!
 * \brief Returns the algorithm id set for this token
 */

int PKI_TOKEN_get_algor_id( PKI_TOKEN *tk )
{
	int ret = PKI_ALGOR_ID_UNKNOWN;

	if (!tk) 
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ALGOR_ID_UNKNOWN;
	}

	if (tk->algor) ret = PKI_X509_ALGOR_VALUE_get_id(tk->algor);

	return ret;
};

/*!
 * \brief Returns the PKI_ALGORITHM pointer set for the token
 */

PKI_X509_ALGOR_VALUE * PKI_TOKEN_get_algor( PKI_TOKEN *tk )
{
	if (!tk)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	return tk->algor;
}

int PKI_TOKEN_set_digest(PKI_TOKEN * tk, const PKI_DIGEST_ALG * digest) {

	// Input Checks
	if (!tk || !digest) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, tk == NULL ? "Token" : "Digest");
		return PKI_ERR;
	}

	// If there is no Keypair associated with the token,
	// there is nothing else we need to do
	if (!tk->keypair) {
		// Assigns the digest
		tk->digest = (PKI_DIGEST_ALG *)digest;
		// All Done
		return PKI_OK;
	}

	// Extracts the keypair value
	PKI_X509_KEYPAIR_VALUE * k_val = PKI_X509_get_value(tk->keypair);
	if (!k_val) return PKI_ERR;

	// Checks if the algorithm is supported by the key
	if (PKI_ERR == PKI_X509_KEYPAIR_is_digest_supported(tk->keypair, digest)) {
		// The Digest is not supported, let's report the error
		PKI_ERROR(PKI_ERR_ALGOR_UNKNOWN, "Digest Algorithm not supported by the key");
		return PKI_ERR;
	}

	// Let's get the X509 algorithm from key and digest
	int alg_nid = PKI_ID_UNKNOWN;
	if (!OBJ_find_sigid_by_algs(&alg_nid, EVP_MD_nid(digest), EVP_PKEY_id(k_val))) {
		PKI_ERROR(PKI_ERR_ALGOR_SET, "Error while setting the X509 algorithm");
		return PKI_ERR;
	}

	// Checks the value
	if (alg_nid == PKI_ID_UNKNOWN) {
		PKI_ERROR(PKI_ERR_ALGOR_SET, "Combined PKEY and MD Algorithm is UNKNOWN");
		return PKI_ERR;
	}

	// Sets the Token's Algorithm
	tk->algor = PKI_X509_ALGOR_VALUE_new_type(alg_nid);

	// All Done.
	return PKI_OK;
}

int PKI_TOKEN_set_digest_id(PKI_TOKEN * tk, PKI_ALGOR_ID digest_id) {

	const PKI_DIGEST_ALG * digest = NULL;

	// Input Checks
	if (!tk) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// Retrieves the digest
	digest = EVP_get_digestbynid(digest_id);
	if (!digest) {
		return PKI_ERROR(PKI_ERR_DIGEST_TYPE_UNKNOWN, NULL);
	}
	
	// Sets the new digest
	tk->digest = (PKI_DIGEST_ALG *)digest;

	// All Done
	return PKI_OK;
}

int PKI_TOKEN_set_digest_by_name(PKI_TOKEN * tk, const char * digest_name) {

	// Input Checks
	if (!tk || !digest_name) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// Gets the ID from the name
	int digest_id = OBJ_sn2nid(digest_name);

	// Let's return the final result
	return PKI_TOKEN_set_digest_id(tk, digest_id); 
}

const PKI_DIGEST_ALG * PKI_TOKEN_get_digest(PKI_TOKEN * tk) {

	// Input Checks
	if (!tk) return NULL;

	// Returns the pointer
	return tk->digest;

}
int PKI_TOKEN_get_digest_id(PKI_TOKEN * tk) {

	// Input Checks
	if (!tk) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// Returns the ID of the digest, if any
	if (tk->digest == NULL) return PKI_ID_UNKNOWN;

	// All done
	return EVP_MD_nid(tk->digest);
}

const char * PKI_TOKEN_get_digest_name(PKI_TOKEN * tk) {

	// Input checks
	if (!tk) return NULL;

	// Converts the digest' NID into text
	return OBJ_nid2sn(EVP_MD_nid(tk->digest));
}


/*!
 * \brief Generates a PKI_X509_KEYPAIR and store it in a PKI_TOKEN.
 *
 * This function assumes a new PKI_TOKEN data structure is passed
 * together with the PKI_SCHEME and the number of bit for the new
 * key. It returns PKI_OK in case of success or PKI_ERR if an
 * error occurs. The _ex version allows to specify additional parameters
 * for the keypair generation. For EC keys, the param is a pointer to
 * an integer (nid of the requested curve).
 *
 * The label (a url string) is needed by some HSM(s).
 */

int PKI_TOKEN_new_keypair_ex(PKI_TOKEN     * tk,
	                           PKI_KEYPARAMS * kp, 
                             char          * label,
                             char          * profile_s) {

	URL *url = NULL;
	int ret = PKI_OK;

	if (!tk) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if (tk->hsm)
	{
		/* Currently only PKCS11 devices REQUIRE a label for
 		 * key creation */
		if ((tk->hsm->type == HSM_TYPE_PKCS11) && !label)
		{
			if ((url = URL_new(label)) == NULL)
			{
				return PKI_ERROR(PKI_ERR_URI_PARSE, label);
			}
		}
	}

	if (!url)
	{
		if((url = URL_new (label)) == NULL )
		{
			return PKI_ERROR(PKI_ERR_URI_PARSE, label);
		}
	}

	ret = PKI_TOKEN_new_keypair_url_ex(tk, kp, url, profile_s);

	if (url) URL_free(url);

	return ret;
}

/*!
 * \brief Generates a PKI_X509_KEYPAIR and store it in a PKI_TOKEN.
 *
 * This function assumes a new PKI_TOKEN data structure is passed
 * together with the PKI_SCHEME and the number of bit for the new
 * key. It returns PKI_OK in case of success or PKI_ERR if an
 * error occurs. The _ex version allows to specify additional parameters
 * for the keypair generation. For EC keys, the param is a pointer to
 * an integer (nid of the requested curve).
 *
 * The label (a url string) is needed by some HSM(s).
 */

int PKI_TOKEN_new_keypair ( PKI_TOKEN *tk, int bits, char *label )
{
	PKI_KEYPARAMS *kp = NULL;
	PKI_SCHEME_ID alg = PKI_SCHEME_UNKNOWN;
	int ret = PKI_OK;

	if (!tk) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if (tk->algor) {
		if ((alg = PKI_X509_ALGOR_VALUE_get_scheme(tk->algor))
															== PKI_SCHEME_UNKNOWN) return PKI_ERR;
	} else {
		alg = PKI_SCHEME_DEFAULT;
	}

	if ((kp = PKI_KEYPARAMS_new(alg, NULL)) == NULL)
		return PKI_ERROR(PKI_ERR_OBJECT_CREATE, NULL);

	if (bits > 0) kp->bits = bits;

	ret = PKI_TOKEN_new_keypair_ex(tk, kp, label, NULL);

	if (kp) PKI_KEYPARAMS_free(kp);

	return ret;
}

/*!
 * \brief Generates a PKI_X509_KEYPAIR and store it in a PKI_TOKEN.
 *
 * This function assumes a new PKI_TOKEN data structure is passed
 * together with the PKI_SCHEME and the number of bit for the new
 * key. It returns PKI_OK in case of success or PKI_ERR if an
 * error occurs.
 *
 * The URL is needed by some HSM(s).
 */

int PKI_TOKEN_new_keypair_url_ex ( PKI_TOKEN *tk, PKI_KEYPARAMS *kp, 
		URL *label, char *profile_s )
{
	PKI_X509_KEYPAIR *p = NULL;
	PKI_X509_PROFILE *prof = NULL;

	PKI_SCHEME_ID scheme = PKI_SCHEME_DEFAULT;

	int free_params = 0;

	if (!tk) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// Loads profile_s
	if (profile_s) prof = PKI_TOKEN_search_profile( tk, profile_s );

	// If !params, then we build one
	if (!kp && prof)
	{
		free_params = 1;
		if ((kp = PKI_KEYPARAMS_new(scheme, prof)) == NULL)
		{
			PKI_X509_PROFILE_free(prof);
			return PKI_ERROR(PKI_ERR_OBJECT_CREATE, NULL);
		}
	}

	// // madwolf: Removed since no prompt should happen at this point
	// // if (!tk->cred) tk->cred = PKI_TOKEN_cred_get(tk, NULL);
	// // Let's check if we need to login
	// if (!tk->isLoggedIn) PKI_TOKEN_login(tk);

	if ((p = PKI_X509_KEYPAIR_new_url_kp( kp, label, tk->cred, tk->hsm )) == NULL)
	{
		if (free_params) PKI_KEYPARAMS_free(kp);
		if (prof) PKI_X509_PROFILE_free(prof);

		return PKI_ERR;
	};

	if (tk->keypair) PKI_X509_KEYPAIR_free(tk->keypair);

	tk->keypair = p;

	if(free_params && kp) PKI_KEYPARAMS_free(kp);

	if (tk->algor) X509_ALGOR_free(tk->algor);

	tk->algor = PKI_X509_KEYPAIR_get_algor(tk->keypair);

	return PKI_OK;
}

/*!
 * \brief Generates a PKI_X509_KEYPAIR and store it in a PKI_TOKEN.
 *
 * This function assumes a new PKI_TOKEN data structure is passed
 * together with the PKI_SCHEME and the number of bit for the new
 * key. It returns PKI_OK in case of success or PKI_ERR if an
 * error occurs.
 *
 * The URL is needed by some HSM(s).
 */

int PKI_TOKEN_new_keypair_url(PKI_TOKEN *tk, int bits, URL *label)
{
	PKI_KEYPARAMS *kp = NULL;
	PKI_SCHEME_ID scheme = PKI_SCHEME_UNKNOWN;
	int ret = PKI_OK;

	if (!tk) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if (tk->algor)
	{
		if ((scheme = PKI_X509_ALGOR_VALUE_get_scheme(tk->algor)) == PKI_SCHEME_UNKNOWN)
			return PKI_ERR;
	}
	else scheme = PKI_SCHEME_DEFAULT;

	if ((kp = PKI_KEYPARAMS_new(scheme, NULL)) == NULL)
		return PKI_ERROR(PKI_ERR_OBJECT_CREATE, NULL);

	if( bits > 0 ) kp->bits = bits;

	ret = PKI_TOKEN_new_keypair_url_ex ( tk, kp, label, NULL );

	if (kp) PKI_KEYPARAMS_free(kp);

	return ret;
}

/*!
 * \brief Returns the PKI_X509_KEYPAIR of a PKI_TOKEN
 *
 * Use this function to get a reference (not a copy) to the PKI_X509_KEYPAIR
 * of the PKI_TOKEN.
 *
 * The function returns the pointer or NULL in case of error of if no
 * PKI_X509_KEYPAIR has been assigned to the PKI_TOKEN yet. 
 */

PKI_X509_KEYPAIR *PKI_TOKEN_get_keypair ( PKI_TOKEN *tk ) {

	if(!tk) 
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	if (PKI_TOKEN_login(tk) != PKI_OK)
	{
		PKI_ERROR(PKI_ERR_TOKEN_LOGIN, NULL);
		return NULL;
	}

	return tk->keypair;
}
 
/*!
 * \brief Set the PKI_TOKEN certificate
 *
 * Use this function to set the certificate of a PKI_TOKEN. The certificate
 * is automatically freed when the PKI_TOKEN_free() function is used.
 * The function returns PKI_OK in case of success or PKI_ERR otherwise.
 */

int PKI_TOKEN_set_cert(PKI_TOKEN *tk, PKI_X509_CERT *x )
{
	if (!tk || !x || !x->value) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if (tk->cert)
	{
		PKI_X509_CERT_free( tk->cert );
		tk->cert = NULL;
	}

	tk->cert = x;

	return PKI_OK;
}

/*!
 * \brief Returns the certificate of a PKI_TOKEN
 *
 * Use this function to get a reference (not a copy) to the certificate 
 * of the PKI_TOKEN.
 *
 * The function returns the pointer or NULL in case of error of if no
 * certificate has been assigned to the PKI_TOKEN yet. 
 */

PKI_X509_CERT * PKI_TOKEN_get_cert(PKI_TOKEN *tk)
{
	if (!tk)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return (NULL);
	}

	return tk->cert;
}

/*!
 * \brief Set the PKI_TOKEN CA certificate
 *
 * Use this function to set the CA certificate of a PKI_TOKEN. The certificate
 * is automatically freed when the PKI_TOKEN_free() function is used.
 * The function returns PKI_OK in case of success or PKI_ERR otherwise.
 */

int PKI_TOKEN_set_cacert( PKI_TOKEN *tk, PKI_X509_CERT *x)
{
	if (!tk || !x || !x->value) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if (tk->cacert)
	{
		PKI_X509_CERT_free(tk->cacert );
		tk->cacert = NULL;
	}

	tk->cacert = x;

	return PKI_OK;
}

/*!
 * \brief Returns the CA certificate of a PKI_TOKEN
 *
 * Use this function to get a reference (not a copy) to the CA certificate 
 * of the PKI_TOKEN.
 *
 * The function returns the pointer or NULL in case of error of if no
 * CA certificate has been assigned to the PKI_TOKEN yet. 
 */

PKI_X509_CERT * PKI_TOKEN_get_cacert(PKI_TOKEN *tk)
{
	if (!tk) 
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	return tk->cacert;
}

/*!
 * \brief Set the PKI_TOKEN stack of additional certificates
 *
 * Use this function to set a stack of certificate to a PKI_TOKEN. The stack
 * is automatically freed when the PKI_TOKEN_free() function is used.
 * The additional certificates are used for validation purposes when a verify
 * of the PKI_TOKEN certificate is performed.
 *
 * The function returns PKI_OK in case of success or PKI_ERR otherwise.
 */

int PKI_TOKEN_set_otherCerts ( PKI_TOKEN *tk, PKI_X509_CERT_STACK *stack )
{
	if (!tk || !stack ) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if (tk->otherCerts)
	{
		PKI_STACK_X509_CERT_free ( stack );
		tk->otherCerts = NULL;
	}
	tk->otherCerts = stack;

	return(PKI_OK);

}

/*!
 * \brief Set the PKI_TOKEN stack of trusted certificates
 *
 * Use this function to set a stack of trusted certs to a PKI_TOKEN. The stack
 * is automatically freed when the PKI_TOKEN_free() function is used.
 * The additional certificates are used for validation purposes when a verify
 * of the PKI_TOKEN certificate is performed.
 *
 * The function returns PKI_OK in case of success or PKI_ERR otherwise.
 */

int PKI_TOKEN_set_trustedCerts ( PKI_TOKEN *tk, PKI_X509_CERT_STACK *stack)
{
	if (!tk || !stack) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if (tk->trustedCerts)
	{
		PKI_STACK_X509_CERT_free ( stack );
		tk->trustedCerts = NULL;
	}
	tk->trustedCerts = stack;

	return(PKI_OK);

}

/*!
 * \brief Set the PKI_TOKEN stack of CRLs
 *
 * Use this function to set a stack of CRLs to a PKI_TOKEN. The stack
 * is automatically freed when the PKI_TOKEN_free() function is used.
 * The CRLs will be used for validation purposes when a verify
 * of a certificate is performed (if the token is passed as an argument).
 *
 * The function returns PKI_OK in case of success or PKI_ERR otherwise.
 */

int PKI_TOKEN_set_crls ( PKI_TOKEN *tk, PKI_X509_CRL_STACK *stack )
{
	if (!tk || !stack) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if (tk->crls)
	{
		PKI_STACK_X509_CRL_free ( stack );
		tk->crls = NULL;
	}
	tk->crls = stack;

	return(PKI_OK);

}

/*!
 * \brief Returns the stack of CRLs stored in a PKI_TOKEN
 *
 * Use this function to get a reference (not a copy) to the stack of
 * CRLs of the PKI_TOKEN.
 *
 * The function returns the pointer to the PKI_X509_CRL_STACK or NULL
 * in case of error.
 */

PKI_X509_CRL_STACK * PKI_TOKEN_get_crls ( PKI_TOKEN *tk )
{
	if (!tk)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return (NULL);
	}

	return tk->crls;
}

/*!
 * \brief Returns the stack of other certificates (chain) of a PKI_TOKEN
 *
 * Use this function to get a reference (not a copy) to the stack of
 * certificates of the PKI_TOKEN.
 *
 * The function returns the pointer to the PKI_X509_CERT_STACK or NULL
 * in case of error.
 */

PKI_X509_CERT_STACK * PKI_TOKEN_get_otherCerts ( PKI_TOKEN *tk )
{
	if (!tk)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return (NULL);
	}

	return tk->otherCerts;
}

/*!
 * \brief Returns the stack of trusted certificates (chain) of a PKI_TOKEN
 *
 * Use this function to get a reference (not a copy) to the stack of
 * trusted certificates (Trust Anchors) of the PKI_TOKEN.
 *
 * The function returns the pointer to the PKI_X509_CERT_STACK or NULL
 * in case of error.
 */

PKI_X509_CERT_STACK * PKI_TOKEN_get_trustedCerts(PKI_TOKEN *tk)
{
	if (!tk)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return (NULL);
	}

	return tk->trustedCerts;
}

/*!
 * \brief Set the credentials to be used when retrieving/using the X509_KEYPAIR.
 *
 * Use this function to set the credentials to be used by the PKI_TOKEN. The
 * credentials are automatically freed when the PKI_TOKEN_free() function is used.
 * The function returns PKI_OK in case of success or PKI_ERR otherwise.
 */

int PKI_TOKEN_set_cred ( PKI_TOKEN *tk, PKI_CRED *cred )
{
	if (!tk || !cred) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if( tk->cred ) PKI_CRED_free (tk->cred);
	tk->cred = PKI_CRED_dup(cred);

	return PKI_OK;
}

/*!
 * \brief Returns the credentials of a PKI_TOKEN
 *
 * Use this function to get a reference (not a copy) to the credentials 
 * of the PKI_TOKEN.
 *
 * The function returns the pointer or NULL in case of error of if no
 * credentials has been assigned to the PKI_TOKEN yet. 
 */

PKI_CRED * PKI_TOKEN_get_cred ( PKI_TOKEN *tk )
{
	if (!tk)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return (NULL);
	}

	return tk->cred;
}

/*!
 * \brief Set the X509_KEYPAIR to be used in the TOKEN.
 *
 * Use this function to set the credentials to be used by the PKI_TOKEN. The
 * credentials are automatically freed when the PKI_TOKEN_free() function is used.
 * The function returns PKI_OK in case of success or PKI_ERR otherwise.
 */

int PKI_TOKEN_set_keypair ( PKI_TOKEN *tk, PKI_X509_KEYPAIR *pkey )
{
	PKI_X509_ALGOR_VALUE *pKeyAlgor = NULL;

	if (!tk || !pkey || !pkey->value)
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if (tk->keypair)
	{
		PKI_X509_KEYPAIR_free( tk->keypair );
		tk->keypair = NULL;
	}

	tk->keypair = pkey;

	if (( pKeyAlgor = PKI_X509_KEYPAIR_get_algor(tk->keypair)) != NULL)
	{
		if (tk->algor) PKI_X509_ALGOR_VALUE_free(tk->algor);
		tk->algor = pKeyAlgor;
	}
	else PKI_log_debug("WARNING: can not get default algorithm from Key!");

	return PKI_OK;
}

/*!
 * \brief Get the CA certificate from a URL and assigns it to the PKI_TOKEN
 *
 * This function loads the CA certificate from a URL and assigns it to the
 * PKI_TOKEN structure. The certificate data structure is automatically
 * freed when the PKI_TOKEN_free() function is used.
 *
 * The function returns PKI_OK in case of success, otherwise it returns
 * PKI_ERR.
 */

int PKI_TOKEN_load_cacert(PKI_TOKEN *tk, char *url_string)
{
	if (!tk || !url_string ) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// if (!tk->cred) tk->cred = PKI_TOKEN_cred_get ( tk, NULL );

	if ((tk->cacert = PKI_X509_CERT_get(url_string, PKI_DATA_FORMAT_UNKNOWN,
												tk->cred, tk->hsm)) == NULL) {
		/* Can not load the certificate from the given URL */
		return PKI_ERROR(PKI_ERR_TOKEN_CACERT_LOAD, url_string);
	}

	return(PKI_OK);
}


/*!
 * \brief Get a certificate from a URL and assigns it to the PKI_TOKEN
 *
 * This function loads a certificate from a URL and assigns it to the
 * PKI_TOKEN structure. The certificate data structure is automatically
 * freed when the PKI_TOKEN_free() function is used.
 *
 * The function returns PKI_OK in case of success, otherwise it returns
 * PKI_ERR.
 */

int PKI_TOKEN_load_cert( PKI_TOKEN *tk, char *url_string )
{
	if (!tk || !url_string) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// if( !tk->cred ) tk->cred = PKI_TOKEN_cred_get ( tk, NULL );

	if((tk->cert = PKI_X509_CERT_get(url_string, PKI_DATA_FORMAT_UNKNOWN,
												tk->cred, tk->hsm)) == NULL) {
		/* Can not load the certificate from the given URL */
		return PKI_ERR;
	}

	/* TODO: Not sure what the use of this call is in this function, additional
	         checks are required. For now, we remove it.
	*/
	/*
	if ((alg = PKI_X509_CERT_get_data(tk->cert, PKI_X509_DATA_ALGORITHM )) == NULL)
	{
		PKI_log_debug ("Can not get Cert Signature Algorithm!");
	}
	else
	{
		PKI_log_debug ("Setting algor to %s", PKI_ALGOR_get_parsed (alg));
		PKI_TOKEN_set_algor(tk, PKI_ALGOR_get_id(alg));
	}
	*/

	return PKI_OK;
}

/*!
 * \brief Get a chain of TRUSTED certificates from a URL and assigns them to
 *        the PKI_TOKEN (CA Certificates)
 *
 * This function loads a set of certificates from a URL and assigns it to the
 * PKI_TOKEN structure. The stack of certificates is automatically
 * freed when the PKI_TOKEN_free() function is used.
 *
 * The function returns PKI_OK in case of success, otherwise it returns
 * PKI_ERR.
 */

int PKI_TOKEN_load_trustedCerts( PKI_TOKEN *tk, char *url_string )
{
	PKI_X509_CERT_STACK *cert = NULL;
	int i = 0;

	if (!tk || !url_string) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// if (!tk->cred) tk->cred = PKI_TOKEN_cred_get(tk, NULL);

	if((cert = PKI_X509_CERT_STACK_get(url_string, PKI_DATA_FORMAT_UNKNOWN,
												tk->cred, tk->hsm)) == NULL) {
		/* Can not load the certificate from the given URL */
		return PKI_ERROR(PKI_ERR_URI_GENERAL, url_string);
	}

	/* attach the stack to the TOKEN structure */
	if ((i = PKI_STACK_X509_CERT_elements(cert)) > 0) tk->trustedCerts = cert;

	// On success the number of certificates in the chain is returned 
	return PKI_OK;
}

/*!
 * \brief Get a chain of certificates from a URL and assigns them to
 *        the PKI_TOKEN (Not Trust Anchors - i.e., trusted CA certs)
 *
 * This function loads a set of certificates from a URL and assigns it to the
 * PKI_TOKEN structure. The stack of certificates is automatically
 * freed when the PKI_TOKEN_free() function is used.
 *
 * The function returns PKI_OK in case of success, otherwise it returns
 * PKI_ERR.
 */

int PKI_TOKEN_load_otherCerts(PKI_TOKEN *tk, char *url_string)
{
	int i = 0;
	PKI_X509_CERT_STACK *cert = NULL;

	if (!tk || !url_string) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// if (!tk->cred) tk->cred = PKI_TOKEN_cred_get(tk, NULL);

	if((cert = PKI_X509_CERT_STACK_get(url_string, PKI_DATA_FORMAT_UNKNOWN,
												tk->cred, tk->hsm)) == NULL) {
		/* Can not load the certificate from the given URL */
		return PKI_ERROR(PKI_ERR_URI_GENERAL, url_string);
	}

	/* attach the stack to the TOKEN structure */
	if( (i = PKI_STACK_X509_CERT_elements( cert )) > 0) tk->otherCerts = cert;

	// On success the number of certificates in the chain is returned
	return PKI_OK;
}

/*!
 * \brief Get a stack of CRLs from a URL and assigns them to the PKI_TOKEN
 *
 * This function loads a set of CRLs from a URL and assigns it to the
 * PKI_TOKEN structure. The memory associated with the stack of CRLs is
 * automatically freed when the PKI_TOKEN_free() function is used.
 *
 * The function returns PKI_OK in case of success, otherwise it returns
 * PKI_ERR.
 */

int PKI_TOKEN_load_crls ( PKI_TOKEN *tk, char *url_string)
{
	PKI_X509_CRL_STACK *crl_sk = NULL;
	int i = 0;

	if (!tk || !url_string) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// if( !tk->cred ) tk->cred = PKI_TOKEN_cred_get ( tk, NULL );

	if ((crl_sk = PKI_X509_CRL_STACK_get( url_string, PKI_DATA_FORMAT_UNKNOWN,
												tk->cred, tk->hsm )) == NULL) {
		/* Can not load the certificate from the given URL */
		return PKI_ERROR(PKI_ERR_URI_GENERAL, url_string);
	}

	/* attach the stack to the TOKEN structure */
	if ((i = PKI_STACK_X509_CRL_elements( crl_sk )) > 0) tk->crls = crl_sk;

	// On success the number of certificates in the chain is returned
	return PKI_OK;
}

/*!
 * \brief Get a PKI_X509_KEYPAIR from a URL and assigns it to the PKI_TOKEN
 *
 * This function loads a keypair from a URL and assigns it to the
 * PKI_TOKEN structure. The keypair data structure is automatically
 * freed when the PKI_TOKEN_free() function is used.
 *
 * The function returns PKI_OK in case of success, otherwise it returns
 * PKI_ERR.
 */

int PKI_TOKEN_load_keypair(PKI_TOKEN *tk, char *url_string)
{
	PKI_X509_KEYPAIR *pkey = NULL;
	URL *url = NULL;

	if (!tk | !url_string) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if ((url = getParsedUrl(url_string)) == NULL)
		return PKI_ERROR(PKI_ERR_URI_PARSE, url_string);

	if ((pkey = PKI_X509_KEYPAIR_get_url( url, PKI_DATA_FORMAT_UNKNOWN,
											tk->cred, tk->hsm )) == NULL) {
		/* Can not load the keypair from the given URL */
		PKI_log_debug("PKI_TOKEN_load_keypair()::Can not load key (%s)", url->url_s);
		PKI_TOKEN_status_add_error(tk, PKI_TOKEN_STATUS_LOGIN_ERR);
		// Free Memory
		if (url) URL_free(url);
		// Error condition
		return PKI_ERROR(PKI_ERR_TOKEN_KEYPAIR_LOAD, url_string);
	}


	// Let's free the URL structure's memory
	if (url) URL_free(url);

	// Set the keypair and return
	if (PKI_TOKEN_set_keypair(tk, pkey) == PKI_OK) {
		// Sets the login status for the token
		if (PKI_TOKEN_set_login_success(tk) == PKI_OK) {
			// Sets the status code for the token
			if (PKI_TOKEN_status_set(tk, PKI_TOKEN_STATUS_OK) != PKI_OK) {
				// Cannot Set the TOKEN status
				return PKI_ERROR(PKI_ERR_TOKEN_SET_STATUS, NULL);
			}
		} else {
			// ERROR: Cannot set the Login Success
			return PKI_ERROR(PKI_ERR_TOKEN_LOGIN, NULL);
		}
	} else {
		// ERROR: Cannot Set the KeyPair for the Token
		return PKI_ERROR(PKI_ERR_TOKEN_KEYPAIR_LOAD, NULL);
	}

	// All Done.
	return PKI_OK;

	/*

	// Frees the memory (if any) associated with the current keypair in the token
	if (tk->keypair) PKI_X509_KEYPAIR_free(tk->keypair);

	// Assign the token's with the new pkey
	tk->keypair = pkey;

	// Extracts the algorithm from pkey
	if ((pKeyAlgor = PKI_X509_KEYPAIR_get_algor(pkey)) != NULL)
	{
		// PKI_TOKEN_set_algor(tk, pKeyAlgor);
		tk->algor = pKeyAlgor;
	}
	else PKI_log_debug("WARNING: can not get default algorithm from Key!");

	if (url) URL_free (url);
	
	return PKI_OK;
	*/
}

/*!
 * \brief Loads a certificate request from a URL and assigns it to the TOKEN
 *
 * The function returns PKI_OK in case of success, otherwise it returns
 * PKI_ERR.
 */

int PKI_TOKEN_load_req ( PKI_TOKEN *tk, char *url_string ) {

	URL *url = NULL;

	if( !tk || !url_string ) return PKI_ERR;

	if((tk->req = PKI_X509_REQ_get( url_string, PKI_DATA_FORMAT_UNKNOWN,
											tk->cred, tk->hsm )) == NULL ) {
		/* Can not load the certificate from the given URL */
		URL_free( url );
		return PKI_ERR;
	}

	return(PKI_OK);
}

/*! \brief Exports a PKI_TOKEN to a URL as PKCS#12 format */

int PKI_TOKEN_export_p12 ( PKI_TOKEN *tk, PKI_DATA_FORMAT format, char *url_s,
					PKI_CRED *cred ) {

	URL *url = NULL;
	PKI_X509_PKCS12 *p12 = NULL;

	/* This will write a PKI_TOKEN in an .p12 file */
	if(!tk || !url_s) return (PKI_ERR);

	if((url = URL_new( url_s )) == NULL ) {
		return( PKI_ERR );
	}
	URL_free ( url );

	if( PKI_TOKEN_login( tk ) != PKI_OK ) {
		return PKI_ERR;
	}

	if((p12 = PKI_TOKEN_get_p12 ( tk, cred )) == NULL ) {
		return ( PKI_ERR );
	}

	if( PKI_X509_PKCS12_put( p12, format, url_s, NULL,
						cred, tk->hsm ) == PKI_ERR ) {
		PKI_X509_PKCS12_free ( p12 );
		return ( PKI_ERR );
	}
	
	PKI_X509_PKCS12_free ( p12 );

	return ( PKI_OK );
}

/*! \brief Returns a PKI_X509_PKCS12 data structure from the PKI_TOKEN */
PKI_X509_PKCS12 *PKI_TOKEN_get_p12 ( PKI_TOKEN *tk, PKI_CRED *cred ) {

	PKI_X509_PKCS12_DATA *data = NULL;
	PKI_X509_PKCS12 *p12 = NULL;

	if((data = PKI_X509_PKCS12_DATA_new()) == NULL ) {
		return ( NULL );
	}

	if( PKI_TOKEN_login( tk ) != PKI_OK ) {
		return PKI_ERR;
	}

	if(PKI_X509_PKCS12_DATA_add_keypair( data, tk->keypair, cred ) == PKI_ERR) {
		PKI_X509_PKCS12_DATA_free ( data );
		return ( NULL );
	}

	if (PKI_X509_PKCS12_DATA_add_certs ( data, tk->cert, tk->cacert,
			tk->trustedCerts, cred ) == PKI_ERR ) {
		PKI_X509_PKCS12_DATA_free ( data );
		return ( NULL );
	}

	if ( tk->otherCerts ) {
		if( PKI_X509_PKCS12_DATA_add_other_certs ( data, 
					tk->otherCerts, cred ) == PKI_ERR ) {
			PKI_X509_PKCS12_DATA_free ( data );
			return ( NULL );
		}
	}

	if((p12 = PKI_X509_PKCS12_new ( data, cred )) == NULL ) {
		PKI_X509_PKCS12_DATA_free ( data );
		return ( NULL );
	}

	PKI_X509_PKCS12_DATA_free ( data );

	return ( p12 );
}

/*!
 * \brief Exports the Token's certificate to a url passed as a string
 */

int PKI_TOKEN_export_cert ( PKI_TOKEN *tk, char *url_string, PKI_DATA_FORMAT format ) {

	if( !tk || !tk->cert || !url_string ) return ( PKI_ERR );

	if (!PKI_TOKEN_is_logged_in(tk) && !PKI_TOKEN_login(tk)) {
		// Error Condition
		return PKI_ERROR(PKI_ERR_HSM_LOGIN, NULL);
	}

	// if( !tk->cred ) tk->cred = PKI_TOKEN_cred_get ( tk, NULL );

	return PKI_X509_CERT_put( tk->cert, format, url_string, 
						NULL, tk->cred, tk->hsm );
}

/*!
 * \brief Exports the Token's KeyPair to the passed external URI (string)
 */

int PKI_TOKEN_export_keypair ( PKI_TOKEN *tk, char *url_string, PKI_DATA_FORMAT format ) {

	int ret = PKI_OK;
	URL *url = NULL;

	if (!tk || !tk->keypair) return ( PKI_ERR );

	if (!url_string) url_string = "stdout";

	if ((url = URL_new( url_string )) == NULL ) {
		PKI_ERROR( PKI_ERR_URI_PARSE, url_string);
		return ( PKI_ERR );
	}

	if (!PKI_TOKEN_is_logged_in(tk) && !PKI_TOKEN_login(tk)) {
		// Free Memory
		URL_free( url );
		// Error Condition
		PKI_ERROR(PKI_ERR_TOKEN_LOGIN, NULL);
		return PKI_ERR;
	}

	ret = PKI_TOKEN_export_keypair_url(tk, url, format);

	if (url) URL_free ( url );

	return ret;
}

/*! 
 * \brief Exports the Token's keypair to the passed external URI
 */

int PKI_TOKEN_export_keypair_url( PKI_TOKEN *tk, URL *url, PKI_DATA_FORMAT format ) {

	PKI_MEM *mem = NULL;

	if (!tk || !tk->keypair || !url) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if( PKI_TOKEN_login( tk ) != PKI_OK ) return PKI_ERROR(PKI_ERR_HSM_LOGIN, NULL);

	if ((tk->hsm) && (tk->hsm->type == HSM_TYPE_PKCS11))
	{
		mem = HSM_X509_KEYPAIR_wrap ( tk->keypair, tk->cred );
		if (!mem) return PKI_ERROR(PKI_ERR_GENERAL, "Can not wrap key in a PKI_MEM");
	}
	else
	{
		if ((mem = PKI_MEM_new_null()) == NULL ) return PKI_ERROR(PKI_ERR_OBJECT_CREATE, NULL);

		if ((PKI_X509_put_mem( tk->keypair, format, &mem, tk->cred)) == NULL)
		{
			if ( mem ) PKI_MEM_free ( mem );
			return PKI_ERROR(PKI_ERR_HSM_KEYPAIR_EXPORT, NULL);
		}
	}

	if (URL_put_data_url(url, mem, NULL, NULL, 0, 0, NULL) == PKI_ERR)
		PKI_ERROR(PKI_ERR_URI_WRITE, url->url_s);

	if (mem) PKI_MEM_free(mem);

	return PKI_OK;
}

/*! \brief Export the TOKEN trustedCerts to an external URI
 */

int PKI_TOKEN_export_trustedCerts(PKI_TOKEN *tk, char *url_string, PKI_DATA_FORMAT format) {

	if( !tk || !tk->cert || !url_string ) return ( PKI_ERR );

	if (!tk->isLoggedIn) PKI_TOKEN_login(tk);

	return PKI_X509_CERT_STACK_put ( tk->trustedCerts, format, url_string,
						NULL, tk->cred, tk->hsm );

}

/*! \brief Export the TOKEN otherCerts to an external URI
 */

int PKI_TOKEN_export_otherCerts ( PKI_TOKEN *tk, char *url_string, PKI_DATA_FORMAT format) {

	URL *url = NULL;
	int ret = PKI_OK;

	if( !tk || !tk->cert || !url_string ) return ( PKI_ERR );

	if((url = URL_new( url_string)) == NULL ) {
		return (PKI_ERR);
	}

	ret = PKI_X509_CERT_STACK_put_url( tk->otherCerts, format, url, 
						NULL, tk->cred, tk->hsm);

	if ( url ) URL_free ( url );

	return ( ret );
}

/*! \brief Export the TOKEN request from the Token to an external URI
 */

int PKI_TOKEN_export_req ( PKI_TOKEN *tk, char *url_string, PKI_DATA_FORMAT format ) {

	if( !tk || !url_string ) {
		PKI_log_debug("ERROR, wrong parameters!\n");
		return ( PKI_ERR );
	}

	if( !tk->req ) {
		PKI_log_debug("ERROR, no req to save!\n");
		return ( PKI_ERR );
	}

	if (!tk->isLoggedIn) PKI_TOKEN_login(tk);

	return PKI_X509_REQ_put( tk->req, format, url_string, NULL,
					tk->cred, tk->hsm);

}

/*!
 * \brief Imports a Keypair into the Token
 */

int PKI_TOKEN_import_keypair ( PKI_TOKEN *tk, PKI_X509_KEYPAIR *key,
							char * url_s ) {

	URL *url = NULL;
	// char *myLabel[2048];
	int ret = PKI_OK;

	// Input Checks
	if (!tk || !key || !url_s)
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// Parses the URL
	if ((url = URL_new( url_s )) == NULL)
		return PKI_ERROR(PKI_ERR_URI_PARSE, "Can not parse URI [%s]", url_s);

	// Checks for the Token Login
	if( PKI_TOKEN_login( tk ) != PKI_OK ) return PKI_ERR;

	// Puts (Imports) the Keypair into the URL location
	ret = PKI_X509_KEYPAIR_put_url(key, PKI_DATA_FORMAT_ASN1, url,
			NULL, tk->hsm );

	// Free the memory
	if ( url ) URL_free ( url );

	// All Done
	return ret;
}

/*!
 * \brief Imports a certificate into the Token
 */

int PKI_TOKEN_import_cert ( PKI_TOKEN *tk, PKI_X509_CERT *cert, 
			 	PKI_DATATYPE type, char *url_s ) {

	int ret = PKI_OK;
	URL *url = NULL;
	char myLabel[2048];

	if (!tk || !cert || !url_s)
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if ((url = URL_new( url_s )) == NULL)
		return PKI_ERROR(PKI_ERR_URI_PARSE, "Can not parse URI [%s]", url_s);

	if( url->proto == URI_PROTO_ID ) {

		memset(myLabel, 0x0, sizeof(myLabel));
        	strncpy(myLabel, url->addr, sizeof(myLabel) - 1);

		switch( type ) {
			case PKI_DATATYPE_X509_CERT:
				strncat( myLabel, "'s ID", sizeof(myLabel) - 1);
				break;
			case PKI_DATATYPE_X509_CA:
				strncat( myLabel, "'s CA Cert",
							sizeof(myLabel) - 1);
				break;
			case PKI_DATATYPE_X509_OTHER:
				strncat( myLabel, "'s Other Cert", 
							sizeof(myLabel) - 1);
				break;
			case PKI_DATATYPE_X509_TRUSTED:
				strncat( myLabel, "'s Trusted Cert", 
							sizeof(myLabel) - 1);
				break;
			default:
				if ( url ) URL_free ( url );
				return ( PKI_ERR );
		}

		if( url->addr ) PKI_Free ( url->addr );
		url->addr = strdup ( myLabel );
	}

	ret = PKI_X509_CERT_put_url ( cert, PKI_DATA_FORMAT_ASN1, url,
			NULL, tk->cred, tk->hsm );

	if ( url ) URL_free ( url );

	return ( ret );
}

/*!
 * \brief Imports a stack of certificates into the Token
 */

int PKI_TOKEN_import_cert_stack ( PKI_TOKEN *tk, PKI_X509_CERT_STACK *sk, 
				  PKI_DATATYPE type, char *url_s ) {

	int ret = PKI_OK;
	URL *url = NULL;
	char myLabel[2048];

	if (!tk || !sk || !url_s)
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if ((url = URL_new( url_s )) == NULL)
		return PKI_ERROR(PKI_ERR_URI_PARSE, "Can not parse URI [%s]", url_s);

	if( url->proto == URI_PROTO_ID ) {

		memset(myLabel, 0x0, sizeof(myLabel));
        	strncpy(myLabel, url->addr, sizeof(myLabel) - 1);

		switch( type ) {
			case PKI_DATATYPE_X509_CERT:
				strncat( myLabel, "'s ID", sizeof(myLabel) - 1);
				break;
			case PKI_DATATYPE_X509_CA:
				strncat( myLabel, "'s CA Cert",
							sizeof(myLabel) - 1);
				break;
			case PKI_DATATYPE_X509_OTHER:
				strncat( myLabel, "'s Other Cert", 
							sizeof(myLabel) - 1);
				break;
			case PKI_DATATYPE_X509_TRUSTED:
				strncat( myLabel, "'s Trusted Cert", 
							sizeof(myLabel) - 1);
				break;
			default:
				if ( url ) URL_free ( url );
				return ( PKI_ERR );
		}

		if( url->addr ) PKI_Free ( url->addr );
		url->addr = strdup ( myLabel );
	}

	ret = PKI_X509_STACK_put_url(sk, PKI_DATA_FORMAT_ASN1,
		url, NULL, tk->cred, tk->hsm );

	if ( url ) URL_free ( url );

	return ( ret );
}

/* TOKEN operations */

/*! \brief Generate a new CRL from a stack of revoked entries by using
 *         the provided token
 *
 * Generates a new signed CRL from a stack of revoked entries. If a profile
 * passed, it is used to set the right extensions in the CRL. To generate a
 * new revoked entry the PKI_X509_CRL_ENTRY_new() function has to be used.
 */
PKI_X509_CRL * PKI_TOKEN_issue_crl (const PKI_TOKEN 			   * tk,           /* signing token */
									const char 					   * const serial, /* crlNumber */ 
									const long long 				 thisUpdate    /* offset */,
									const long long 				 nextUpdate    /* offset */, 
									const PKI_X509_CRL_ENTRY_STACK * const sk,     /* stack of rev */
									const PKI_X509_EXTENSION_STACK * const exts,   /* stack of crl exts */
									const char 					   * profile_s ) {

	PKI_X509_CRL *crl = NULL;
	PKI_X509_PROFILE *profile = NULL;

	if( !tk ) return ( NULL );

	if( profile_s ) {
		profile = PKI_TOKEN_search_profile( tk, profile_s );
		
		/*
		if( tk->profiles  != NULL ) {
			for( i=0; i < PKI_STACK_X509_PROFILE_elements(tk->profiles);i++) {
				tmp_profile = PKI_STACK_X509_PROFILE_get_num (
                                                        tk->profiles, i );
				prof_name = PKI_X509_PROFILE_get_name( tmp_profile );
				if( !prof_name ) {
					continue;
				};

				if( strcmp_nocase( profile_s, prof_name ) == 0 ) {
					profile = tmp_profile;
					break;
				}
			}
		}
		*/

		if( !profile ) {
			/* Error, the requested profile does not exists! */
			PKI_log_debug("ERROR, no matching profile found (%s)!\n",
				profile_s);
			return NULL;
		};
	};

	// Checks if the Token is in a good logged in status
	if (PKI_TOKEN_is_logged_in(tk) == PKI_ERR) {
		PKI_ERROR(PKI_ERR_TOKEN_NOT_LOGGED_IN, NULL);
		return NULL;
	}

	// // 
	// if (PKI_TOKEN_login( tk ) != PKI_OK ) {
	// 	return NULL;
	// }

	// if( !tk->cred ) {
	// 	tk->cred = PKI_TOKEN_cred_get ( tk, NULL );
	// };

	crl = PKI_X509_CRL_new(tk->keypair,
						   tk->cert,
						   serial,
						   thisUpdate, 
						   nextUpdate,
						   sk,
						   exts,
						   profile,
						   tk->oids,
						   tk->hsm );

	return crl;
}

/*!
 * \brief Generates a new PKI_X509_REQ object
 */

int PKI_TOKEN_new_req(PKI_TOKEN *tk, char *subject, char *profile_s ) {

	PKI_X509_PROFILE *req_profile = NULL;
		// Profile pointer

	// Input checks
	if( !tk || !tk->keypair ) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return (PKI_ERR);
	}

	// Logs into the token (if not already logged)
	if (!tk->isLoggedIn && PKI_TOKEN_login(tk) != PKI_OK) {
		return PKI_ERR;
	}

	// If we have a request already, let's free it
	if( tk->req ) {
		PKI_X509_REQ_free ( tk->req );
		tk->req = NULL; // Security
	}

	// Loads the profile
	if( profile_s ) {
		if((req_profile = PKI_TOKEN_search_profile(tk, profile_s)) == NULL) {
			PKI_ERROR(PKI_ERR_CONFIG_MISSING, profile_s);
			return PKI_ERR;
		};
	};

	// Generates a new Request and saves it to the token
	tk->req = PKI_X509_REQ_new( tk->keypair, subject, req_profile,
			tk->oids, tk->digest, tk->hsm ); 

	// Error condition check
	if (!tk->req) return PKI_ERR;

	// All Done
	return PKI_OK;
}


int PKI_TOKEN_set_req( PKI_TOKEN *tk, PKI_X509_REQ *req ) {
	if (!tk || !req ) return (PKI_ERR);

	tk->req = req;

	return (PKI_OK);
}

int PKI_TOKEN_del_url ( PKI_TOKEN *tk, URL *url, PKI_DATATYPE datatype ) {

	if( !tk || !url ) return ( PKI_ERR );

	return HSM_X509_del_url ( datatype, url, tk->cred, tk->hsm );
}

/*!
 * \brief Returns a named profile from the loaded ones
 */

PKI_X509_PROFILE *PKI_TOKEN_search_profile(const PKI_TOKEN * const tk, const char * const profile_s ) {

	PKI_X509_PROFILE *tmp_profile = NULL;
	PKI_X509_PROFILE *ret = NULL;
	char *prof_name = NULL;
	int i = 0;

	if( !tk || !tk->profiles || !profile_s )
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	for( i=0; i < PKI_STACK_X509_PROFILE_elements( tk->profiles ); i++)
	{
		tmp_profile = PKI_STACK_X509_PROFILE_get_num(tk->profiles, i);

		if((prof_name = PKI_X509_PROFILE_get_name( tmp_profile )) == NULL) 
			continue;

		if( strcmp_nocase( profile_s, prof_name ) == 0 )
		{
			ret = tmp_profile;
			break;
		}
	}

	return (ret);

}

int PKI_TOKEN_self_sign (PKI_TOKEN *tk, char *subject, char *serial,
				unsigned long validity, char *profile_s ) {

	PKI_X509_PROFILE *cert_profile = NULL;

	if (!tk || !tk->keypair)
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if (PKI_OK != PKI_TOKEN_login(tk))
		return PKI_ERROR(PKI_ERR_TOKEN_LOGIN, NULL);

	if (tk->cert) {
		/* ERROR, a Token Certificate already exists! */
		PKI_log(PKI_LOG_WARNING, "A cert already exists in token when "
					 "calling PKI_TOKEN_self_sign()!");
		PKI_X509_CERT_free ( tk->cert );
	}

	if( profile_s ) {
		if((cert_profile = PKI_TOKEN_search_profile (tk, profile_s ))
							== NULL) {;

			/* Error, the requested profile does not
			   exists! */
			PKI_log_err("Requested profile (%s) not found when self-signing cert!\n", profile_s);
			return (PKI_ERR);
		}
	}

	// if (!tk->isLoggedIn) PKI_TOKEN_login(tk);
	// // if (!tk->cred ) tk->cred = PKI_TOKEN_cred_get(tk, NULL );

	if (!serial) serial = "0";

	tk->cert = PKI_X509_CERT_new ( NULL, tk->keypair, tk->req, subject,
		serial, validity, cert_profile, tk->algor, tk->oids, tk->hsm );

	if (!tk->cert) return PKI_ERROR(PKI_ERR_X509_CERT_CREATE, NULL);

	return (PKI_OK);
}

PKI_X509_CERT * PKI_TOKEN_issue_cert(PKI_TOKEN *tk, char *subject, char *serial,
		unsigned long validity, PKI_X509_REQ *req, char *profile_s ) {

	PKI_X509_PROFILE *cert_profile = NULL;

	if (!tk || !tk->keypair) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	if (PKI_TOKEN_login(tk) != PKI_OK) {
		PKI_ERROR(PKI_ERR_TOKEN_LOGIN, NULL);
		return NULL;
	}

	if( !tk->cert ) {
		/* ERROR, a Token Certificate already exists! */
		PKI_ERROR(PKI_ERR_X509_CERT_CREATE,
			"No certificate available in signing token!");
		return NULL;
	}

	if( profile_s ) {
		if((cert_profile = PKI_TOKEN_search_profile (tk, profile_s ))
							== NULL) {
			PKI_DEBUG("Can not find requested profile (%s)", profile_s);
			return NULL;
		}
	}

	if( !req ) req = tk->req;

	// // if( !tk->cred ) {
	// // 	tk->cred = PKI_TOKEN_cred_get ( tk, NULL );
	// // }
	// if (!tk->isLoggedIn) PKI_TOKEN_login(tk);

	return PKI_X509_CERT_new (tk->cert, tk->keypair, req, subject,
			serial, validity, cert_profile, tk->algor, 
				tk->oids, tk->hsm );
}

PKI_TOKEN *PKI_TOKEN_issue_proxy (PKI_TOKEN *tk, char *subject, 
		char *serial, unsigned long validity, 
			char *profile_s, PKI_TOKEN *px_tk ) {

	unsigned char serBuf[10];
	char *proxySubject = NULL;
	char *proxySerial = NULL;
	char *proxyProfile_s = NULL;
	char *name = NULL;
	int i = 0;

	if( PKI_TOKEN_login( tk ) != PKI_OK ) {
		return PKI_ERR;
	}

	if ( !tk || !tk->keypair || !tk->cert ) return ( NULL );

	if (!subject) {
		subject = "CN=Proxy";
	}

	if(!serial) {
		PKI_INTEGER *asn1_integer = NULL;

		RAND_bytes( serBuf, sizeof(serBuf));
		asn1_integer = PKI_INTEGER_new_bin( serBuf, sizeof(serBuf));

		proxySerial = PKI_INTEGER_get_parsed( asn1_integer );
	}

	if( validity <= 0 ) {
		validity = 60;
	}

	if( !px_tk ) {
		px_tk = PKI_TOKEN_new_null();
		// PKI_log_err("ERROR::Proxy Token needed in"
		// 			" PKI_TOKEN_issue_proxy()");
		if(!px_tk ) return ( PKI_ERR );
	}

	if( !px_tk->keypair ) {
		PKI_TOKEN_new_keypair( px_tk, 2048, NULL );
	}

	if((name = PKI_X509_CERT_get_parsed(tk->cert, 
				PKI_X509_DATA_SUBJECT)) == NULL ) {
		PKI_log_debug("ERROR::No subject from issuing Cert!");
		return ( PKI_ERR );
	}

	if( !profile_s ) {
		PKI_X509_PROFILE *profile = NULL;

		profile = PKI_X509_PROFILE_get_default(PKI_X509_PROFILE_PROXY);

		PKI_TOKEN_add_profile ( tk, profile );
		proxyProfile_s = PKI_PROFILE_DEFAULT_PROXY_NAME;
	} else {
		proxyProfile_s = profile_s;
	}

	if( !px_tk->req ) {
		PKI_TOKEN_new_req ( px_tk, name, profile_s );
	}

	if( subject ) {
		size_t subjectSize = 0;

		/* The new name is equal to the old one + ", CN=..." */
		subjectSize = strlen(name) + 5 + strlen(subject) + 1;
		proxySubject = PKI_Malloc( subjectSize );
		
		snprintf(proxySubject, subjectSize, "%s, %s",
					name, subject );
	} else {
		size_t subjectSize = 0;

		/* The new name is equal to the old one + ", CN=Proxy" */
		subjectSize = strlen(name) + 5 + 5 + 1;
		proxySubject = PKI_Malloc( subjectSize );

		snprintf(proxySubject, subjectSize, "%s, CN=Proxy", name );
	}

	/* Let's free the name */
	if(name) PKI_Free ( name );

	if((px_tk->cert = PKI_TOKEN_issue_cert (tk, proxySubject, 
		    			proxySerial, validity, px_tk->req, 
						proxyProfile_s )) == NULL ) {
                printf("ERROR, can not issue Proxy Certificate!\n");
                exit(1);
        }

	/* Now We have to copy all the other certs to the new token */
	px_tk->cacert = PKI_X509_CERT_dup ( PKI_TOKEN_get_cert ( tk ) );

	/* Adds the trustedCerts to the Proxy Token */
	if ( !px_tk->trustedCerts ) {
		if((px_tk->trustedCerts = PKI_STACK_X509_CERT_new()) == NULL ) {
			PKI_log_err("%s:%d::Memory Error");
		}
	}
	for(i=0;i<PKI_STACK_X509_CERT_elements( tk->trustedCerts ); i++ ) {
		PKI_X509_CERT *x = NULL;

		x = PKI_STACK_X509_CERT_get_num( tk->trustedCerts, i );
		PKI_STACK_X509_CERT_push( px_tk->trustedCerts, 
						PKI_X509_CERT_dup ( x ) );
	}

	/* Adds the Other Certs stack to the Proxy Token */
	if ( !px_tk->otherCerts ) {
		if((px_tk->otherCerts = PKI_STACK_X509_CERT_new()) == NULL ) {
			PKI_log_err("%s:%d::Memory Error");
		}
	}
	for(i=0;i<PKI_STACK_X509_CERT_elements( tk->otherCerts ); i++ ) {
		PKI_X509_CERT *x = NULL;

		x = PKI_STACK_X509_CERT_get_num( tk->otherCerts, i );
		PKI_STACK_X509_CERT_push( px_tk->otherCerts, 
						PKI_X509_CERT_dup ( x ) );
	}


	if( !serial ) {
		if(proxySerial) PKI_Free ( proxySerial );
	}

	if ( proxySubject ) PKI_Free ( proxySubject );

	return ( px_tk );
}

int PKI_TOKEN_clear_profiles(PKI_TOKEN * tk) {

	if (!tk) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if (tk->profiles) {
		PKI_STACK_X509_PROFILE_free_all(tk->profiles);
		tk->profiles = NULL;
	}

	return PKI_OK;
}

int PKI_TOKEN_load_profiles ( PKI_TOKEN *tk, char *urlStr )
{
	struct dirent *dd = NULL;
	DIR *dirp = NULL;
	URL *url = NULL;
	char * fullpath = NULL;

	/* Check input */
	if (!tk || !urlStr) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if ((url = URL_new(urlStr)) == NULL ) return PKI_ERROR(PKI_ERR_URI_PARSE, urlStr);

	if (tk->profiles == NULL)
	{
		if ((tk->profiles = PKI_STACK_X509_PROFILE_new()) == NULL)
		{
			if (url) URL_free (url);
			return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		}
	}

	if (url->proto != URI_PROTO_FILE)
	{
		if (url) URL_free(url);
		PKI_ERROR(PKI_ERR_CONFIG_LOAD, "only file:// is currently supported for profiles loading!");
		return PKI_ERR;
	}

	if ((dirp = opendir(url->addr)) == NULL)
	{
		if (url) URL_free(url);
		// return PKI_ERROR(PKI_ERR_CONFIG_LOAD, "Can not open directory %s!", url->addr ? url->addr : "<null>" );
		return PKI_ERR;
	}
	else
	{
		while(( dd = readdir( dirp )) != NULL)
		{
			size_t len;
			char *filename = NULL;

			filename = dd->d_name;
			len = strlen( filename );

			if (strcmp( ".xml", filename +len - 4)) continue;
			else
			{
				size_t fullsize = 0;

				fullsize = strlen(url->addr) + strlen( filename ) + 2;

				if ((fullsize = strlen(url->addr) + strlen( filename ) + 2) > BUFF_MAX_SIZE)
				{
					PKI_log_debug("ERROR, filename too long!\n");
					continue;
				}
				
				if((fullpath = PKI_Malloc(fullsize)) == NULL)
				{
					PKI_log_debug("ERROR, name too long!\n");
					continue;
				}

				snprintf(fullpath, fullsize, "%s/%s", url->addr, filename );

				PKI_TOKEN_add_profile(tk, PKI_X509_PROFILE_load ( fullpath ));

				PKI_Free ( fullpath );
				fullpath = NULL;
			}
		}
		closedir( dirp );
	}

	if( url ) URL_free (url);

	return (PKI_OK);
}

int PKI_TOKEN_add_profile( PKI_TOKEN *tk, PKI_X509_PROFILE *profile )
{
	if (!tk || !profile ) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if(tk->profiles == NULL)
	{
		if((tk->profiles = PKI_STACK_X509_PROFILE_new()) == NULL)
		{
			PKI_log_debug("ERROR, can not create a new PROFILE STACK!");
			return (PKI_ERR);
			}
	}

	PKI_STACK_X509_PROFILE_ins_num(tk->profiles, 0, profile);
	// PKI_STACK_X509_PROFILE_push( tk->profiles, profile );

	return ( PKI_OK );
}


int PKI_TOKEN_print_info ( PKI_TOKEN *tk ) {

	if (!tk) return ( PKI_ERR );

	HSM_SLOT_INFO_print ( (unsigned long) tk->slot_id, tk->cred, tk->hsm );

	// // if( !tk->cred ) {
	// // 	tk->cred = PKI_TOKEN_cred_get ( tk, NULL );
	// // }

	// // Log in into the Token
	// if (!tk->isLoggedIn) PKI_TOKEN_login(tk);

	if ( tk->hsm && tk->hsm->callbacks && 
				tk->hsm->callbacks->slot_info_get ) {
		tk->hsm->callbacks->slot_info_get( (unsigned long) 
				tk->slot_id, tk->hsm );
	}

	return ( PKI_OK );
}

/*
int PKI_TOKEN_set_cert_profile( PKI_TOKEN *tk, PKI_X509_PROFILE *cert_prof ) {
	return PKI_ERR;
}
int PKI_TOKEN_set_req_profile( PKI_TOKEN *tk, PKI_X509_PROFILE *req_prof ) {
	return PKI_ERR;
}
*/


