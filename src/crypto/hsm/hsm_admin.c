/* HSM Object Management Functions */

#include <libpki/crypto/hsm/hsm_admin.h>

/*!
 * \brief Initializes the HSM
 */
int CRYPTO_HSM_driver_new(HSM * hsm) {

	if (!hsm) return PKI_ERR;

	/* Call the init function provided by the hsm itself */
	if (hsm->admin_callbacks->new) {
		return hsm->admin_callbacks->new(&hsm->driver, hsm->config);
	}

	return PKI_OK;
}

/*!
 * \brief Initializes the HSM
 */
int CRYPTO_HSM_init( HSM *hsm ) {

	if( !hsm || !hsm->admin_callbacks ) return (PKI_ERR);

	/* Call the init function provided by the hsm itself */
	if( hsm->admin_callbacks->init )
	{
		return (hsm->admin_callbacks->init(hsm, hsm->config ));
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
 * \brief Initializes the HSM
 */
int CRYPTO_HSM_driver_free(HSM * hsm) {

	if (!hsm) return PKI_ERR;

	/* Call the init function provided by the hsm itself */
	if (hsm->driver && hsm->admin_callbacks->free) {
		int ret = hsm->admin_callbacks->free(hsm->driver);
		hsm->driver = NULL;
		return ret;
	}

	return PKI_OK;
}


/* -------------------------- Access control to HSM ----------------------- */

int CRYPTO_HSM_login ( HSM *hsm, PKI_CRED *cred ) {

	if (!hsm) return (PKI_ERR);

	if ( hsm->admin_callbacks->login ) {
		return ( hsm->admin_callbacks->login(hsm, cred ));
	} else {
		/* No login required by the HSM */
		PKI_log_debug("No login function for selected HSM");
	}

	return ( PKI_OK );
}

int CRYPTO_HSM_logout ( HSM *hsm ) {

	if (!hsm || !hsm->admin_callbacks ) return (PKI_ERR);

	if ( hsm->admin_callbacks && hsm->admin_callbacks->logout ) {
		return ( hsm->admin_callbacks->logout( hsm ));
	} else {
		/* No login required by the HSM */
		PKI_log_debug("No login function for selected HSM");
	}

	return ( PKI_OK );
}


/* -------------------------- FIPS mode for HSM ----------------------- */

int CRYPTO_HSM_set_fips_mode(const HSM *hsm, int enabled)
{
	if (!hsm) hsm = HSM_get_default();
	if (!hsm) return PKI_ERR;

	if (hsm->admin_callbacks && hsm->admin_callbacks->set_fips_mode)
	{
		return hsm->admin_callbacks->set_fips_mode(hsm, (enabled > 0 ? 1 : 0));
	}
	else
	{
		// If no FIPS mode is available, let's return 0 (false)
		return PKI_ERR;
	}
}

int CRYPTO_HSM_is_fips_mode(const HSM *hsm)
{
	if (!hsm) hsm = HSM_get_default();
	if (!hsm) return PKI_ERR;

	if (hsm->admin_callbacks && hsm->admin_callbacks->is_fips_mode)
	{
		return hsm->admin_callbacks->is_fips_mode(hsm);
	}
	else
	{
		return PKI_ERR;
	}
}

/* -------------------------- General Crypto HSM ----------------------- */

int CRYPTO_HSM_set_sign_algor(PKI_TYPE alg, HSM *hsm) {

	int ret = PKI_OK;

	// Input Checks
	if (!alg) {
		PKI_DEBUG("No algorithm passed!");
		return PKI_ERR;
	}

	// Sets the algorithm if it is an hardware token
	if (hsm && hsm->admin_callbacks && hsm->admin_callbacks->sign_algor) {

		// Using the HSM callback
		PKI_log_debug("Setting the signature algorithm for selected HSM");
		ret = hsm->admin_callbacks->sign_algor(hsm, alg);
	}

	// All Done
	return (ret);
}


