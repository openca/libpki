/* openssl_hsm_admin.c */

// Single Include
#include <libpki/crypto/hsm/openssl/openssl_hsm_admin.h>

/* Structure for the OpenSSL's Software Token definition */
HSM openssl_hsm = {

	/* Version of the token */
	1,

	/* Description of the HSM */
	"OpenSSL Software HSM",

	/* Manufacturer */
	"OpenSSL Project",

	/* Pointer to the HSM config file and parsed structure*/
	NULL, 

	/* One of PKI_HSM_TYPE value */
	HSM_TYPE_SOFTWARE,

	/* URL for the ID of the driver, this is filled at load time */
	NULL,

	/* Pointer to the driver structure */
	NULL,

	/* Pointer to internal session handler */
	NULL,

	/* Credential for the HSM - usually used for the SO */
	NULL,

	/* is Logged In ? */
	0,

	/* is Cred Set ? */
	0,

	/* is Login Required ? */
	0,

	/* Callbacks Structures */
	NULL,
	NULL,
	NULL
};

					// =================================
					// OpenSSL HSM Admin Callbacks Table
					// =================================

const HSM_ADMIN_CALLBACKS openssl_hsm_admin_cb = {
	HSM_OPENSSL_new_driver, // new
	HSM_OPENSSL_init, // init
	HSM_OPENSSL_free_driver, // free
	NULL, // login
	NULL, // logout
	NULL, // signature_algor
	HSM_OPENSSL_set_fips_mode, // set_fips_mode
	HSM_OPENSSL_is_fips_mode,  // is_fips_mode
};

					// ==============================
					// Admin Callbacks Implementation
					// ==============================

const HSM * HSM_OPENSSL_get_default( void )
{
	return ((const HSM *)&openssl_hsm);
}

int HSM_OPENSSL_new_driver(void **driver) {

	if (!driver) {
		return (PKI_ERR);
	}

	// We should get the OpenSSL's Library CTX and set it
	// for the HSM driver
	OSSL_LIB_CTX *libctx = NULL;
	if ((libctx = OSSL_LIB_CTX_new()) == NULL) {
		return PKI_ERR;
	}

	*driver = (void *)libctx;

	return PKI_OK;
}

int HSM_OPENSSL_free_driver(void *driver) {

	if (!driver) {
		return (PKI_ERR);
	}

	OSSL_LIB_CTX_free((OSSL_LIB_CTX *)driver);

	return PKI_OK;
}

int HSM_OPENSSL_init(HSM *driver, PKI_CONFIG *conf) {

	if (!driver) {
		return (PKI_ERR);
	}

#if OPENSSL_VERSION_NUMBER >= 0x3000000fL
	// Initializes the OQS Provider layer
	PKI_init_providers();
#endif

	// OpenSSL init
	X509V3_add_standard_extensions();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();
	OpenSSL_add_all_ciphers();

	// Pthread Initialization
	OpenSSL_pthread_init();

	// Initializes the SSL layer
	SSL_library_init();

	/* No need for initialization of the software driver */
	return PKI_OK;
}

/*!
 * \brief Sets the fips operation mode when the parameter is != 0,
 * otherwise it sets the HSM in non-fips mode
 */
int HSM_OPENSSL_set_fips_mode(const HSM *driver, int k) {

#ifdef OPENSSL_FIPS
    return (FIPS_mode_set(k) == 1 ? PKI_OK : PKI_ERR);
#else
    return PKI_ERR;
#endif

}

/*!
 * \brief Returns 0 if HSM is operating in non-FIPS mode, true (!0) if FIPS
 * mode is enabled.
 */
int HSM_OPENSSL_is_fips_mode(const HSM *driver)
{
#ifdef OPENSSL_FIPS
    return (FIPS_mode() == 0 ? PKI_ERR : PKI_OK);
#else
    return PKI_ERR;
#endif

}

/* ----------------------- General Signing function -------------------- */

// PKI_MEM * HSM_OPENSSL_sign(PKI_MEM * der, PKI_DIGEST_ALG * digest, PKI_X509_KEYPAIR *key) {

// 	EVP_MD_CTX *ctx = NULL;
// 		// Digest's context

// 	size_t out_size = 0;
// 	// size_t ossl_ret = 0;

// 	PKI_MEM *out_mem = NULL;
// 		// Output buffer

// 	EVP_PKEY *pkey = NULL;
// 		// Signing Key Value

// 	int digestResult = -1;
// 	int def_nid = NID_undef;
// 		// OpenSSL return value

// 	if (!der || !der->data || !key || !key->value)
// 	{
// 		PKI_ERROR( PKI_ERR_PARAM_NULL, NULL);
// 		return NULL;
// 	}

// 	// Private Key
// 	pkey = PKI_X509_get_value(key);
// 	if (!pkey) {
// 		PKI_ERROR(PKI_ERR_PARAM_NULL, "Cannot retrieve the internal value of the key (PKEY).");
// 		return NULL;
// 	}

// 	// Get the Maximum size of a signature
// 	out_size = (size_t) EVP_PKEY_size(pkey);

// 	// Gets the default digest for the key
// 	digestResult = EVP_PKEY_get_default_digest_nid(pkey, &def_nid);

// 	// PKI_DEBUG("Requested Digest for Signing is %s", digest ? PKI_ID_get_txt(EVP_MD_nid(digest)) : "NULL");
// 	// PKI_DEBUG("Checking Default Digest for PKEY %d (%s) is %d (%s) (result = %d)",
// 	// 	EVP_PKEY_id(pkey), PKI_ID_get_txt(EVP_PKEY_id(pkey)), def_nid, PKI_ID_get_txt(def_nid), digestResult);

// 	// Checks for error
// 	if (digest == NULL && digestResult <= 0) {
// 		PKI_DEBUG("Cannot get the default digest for signing key (type: %d)", EVP_PKEY_id(pkey));
// 		return NULL;
// 	}

// 	// If the returned value is == 2, then the returned
// 	// digest is mandatory and cannot be replaced
// 	if (digestResult == 2 && def_nid != EVP_MD_nid(digest)) {
// 		// // Checks if we are in a no-hash mandatory
// 		// if (def_nid == NID_undef && (digest != EVP_md_null() && digest != NULL)) {
// 		// 	PKI_DEBUG("PKEY requires no hash but got one (%d)", EVP_MD_nid(digest));
// 		// 	return NULL;
// 		// }
// 		// // Checks if we are using the mandated digest
// 		// if ((digest != NULL && def_nid != NID_undef) || (def_nid != EVP_MD_nid(digest))) {
// 		// 	PKI_DEBUG("PKEY requires digest (%d) but got (%d)", def_nid, EVP_MD_nid(digest));
// 		// 	return NULL;
// 		// }
// 		PKI_DEBUG("PKEY requires %s digest (mandatory) and cannot be used with %s digest (requested).",
// 			def_nid == NID_undef ? "NO" : PKI_ID_get_txt(def_nid), 
// 			digest == NULL ? "NO" : PKI_ID_get_txt(EVP_MD_nid(digest)));
// 		return NULL;
// 	}

// 	// Initialize the return structure
// 	if ((out_mem = PKI_MEM_new ((size_t)out_size)) == NULL) {
// 		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
// 		return NULL;
// 	}

// 	// Creates the context
// 	if ((ctx = EVP_MD_CTX_create()) == NULL) {
// 		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
// 		goto err;
// 	}

// 	// Initializes the Context
// 	EVP_MD_CTX_init(ctx);

// 	// PKI_DEBUG("MD (digest) = %p (EVP_md_null = %p) (EVP_md_null() ==> %d)", 
// 	// 	digest, EVP_md_null, EVP_md_null() == digest);

// 	// DEBUG
// 	// PKI_DEBUG("MD (digest) in DigestSignInit: %d (%s)", 
// 	// 	digest ? EVP_MD_nid(digest) : NID_undef, digest ? PKI_DIGEST_ALG_get_parsed(digest) : "<NULL>");

// 	// Initializes the Digest and does special processing for when the 
// 	// EVP_md_null() is used to indicate that the NO HASH was requested
// 	if (!EVP_DigestSignInit(ctx, NULL /* &pctx */, EVP_md_null() == digest ? NULL : digest, NULL, pkey)) {
// 		PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, "Cannot Initialize EVP_DigestSignInit()");
// 		goto err;
// 	}

// 	if (EVP_DigestSign(ctx, out_mem->data, &out_size, der->data, der->size) <= 0) {
// 		PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, "Cannot generate signature via EVP_DigestSign()");
// 		goto err;
// 	}
	
// 	// Update the size of the signature
// 	out_mem->size = (size_t) out_size;

// 	// // Updates the Digest calculation with the TBS data
// 	// if (EVP_DigestSignUpdate(ctx, 
// 	// 						 der->data,
// 	// 						 der->size) <= 0) {
// 	// 	PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, "Cannot Update EVP_DigestSignUpdate()");
// 	// 	goto err;
// 	// }

// 	// // Finalize the MD
// 	// // EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_FINALISE);

// 	// // Finalizes the Signature calculation and saves it in the output buffer
// 	// if (EVP_DigestSignFinal(ctx,
// 	// 						out_mem->data,
// 	// 						&out_size) <= 0) {
// 	// 	PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, "Cannot Finalize EVP_DigestSignFinal()");
// 	// 	goto err;
// 	// }
// 	// else out_mem->size = (size_t) out_size;

// 	// All Done
// 	goto end;

// err:

// 	// Error Condition, free the output's memory
// 	if (out_mem) PKI_MEM_free(out_mem);
// 	out_mem = NULL;

// end:
// 	// Cleanup the context
// #if OPENSSL_VERSION_NUMBER <= 0x1010000f
// 	if (ctx) EVP_MD_CTX_cleanup(ctx);
// #else
// 	if (ctx) EVP_MD_CTX_reset(ctx);
// #endif

// 	// Frees the CTX structure
// 	if (ctx) EVP_MD_CTX_destroy(ctx);

// 	// Returns the result or NULL
// 	return out_mem;
// }



/* -------------------- OPENSSL Callbacks Management Functions ------------- */

