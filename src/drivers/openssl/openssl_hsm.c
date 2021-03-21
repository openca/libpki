/* HSM Object Management Functions */

#include <strings.h>
#include <libpki/pki.h>
#include <libpki/hsm_st.h>

/* Callbacks for Software OpenSSL HSM */
const HSM_CALLBACKS openssl_hsm_callbacks = {
		/* Errno */
		HSM_OPENSSL_get_errno,
		/* Err Descr */
		HSM_OPENSSL_get_errdesc,
		/* Init */
		HSM_OPENSSL_init,
		/* Free */
		HSM_OPENSSL_free,
		/* Login */
		NULL,
		/* Logout */
		NULL,
		/* Set Algorithm */
		NULL, /* HSM_OPENSSL_algor_set, */
		/* Set fips mode */
		HSM_OPENSSL_set_fips_mode, 
		/* Fips operation mode */
		HSM_OPENSSL_is_fips_mode, 
		/* General Sign */
		HSM_OPENSSL_sign,
		/* General Verify */
		NULL, /* HSM_OPENSSL_verify, */
		/* Key Generation */
		HSM_OPENSSL_X509_KEYPAIR_new,
		/* Free Keypair Function */
		HSM_OPENSSL_X509_KEYPAIR_free,
		/* Key Wrapping */
		NULL, // HSM_OPENSSL_X509_KEYPAIR_STACK_wrap,
		/* Key Unwrapping */
		NULL, // HSM_OPENSSL_X509_KEYPAIR_STACK_unwrap,
		/* Obj Load Function */
		NULL, // HSM_OPENSSL_X509_STACK_get_url,
		/* Obj Add Function */
		NULL, // HSM_OPENSSL_X509_STACK_put_url,
		/* Obj Del Function */
		NULL, /* HSM_OPENSSL_X509_STACK_del_url */
		/* Get the number of available Slots */
		NULL, // HSM_OPENSSL_SLOT_num,
		/* Get Slot info */
		HSM_OPENSSL_SLOT_INFO_get,
		/* Free Slot info */
		NULL, /* HSM_OPENSSL_SLOT_INFO_free */
		/* Set the current slot */
		NULL, /* HSM_OPENSSL_SLOT_select */
		/* Cleans up the current slot */
		NULL, /* HSM_OPENSSL_SLOT_clean */
		/* Get X509 Callbacks */
		HSM_OPENSSL_X509_get_cb
};

/* Structure for PKI_TOKEN definition */
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

	/* Callbacks Structures */
	&openssl_hsm_callbacks
};


HSM_SLOT_INFO openssl_slot_info = {

        /* Device Manufacturer ID */
	"OpenSSL",

        /* Device Description */
	"Software interface",

        /* Hardware Version */
	1,
	0,

        /* Firmware Version */
        1,
	0,

	/* Initialized */
	1,

	/* Present */
	1,

	/* Removable */
	0,

	/* Hardware */
	0,

	/* Token Info */
	{
		/* Token Label */
		"Unknown Label\x0                ",
		/* ManufacturerID */
		"Unknown\x0                      ",
		/* Model */
		"Unknown\x0        ",
		/* Serial Number */
		"0\x0              ",
		/* Max Sessions */
		65535,
		/* Current Sessions */
		0,
		/* Max Pin Len */
		0,
		/* Min Pin Len */
		0,
		/* Memory Pub Total */
		0,
		/* Memory Pub Free */
		0,
		/* Memory Priv Total */
		0,
		/* Memory Priv Free */
		0,
		/* HW Version Major */
		1,
		/* HW Version Minor */
		0,
		/* FW Version Major */
		1,
		/* FW Version Minor */
		0,
		/* HAS Random Number Generator (RNG) */
		1,
		/* HAS clock */
		0,
		/* Login is Required */
		0,
		/* utcTime */
		""
	}

};

unsigned long HSM_OPENSSL_get_errno ( void )
{
	unsigned long ret = 0;

	ret = ERR_get_error();

	return ret;
}

char * HSM_OPENSSL_get_errdesc ( unsigned long err, char *str, size_t size )
{
	char * ret = NULL;

	if (err == 0) err = ERR_get_error();

	if (str && size > 0)
	{
		ERR_error_string_n ( err, str, size );
		ret = str;
	}
	else ret = ERR_error_string(err, NULL);
	
	return ret;
}

const HSM * HSM_OPENSSL_get_default( void )
{
	return ((const HSM *)&openssl_hsm);
}

HSM *HSM_OPENSSL_new ( PKI_CONFIG *conf )
{
	HSM *hsm = NULL;

	hsm = (HSM *) PKI_Malloc ( sizeof( HSM ));
	memcpy( hsm, &openssl_hsm, sizeof( HSM));

	/* Not really needed! */
	hsm->callbacks = &openssl_hsm_callbacks;

	if( conf ) {
		hsm->config = conf;
	}

	hsm->type = HSM_TYPE_SOFTWARE;

	return( hsm );
}

int HSM_OPENSSL_free ( HSM *driver, PKI_CONFIG *conf ) {

	if( driver == NULL ) return (PKI_OK);

	return (PKI_ERR);
}

int HSM_OPENSSL_init( HSM *driver, PKI_CONFIG *conf ) {

	if( driver == NULL ) return (PKI_ERR);

	/* Checks the FIPS mode */
	if (PKI_is_fips_mode() == PKI_OK)
	{
		if (HSM_OPENSSL_set_fips_mode(driver, 1) == PKI_ERR)
			return PKI_ERR;
	}

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

PKI_MEM * HSM_OPENSSL_sign(PKI_MEM *der, PKI_DIGEST_ALG *digest, PKI_X509_KEYPAIR *key)
{

	EVP_MD_CTX *ctx = NULL;
	EVP_PKEY_CTX *pCtx = NULL;

	size_t out_size = 0;
	size_t ossl_ret = 0;

	PKI_MEM *out_mem = NULL;
	EVP_PKEY *pkey = NULL;

	int def_nid = NID_undef;

    PKI_log_err("DIGEST ALGORITHM => %s", 
    	PKI_DIGEST_ALG_get_parsed(digest));

	if (!der || !der->data || !key || !key->value)
	{
		PKI_ERROR( PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	// Private Key
	pkey = key->value;

	// Get the Maximum size of a signature
	ossl_ret = out_size = (size_t) EVP_PKEY_size(pkey);

	// Initialize the return structure
	if ((out_mem = PKI_MEM_new ((size_t)out_size)) == NULL) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	// Creates the context
	if ((ctx = EVP_MD_CTX_create()) == NULL) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		if (out_mem) PKI_MEM_free(out_mem);
		return NULL;
	}

	// Initializes the Context
	EVP_MD_CTX_init(ctx);

    /*
     * EVP_PKEY_get_default_digest_nid() returns 2 if the digest is mandatory
     * for this algorithm.
     */
    if (EVP_PKEY_get_default_digest_nid(pkey, &def_nid) == 2
            && def_nid == NID_undef) {
        /* The signing algorithm requires there to be no digest */
        digest = NULL;
    }

    PKI_log_err("DIGEST ALGORITHM => %p", digest);

    if (!EVP_DigestSignInit(ctx, &pCtx, NULL, NULL, pkey)) {
    	PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, "Cannot Initialize EVP_DigestSignInit()");
    	// Cleanup the context
#if OPENSSL_VERSION_NUMBER <= 0x1010000f
		EVP_MD_CTX_cleanup(ctx);
#else
		EVP_MD_CTX_reset(ctx);
#endif
		EVP_MD_CTX_destroy(ctx);
        return NULL;
    }

    /*
    for (i = 0; i < sk_OPENSSL_STRING_num(sigopts); i++) {
        char *sigopt = sk_OPENSSL_STRING_value(sigopts, i);
        if (pkey_ctrl_string(pkctx, sigopt) <= 0) {
            BIO_printf(bio_err, "parameter error \"%s\"\n", sigopt);
            ERR_print_errors(bio_err);
            return 0;
        }
    }
    */


	// Initializes the Signature
	EVP_SignInit_ex(ctx, digest, NULL);
	EVP_SignUpdate (ctx, der->data, der->size);

	// Finalizes the signature
	if (!EVP_SignFinal(ctx, out_mem->data, (unsigned int *) &ossl_ret, pkey))
	{
		PKI_ERROR(PKI_ERR_SIGNATURE_CREATE, "Cannot finalize signature (%s)", 
			HSM_OPENSSL_get_errdesc(HSM_OPENSSL_get_errno(), NULL, 0));

		PKI_MEM_free(out_mem);
		out_mem = NULL;
	}
	else out_mem->size = (size_t) ossl_ret;

	// PKI_DEBUG("[Signature Generated: %d bytes (estimated: %d bytes)]", 
	//	ossl_ret, out_size);

	// Cleanup the context
#if OPENSSL_VERSION_NUMBER <= 0x1010000f
	EVP_MD_CTX_cleanup(ctx);
#else
	EVP_MD_CTX_reset(ctx);
#endif

	EVP_MD_CTX_destroy(ctx);

	return out_mem;
}
/* ---------------------- OPENSSL Slot Management Functions ---------------- */

HSM_SLOT_INFO * HSM_OPENSSL_SLOT_INFO_get (unsigned long num, HSM *hsm) {

	HSM_SLOT_INFO *ret = NULL;

	ret = (HSM_SLOT_INFO *) PKI_Malloc ( sizeof (HSM_SLOT_INFO));
	memcpy( ret, &openssl_slot_info, sizeof( HSM_SLOT_INFO ));

	return (ret);
}

/* -------------------- OPENSSL Callbacks Management Functions ------------- */

