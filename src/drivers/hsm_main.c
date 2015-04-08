/* HSM Object Management Functions */

#include <libpki/pki.h>

/* --------------------------- Static function(s) ------------------------- */

/*
static int __set_algorithm (PKI_ALGOR *alg, ASN1_OBJECT *obj, int ptype) {

	if (!alg) return PKI_ERR;

	if (ptype != V_ASN1_UNDEF) {
		if (alg->parameter == NULL) {
			if((alg->parameter = ASN1_TYPE_new()) == NULL ) {
				return PKI_ERR;
			};
		};
	};

	if (alg->algorithm) {
		ASN1_OBJECT_free(alg->algorithm);
	}
	alg->algorithm = obj;

	if (ptype == 0) {
		return PKI_OK;
	}

	if (ptype == V_ASN1_UNDEF) {
		if (alg->parameter) {
			ASN1_TYPE_free(alg->parameter);
			alg->parameter = NULL;
		}
	} else {
		ASN1_TYPE_set(alg->parameter, ptype, NULL);
	}

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

HSM *HSM_new( char *dir, char *name ) {

	HSM *hsm = NULL;
	char * url_s = NULL;

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


	/* Let's generate the right searching string with the namespace
	   prefix */
	if((type = PKI_CONFIG_get_value ( conf, "/hsm/type")) == NULL ) {
		/* No type in the config! */
		PKI_log_debug("ERROR, No HSM type in the config!");
		// PKI_CONFIG_free ( conf );
		// return (NULL);
		type = "software";
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
		PKI_CONFIG_free ( conf );
		return (NULL);
	}

	if ( ( hsm != NULL ) && (HSM_init ( hsm ) != PKI_OK) )
	{
			HSM_free ( hsm );
			return NULL;
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
				HSM_free(hsm);
				return NULL;
			}
	}
	else
	{
		PKI_log_debug("HSM created in non-FIPS mode");
	}

	PKI_CONFIG_free ( conf );
	if (url_s) PKI_Free ( url_s );
	if (type) PKI_Free(type);

	return (hsm);

err:
	PKI_CONFIG_free ( conf );
	if (url_s) PKI_Free ( url_s );
	if (type) PKI_Free(type);

	return (NULL);
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

HSM *HSM_new_fips( char *dir, char *name )
{
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
		return (hsm->callbacks->init ( hsm, hsm->config ));
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
		return ( hsm->callbacks->login( hsm, cred ));
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

int HSM_set_algor ( PKI_ALGOR *alg, HSM *hsm ) {

	int ret = PKI_OK;

	if( !alg ) {
		PKI_log_debug( "HSM_set_algor()::Error, no algorithm passed!");
		return ( PKI_ERR );
	}

	if( hsm && hsm->callbacks && hsm->callbacks->select_algor ) {
		ret = hsm->callbacks->select_algor ( hsm, alg );
	} else {
		PKI_log_debug ("No set algor from selected HSM");
		ret = PKI_OK;
	}

	return (ret);
}

/* ------------------------ General PKI Signing ---------------------------- */

/*! \brief Signs a PKI_X509 object */

// Small Hack - taps into OpenSSL internals.. needed for setting the right
// algorithm for signing

#ifdef EVP_MD_FLAG_PKEY_METHOD_SIGNATURE
#define ENABLE_AMETH	1
#endif

#ifdef ENABLE_AMETH
typedef struct my_meth_st {
    	int pkey_id;
    	int pkey_base_id;
    	unsigned long pkey_flags;
} LIBPKI_METH;
#endif

int PKI_X509_sign(PKI_X509 *x, PKI_DIGEST_ALG *digest, PKI_X509_KEYPAIR *key) {

	PKI_MEM *der = NULL;
	PKI_MEM *sig = NULL;

	/*
	PKI_ALGOR *alg1 = NULL;
	PKI_ALGOR *alg2 = NULL;
	*/

	PKI_ALGOR *algs[] = {
		NULL,
		NULL,
		NULL
	};

	PKI_STRING *signature = NULL;

#ifdef ENABLE_AMETH
	int signid = 0;
	struct my_meth_st *ameth = NULL;
	int paramtype = V_ASN1_UNDEF;
	PKI_X509_KEYPAIR_VALUE *pkey = NULL;
#endif

	int i;

	if (!x || !x->value || !key || !key->value ) 
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if (!digest) digest = PKI_DIGEST_ALG_DEFAULT;

	algs[0] = PKI_X509_get_data(x, PKI_X509_DATA_SIGNATURE_ALG1);
	algs[1] = PKI_X509_get_data(x, PKI_X509_DATA_SIGNATURE_ALG2);

	/*
	// Let's get the references to the signature algorithms
	PKI_X509_CERT_VALUE *c = (PKI_X509_CERT_VALUE *) x->value;
	if (c->cert_info)
	{
		algs[0] = c->cert_info->signature;
	}
	algs[1] = c->sig_alg;
	*/

	// Check we got at least one
	if( !algs[0] && !algs[1] )
	{
		PKI_log_debug("Can not retrieve sign algorithm!");
		return PKI_ERR;
	}


#ifdef ENABLE_AMETH
	pkey = key->value;
	ameth = (struct my_meth_st *) pkey->ameth;

	if (digest->flags & EVP_MD_FLAG_PKEY_METHOD_SIGNATURE)
	{
		if (!ameth || !OBJ_find_sigid_by_algs(&signid, EVP_MD_nid(digest), 
			ameth->pkey_id))
		{
			// ASN1_R_DIGEST_AND_KEY_TYPE_NOT_SUPPORTED
			return PKI_ERR;
		}
	}
	else signid = digest->pkey_type;

    if (ameth->pkey_flags & ASN1_PKEY_SIGPARAM_NULL) paramtype = V_ASN1_NULL;
    else paramtype = V_ASN1_UNDEF;

	for (i = 0; i < 2; i++)
	{
		if (algs[i]) X509_ALGOR_set0(algs[i], OBJ_nid2obj(signid), paramtype, NULL);
	}
#else
	/* Get the pointers to the internal algor data - very OpenSSL related */
	for ( i = 0; i < 2; i ++ ) {
		PKI_ALGOR *a = NULL;

		a = algs[i];

		if ( a == NULL ) continue;

		if ( (digest->pkey_type == PKI_ALGOR_DSA_SHA1)
#ifdef ENABLE_ECDSA
			|| ( digest->pkey_type == PKI_ALGOR_ECDSA_SHA1 ) ||
			( digest->pkey_type == PKI_ALGOR_ECDSA_SHA256 ) ||
			( digest->pkey_type == PKI_ALGOR_ECDSA_SHA384 ) ||
			( digest->pkey_type == PKI_ALGOR_ECDSA_SHA512 )
#endif
				) {
			if(a->parameter) ASN1_TYPE_free(a->parameter);
			a->parameter = NULL;
		} else if ((a->parameter == NULL) ||
				(a->parameter->type != V_ASN1_NULL)) {

			if(a->parameter) ASN1_TYPE_free(a->parameter);
			if ((a->parameter=ASN1_TYPE_new()) == NULL) {
				PKI_log_err ("Memory Error");
				return PKI_ERR;
			};
			a->parameter->type=V_ASN1_NULL;
		}

		a->algorithm = OBJ_nid2obj( digest->pkey_type );

		if (a->algorithm == NULL) {
			PKI_log_err ("Unknown Object Type");
			return PKI_ERR;
		};

		if (a->algorithm->length == 0) {
			PKI_log_err ("Object Identifier not valid or unknown!");
			return PKI_ERR;
		}
	}
#endif

	// Now let's set the algorithms - NOTE: algs are passed by ref, no need to set it
	// if (algs[0]) PKI_X509_CERT_set_data(x, PKI_X509_DATA_SIGNATURE_ALG1, algs[0]);
	// if (algs[1]) PKI_X509_CERT_set_data(x, PKI_X509_DATA_SIGNATURE_ALG2, algs[1]);

	/*
    if (algs[0]) {
        X509_ALGOR_set0(algs[0], OBJ_nid2obj(signid), paramtype, NULL);
	};

    if (algs[1]) {
        X509_ALGOR_set0(algs[1], OBJ_nid2obj(signid), paramtype, NULL);
	};
	*/

	/* Get the pointers to the internal algor data - very OpenSSL related */
	/*
	for ( i = 0; i < 2; i ++ ) {
		if ( i == 0 )
			a = alg1;
		else
			a = alg2;

		if ( a == NULL ) continue;

		if ( (digest->pkey_type == NID_dsaWithSHA1) ||
				( digest->pkey_type == NID_ecdsa_with_SHA1 )) {

			ASN1_TYPE_free(a->parameter);
            a->parameter = NULL;
		} else if ((a->parameter == NULL) ||
				(a->parameter->type != V_ASN1_NULL)) {

            ASN1_TYPE_free(a->parameter);
            if ((a->parameter=ASN1_TYPE_new()) == NULL) {
				PKI_log_err ("Memory Error");
				return PKI_ERR;
			};
            a->parameter->type=V_ASN1_NULL;
		}

		a->algorithm = OBJ_nid2obj( digest->pkey_type );
        if (a->algorithm == NULL) {
            PKI_log_err ("Unknown Object Type");
			return PKI_ERR;
		};

		if (a->algorithm->length == 0) {
            PKI_log_err ("Object Identifier not valid or unknown!");
            return PKI_ERR;
		}
	}
	*/

	/*
	if (alg1)
		__set_algorithm(alg1, OBJ_nid2obj(digest->pkey_type), paramtype);
	if (alg2)
		__set_algorithm(alg2, OBJ_nid2obj(digest->pkey_type), paramtype);
	*/

	if ((der = PKI_X509_get_data(x, PKI_X509_DATA_TBS_MEM_ASN1)) == NULL)
	{
		if ((der = PKI_X509_put_mem(x, PKI_DATA_FORMAT_ASN1, NULL, NULL )) == NULL)
		{
			PKI_log_debug("Can not convert object to ASN1");
			return PKI_ERR;
		}
	}

	if ((sig = PKI_sign(der, digest, key)) == NULL)
	{
		PKI_MEM_free ( der );
		return PKI_ERR;
	}

	/* der work is finished, let's free the memory */
	PKI_MEM_free ( der );

	if((signature = PKI_X509_get_data(x, PKI_X509_DATA_SIGNATURE))==NULL)
	{
		PKI_MEM_free (sig);
		PKI_log_debug("Can't get signature data");
		return PKI_ERR;
	}

	if ( signature->data ) PKI_Free ( signature->data );

	signature->data   = sig->data;
	signature->length = (int) sig->size;

	signature->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07);
  signature->flags |=ASN1_STRING_FLAG_BITS_LEFT;

	// We can not free the data in the sig PKI_MEM because that is
	// actually owned by the signature now, so let's change the
	// data pointer and then free the PKI_MEM data structure
	sig->data = NULL;
	sig->size = 0;

	// Now we can free the signature mem
	PKI_MEM_free(sig);

	return PKI_OK;

}

/*! \brief General signature function on data */

PKI_MEM *PKI_sign ( PKI_MEM *der, PKI_DIGEST_ALG *alg, PKI_X509_KEYPAIR *key ) {

	PKI_MEM *sig = NULL;
	HSM *hsm = NULL;

	// Input check
	if (!der || !der->data || !key || !key->value)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	// Uses the default algorithm if none was provided
	if ( !alg ) alg = PKI_DIGEST_ALG_DEFAULT;

	// If no HSM is provided, let's get the default one
	if (!(hsm && hsm->callbacks && hsm->callbacks->sign))
		hsm = (HSM *) HSM_get_default();

	// Requires the use of the HSM's sign callback
	if (hsm && hsm->callbacks && hsm->callbacks->sign)
	{
		sig = hsm->callbacks->sign(der, alg, key); 
		if (sig) PKI_log_debug("Signature Size (%d bytes)", sig->size);
	}

	// Let's return the output of the signing function
	return sig;
}

/*!
 * \brief Verifies a PKI_X509 by using a key from a certificate
 */

int PKI_X509_verify_cert ( PKI_X509 *x, PKI_X509_CERT *cert ) {

	PKI_X509_KEYPAIR *kp = NULL;
	PKI_X509_KEYPAIR *kval = NULL;
	int ret = -1;

	if (!x || !x->value || !cert || !cert->value ) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	kval = PKI_X509_CERT_get_data ( cert, PKI_X509_DATA_PUBKEY );
	if ( !kval ) return PKI_ERR;

	kp = PKI_X509_new_value ( PKI_DATATYPE_X509_KEYPAIR, kval, NULL);
	if ( !kp ) return PKI_ERR;

	ret = PKI_X509_verify ( x, kp );
	kp->value = NULL;
	PKI_X509_KEYPAIR_free ( kp );
	
	return ret;
}

/*!
 * \brief Verifies a signature on a PKI_X509 object (not for PKCS7 ones)
 */

int PKI_X509_verify ( PKI_X509 *x, PKI_X509_KEYPAIR *key ) {

	int ret = PKI_ERR;
	const HSM *hsm = NULL;

	PKI_MEM *data = NULL;
	PKI_MEM *sig = NULL;

	PKI_STRING *sig_value = NULL;
	PKI_ALGOR *alg = NULL;

	PKI_init_all();

	if (!x || !x->value || !key || !key->value)
	{
		if (!x || !x->value) PKI_log_err("Missing data to verify");
		if (!key || !key->value) PKI_log_err("Missing keypair to verify with");
		return PKI_ERR;
	}

	if ( key->hsm ) hsm = key->hsm;
	else hsm = HSM_get_default();

	if (( alg = PKI_X509_get_data ( x, PKI_X509_DATA_ALGORITHM )) == NULL)
	{
		PKI_log_err("Can not get algorithm from object!");
		return PKI_ERR;
	}

	if ((data = PKI_X509_get_data (x, PKI_X509_DATA_TBS_MEM_ASN1)) == NULL)
	{
		PKI_log_err("Can not get To Be signed object!");
		return PKI_ERR;
	}

	if ((sig_value = PKI_X509_get_data (x, PKI_X509_DATA_SIGNATURE )) == NULL)
	{
		PKI_log_err("Can not get Signature from the object!");
		PKI_MEM_free ( data );
		return PKI_ERR;
	}

	if((sig = PKI_MEM_new_null ()) == NULL ){
		PKI_MEM_free ( data );
		return PKI_ERR;
	}

	if ((PKI_MEM_add(sig, (char *)sig_value->data, (size_t) sig_value->length)) == PKI_ERR)
	{
		PKI_MEM_free ( sig );
		PKI_MEM_free ( data );
		return PKI_ERR;
	}

	// PKI_log_debug(">>> GOT SIG [%p - size=%d]", sig, sig->size );

	if (hsm && hsm->callbacks && hsm->callbacks->verify)
	{
		PKI_log_debug( "HSM verify() callback called " );
		ret = hsm->callbacks->verify( data, sig, alg, key ); 
	}
	else
	{
		ret = PKI_verify_signature ( data, sig, alg, key );
	}

	if ( data ) PKI_MEM_free ( data );
	if ( sig  ) PKI_MEM_free ( sig  );

	// Provides some additional information in debug mode
	if (ret != PKI_OK)
	{
		PKI_log_debug("Crypto Layer Error: %s (%d)", 
			HSM_get_errdesc(HSM_get_errno(hsm), hsm), HSM_get_errno(hsm));
	}

	return (ret);
}

/*! \brief Verifies a signature */

int PKI_verify_signature ( PKI_MEM *data, PKI_MEM *sig, PKI_ALGOR *alg,
						PKI_X509_KEYPAIR *key )
{
	EVP_MD_CTX ctx;
	PKI_DIGEST_ALG *dgst = NULL;

	if( !data || !data->data || !sig || !sig->data ||
			 !alg || !key || !key->value ) 
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	if((dgst = PKI_ALGOR_get_digest( alg )) == PKI_ID_UNKNOWN ) {
		PKI_log_debug( "PKI_verify_signature() can not get digest!");
		return PKI_ERR;
	}

	EVP_MD_CTX_init(&ctx);

	if((EVP_VerifyInit_ex(&ctx,dgst, NULL)) == 0 ) {
		PKI_log_debug( "PKI_verify_signature() verify init failed!");
		goto err;
	}

	if((EVP_VerifyUpdate(&ctx,(unsigned char *)data->data,
							data->size)) <= 0 ) {
		PKI_log_debug( "PKI_verify_signature() verifyUpdate failed!");
		goto err;
	}

	if (EVP_VerifyFinal(&ctx,(unsigned char *)sig->data,
                        (unsigned int)sig->size, key->value ) <= 0 ) {
		PKI_log_debug( "PKI_verify_signature() verifyFinal failed!");
		goto err;
	}

	EVP_MD_CTX_cleanup(&ctx);
	return PKI_OK;

err:
	EVP_MD_CTX_cleanup(&ctx);
	return PKI_ERR;
}

/* ----------------------- General Obj Management ------------------------ */

/*! \brief Gets a stack of X509 objects from the URL in the HSM */

PKI_X509_STACK *HSM_X509_STACK_get_url ( PKI_DATATYPE type, URL *url, 	
						PKI_CRED *cred, HSM *hsm ) {

	PKI_STACK *ret = NULL;

	if( !url ) return ( NULL );

	if( url->proto != URI_PROTO_ID ) return NULL;

	if( !hsm ) hsm = (HSM * ) HSM_get_default();

	if( hsm  && hsm->callbacks && hsm->callbacks->x509_sk_get_url ) { 
		ret = hsm->callbacks->x509_sk_get_url( type, url, cred, hsm );
	};

        return ( ret );
}

/*! \brief Stores a stack of PKI_X509 objects in the specified URL/HSM */

int HSM_X509_STACK_put_url ( PKI_X509_STACK *sk, URL *url, 
						PKI_CRED *cred, HSM *hsm ) {

	int ret = PKI_OK;

	if( !url || !sk ) return PKI_ERR;

	if ( url->proto != URI_PROTO_ID ) return PKI_ERR;

	if( !hsm ) hsm = (HSM *) HSM_get_default();

	if( hsm  && hsm->callbacks && hsm->callbacks->x509_sk_add_url ) { 
		ret = hsm->callbacks->x509_sk_add_url( sk, url, cred, hsm );
	};

        return ( ret );
}

/*! \brief Stores the contents of a stack of MEM to the specified URL/HSM */

int HSM_MEM_STACK_put_url ( PKI_MEM_STACK *sk, URL *url, PKI_DATATYPE type,
						PKI_CRED *cred, HSM *hsm ) {
	int i = 0;
	int ret = PKI_OK;

	PKI_MEM *mem = NULL;
	PKI_X509 *x_obj = NULL;
	PKI_X509_STACK *obj_sk = NULL;

	if(( obj_sk = PKI_STACK_new_type( type )) == NULL ) {
		return PKI_ERR;
	}

	for ( i = 0; i < PKI_STACK_MEM_elements ( sk ); i++ ) {
		PKI_X509_STACK *mem_obj_sk = NULL;

		/* Gets the PKI_MEM container from the stack */
		if((mem = PKI_STACK_MEM_get_num ( sk, i )) == NULL ) {
			continue;
		}

		/* Gets the objects (multiple, possibly) from each PKI_MEM */
		if((mem_obj_sk = PKI_X509_STACK_get_mem ( mem, type, 
						cred, hsm )) == NULL ) {
			continue;
		}

		/* Builds the stack of PKI_X509 objects */
		while ((x_obj = PKI_STACK_X509_pop ( mem_obj_sk )) != NULL ) {
			/* Push the Object on the Stack */
			PKI_STACK_X509_push ( obj_sk, x_obj );
		}
	}

	/* Now Put the stack of objects in the HSM */
	ret = HSM_X509_STACK_put_url ( sk, url, cred, hsm );

	/* Clean the stack of Objects we created */
	while ( (x_obj = PKI_STACK_X509_pop ( sk )) != NULL ) {
		PKI_X509_free ( x_obj );
	}
	PKI_STACK_X509_free ( sk );

	/* Return value */
	return ret;
}

/*! \brief Deletes a Stack of Objects that are stored in a HSM */

int HSM_X509_STACK_del ( PKI_X509_STACK *sk ) {

	int ret = PKI_ERR;
	int i = 0;

	// HSM *hsm = NULL;
	// HSM *def_hsm = NULL;

	PKI_X509 *obj = NULL;

	if ( !sk ) return ( PKI_ERR );

	for ( i = 0; i < PKI_STACK_X509_elements ( sk ); i++ ) {
		obj = PKI_STACK_X509_get_num ( sk, i );

		if (!obj || !obj->value ) continue;

		if ( obj->ref ) {
			ret = HSM_X509_del_url ( obj->type, obj->ref, 
							obj->cred, obj->hsm );

			if ( ret == PKI_ERR ) return PKI_ERR;
		}
	}

	return PKI_OK;
}

/*! \brief Deletes the contents of the specified URL in the HSM */

int HSM_X509_del_url ( PKI_DATATYPE type, URL *url, PKI_CRED *cred, HSM *hsm ) {

	int ret = PKI_OK;

	if( !url ) return ( PKI_ERR );

	if( !hsm ) hsm = (HSM *) HSM_get_default();

	if( hsm  && hsm->callbacks && hsm->callbacks->x509_del_url ) { 
		ret = hsm->callbacks->x509_del_url( type, url, cred, hsm );
	};

        return ( ret );
}

/*! \brief Returns the callbacks for the specific HSM */

const PKI_X509_CALLBACKS * HSM_X509_get_cb ( PKI_DATATYPE type, HSM *hsm ) {

	if ( !hsm || !hsm->callbacks ) return HSM_OPENSSL_X509_get_cb (type);

	return hsm->callbacks->x509_get_cb ( type );
}

