/* PKI_X509_OCSP_RESP object management */

#include <libpki/pki.h>

/* ---------------------------- Memory Management ----------------------- */

/*! \brief Generates an empty OCSP request  */

PKI_OCSP_RESP *PKI_OCSP_RESP_new ( void ) {

	PKI_X509_OCSP_RESP_VALUE *r = NULL;
	OCSP_BASICRESP *bs = NULL;

	PKI_OCSP_RESP * ret = NULL;

	if(( r = OCSP_RESPONSE_new()) == NULL ) {
		PKI_log_debug("Memory Error");
		return NULL;
	}

	if (!(ASN1_ENUMERATED_set(r->responseStatus, 
			PKI_X509_OCSP_RESP_STATUS_SUCCESSFUL))) {
		if (r) OCSP_RESPONSE_free (r);
		return NULL;
	}

	if(( bs = OCSP_BASICRESP_new()) == NULL ) {
		PKI_log_debug("Memory Error");
		if( r ) OCSP_RESPONSE_free ( r );
		return ( NULL );
	}

	if(( ret = (PKI_OCSP_RESP *) 
			PKI_Malloc (sizeof(PKI_OCSP_RESP)))==NULL){
		PKI_log_debug("Memory Error");
		if ( bs ) OCSP_BASICRESP_free ( bs );
		if ( r  ) OCSP_RESPONSE_free ( r );
		return ( NULL );
	}

	ret->resp = r;
	ret->bs = bs;

	return ret;
}


void PKI_OCSP_RESP_free( PKI_OCSP_RESP *x ) {

	/* if no PKI_X509_OCSP_RESP is passed, let's return an error */
	if( !x ) return;

	/* Free the memory */
	if( x->resp ) OCSP_RESPONSE_free( x->resp );
	if( x->bs ) OCSP_BASICRESP_free ( x->bs );

	PKI_Free ( x );

	/* Return success -- 1 */
	return;
}

PKI_X509_OCSP_RESP *PKI_X509_OCSP_RESP_new_null ( void ) {
	return PKI_X509_new ( PKI_DATATYPE_X509_OCSP_RESP, NULL );
}

PKI_X509_OCSP_RESP *PKI_X509_OCSP_RESP_new ( void ) {
	PKI_X509_OCSP_RESP *ret = NULL;

	if((ret = PKI_X509_OCSP_RESP_new_null ()) == NULL ) {
		return NULL;
	}

	if ( ret->cb && ret->cb->create ) {
		ret->value = ret->cb->create();
	}

	return ret;
}

void PKI_X509_OCSP_RESP_free_void( void *x ) {
	PKI_X509_OCSP_RESP_free( (PKI_X509_OCSP_RESP *)x);
}

/*! \brief Frees the memory associated with a PKI_X509_OCSP_RESP object */

void PKI_X509_OCSP_RESP_free( PKI_X509_OCSP_RESP *x ) {

	if ( !x ) return;

	PKI_X509_free ( x );

	return;
}

/*! \brief Sets the status of the request */

int PKI_X509_OCSP_RESP_set_status ( PKI_X509_OCSP_RESP *x, 
				PKI_X509_OCSP_RESP_STATUS status ) {

	PKI_OCSP_RESP * r = NULL;

	
	if ( !x || !x->value ) return PKI_ERR;

	r = x->value;

	if (!r->resp) return PKI_ERR;

	if (!(ASN1_ENUMERATED_set(r->resp->responseStatus, status)))
			return PKI_ERR;

	return PKI_OK;
}

/*! \brief Adds one basic request (one certificate) to the request by using
 *         the passed PKI_INTEGER as the serial number of the certificate */

int PKI_X509_OCSP_RESP_add ( PKI_X509_OCSP_RESP *resp, 
			OCSP_CERTID *cid, PKI_OCSP_CERTSTATUS status,
			PKI_TIME *revokeTime, PKI_TIME *thisUpdate,
			PKI_TIME *nextUpdate, 
			PKI_X509_CRL_REASON reason,
			PKI_X509_EXTENSION *invalidityDate ) {

	OCSP_SINGLERESP *single = NULL;
	PKI_TIME *myThisUpdate = NULL;

	PKI_OCSP_RESP *r = NULL;

	if ( !resp || !resp->value || !cid ) return ( PKI_ERR );

	r = resp->value;

	if( !r->bs ) return PKI_ERR;

	if (thisUpdate == NULL )
	{
		myThisUpdate = X509_gmtime_adj(NULL,0);
	}
	else
	{
		myThisUpdate = PKI_TIME_dup(thisUpdate);
	}

	if((single = OCSP_basic_add1_status(r->bs, cid,
			status, reason, revokeTime, myThisUpdate, nextUpdate))== NULL)
	{
		PKI_log_err ("Can not create basic entry!");
		return ( PKI_ERR );
	}

	if (myThisUpdate) PKI_TIME_free(myThisUpdate);

	if (invalidityDate)
	{
		if (!OCSP_SINGLERESP_add1_ext_i2d(single,
                		NID_invalidity_date, invalidityDate, 0, 0))
		{
			PKI_log_err("Can not create extension entry for response!");
			return PKI_ERR;
		}
	}

	return PKI_OK;
}

int PKI_X509_OCSP_RESP_DATA_sign (PKI_X509_OCSP_RESP *resp, 
				PKI_X509_KEYPAIR *k, PKI_DIGEST_ALG *md ) {

	int ret = 0;
	OCSP_BASICRESP *bsrp = NULL;
	PKI_X509_OCSP_RESP_VALUE *resp_val = NULL;

	PKI_OCSP_RESP *r = NULL;

	if(!resp || !resp->value || !k || !k->value) 
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	r = resp->value;
	if( !r->bs ) 
	{
		PKI_ERROR(PKI_ERR_OCSP_RESP_SIGN, NULL);
		return PKI_ERR;
	}

	// If no digest is given, let's use the default one
	if (!md) md = PKI_DIGEST_ALG_SHA1;

	// Using the generic signing function
	ret = PKI_X509_sign(resp, md, k);
	if (ret == PKI_ERR)
	{
		PKI_log_err("ERROR while calling PKI_X509_sign()");

		r->bs->signature = NULL;
		PKI_ERROR(PKI_ERR_OCSP_RESP_SIGN, ERR_error_string(ERR_get_error(), NULL));
		return PKI_ERR;
	}

	resp_val = r->resp;
	bsrp = r->bs;

	// In case the responseBytes are not already set, let's generate them ourselves
	if (!resp_val->responseBytes)
	{
		if (!(resp_val->responseBytes = OCSP_RESPBYTES_new()))
		{
			PKI_log_err("ERROR while allocating memory");
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			return PKI_ERR;
		}

		resp_val->responseBytes->responseType = 
			OBJ_nid2obj(NID_id_pkix_OCSP_basic);
	}

	/* Now add the encoded data to the request bytes */
	if (!ASN1_item_pack(bsrp, ASN1_ITEM_rptr(OCSP_BASICRESP), &resp_val->responseBytes->response)) 
	{
		PKI_log_err("ERROR while encoding data");
		PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, NULL);
		return PKI_ERR;
	}

	return ( PKI_OK );
}

/*! \brief Signs a PKI_X509_OCSP_RESP, for a simpler API use PKI_X509_OCSP_RESP_sign_tk */
int PKI_X509_OCSP_RESP_sign ( PKI_X509_OCSP_RESP *resp, 
		PKI_X509_KEYPAIR *keypair, PKI_X509_CERT *cert, 
		PKI_X509_CERT *issuer, PKI_X509_CERT_STACK * otherCerts,
		PKI_DIGEST_ALG *digest ) {

	OCSP_RESPID *rid;
	PKI_OCSP_RESP *r = NULL;

	if (!resp || !keypair || !keypair->value)
	{
		PKI_log_err("Parameter Error (data %p - keypair %p)", resp, keypair);
		return PKI_ERR;
	}

	r = resp->value;

	if (!r || !r->resp || !r->bs ) 
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	if (!cert || !cert->value )
	{
		PKI_log(PKI_LOG_WARNING,"Signing an OCSP_RESP without a cert");
	}

	if (!issuer || !issuer->value )
	{
		PKI_log( PKI_LOG_WARNING, "Signing an OCSP_RESP without the "
			"issuer's certificate!");
	}

	rid = r->bs->tbsResponseData->responderId;

	if (cert)
	{
	/*
	unsigned char md[SHA_DIGEST_LENGTH];
    X509_pubkey_digest(cert, EVP_sha1(), md, NULL);
    if (!(rid->value.byKey = ASN1_OCTET_STRING_new())) {
		PKI_log_err ("Memory Allocation Failed");
                return PKI_ERR;
	}
    if (!(ASN1_OCTET_STRING_set(rid->value.byKey, md, SHA_DIGEST_LENGTH))) {
		PKI_log_err("Internal Error");
		return PKI_ERR;
	}
    rid->type = V_OCSP_RESPID_KEY;
	*/

		if (!X509_NAME_set(&rid->value.byName, X509_get_subject_name(cert->value)))
		{
			PKI_log_err("Internal Error");
			return PKI_ERR;
		}

		rid->type = V_OCSP_RESPID_NAME;
	}
	else
	{
		PKI_DIGEST *dgst = PKI_X509_KEYPAIR_pub_digest(keypair, PKI_DIGEST_ALG_SHA1);

		if (!dgst)
		{
			PKI_log_err("Can not get Keypair Sha-1 value!");
			return PKI_ERR;
		}

		rid->type = V_OCSP_RESPID_KEY;
		if((rid->value.byKey = ASN1_OCTET_STRING_new()) == NULL)
		{
			PKI_log_err("Memory Allocation Error!");
			PKI_DIGEST_free(dgst);
			return PKI_ERR;
		}

		if(!ASN1_OCTET_STRING_set(rid->value.byKey, dgst->digest, (int) dgst->size))
		{
			PKI_log_err("Can not assign Responder Id by Key (Internal Error!)");
			PKI_DIGEST_free(dgst);
			return PKI_ERR;
		}

		// All done here.
		PKI_DIGEST_free(dgst);
	}

	if(X509_gmtime_adj(r->bs->tbsResponseData->producedAt, 0) == 0 ) {
		PKI_log_err("Error adding signed time to response");
		// return PKI_ERR;
	}

	if (!(r->resp->responseBytes = OCSP_RESPBYTES_new())) {
		PKI_log_debug("OCSP RESPBYTES Memory error");
		return PKI_ERR;
	}

	if((r->resp->responseBytes->responseType = 
			OBJ_nid2obj(NID_id_pkix_OCSP_basic)) == NULL ) {
		PKI_log_debug("id-pkix-ocsp-basic OID error");
		return PKI_ERR;
	};

	if ( r->bs == NULL )
	{
		PKI_log_debug("Basic Response is empty, no sign allowed!");
		return PKI_ERR;

		/*
		if((r->bs = OCSP_BASICRESP_new()) == NULL ) {
			PKI_log_err ("Memory Error (BASICREQUEST creation)");
			return PKI_ERR;
		}
		*/
	}

	/* If there's old certs, let's clean the stack */
	if( r->bs->certs )
	{
		PKI_X509_CERT_VALUE *tmp_cert = NULL;

		while ( (tmp_cert = sk_X509_pop( r->bs->certs )) != NULL )
		{
			X509_free ( tmp_cert );
		}
	}
	else
	{
		if((r->bs->certs = sk_X509_new_null()) == NULL)
		{
			PKI_log_debug("ERROR, Can not Create stack "
						"of certs in signature!");
			return( PKI_ERR );
		}
	}

	/* Let's push the signer's certificate */
	// if ( cert ) OCSP_basic_add1_cert( r->bs, cert->cb->dup ( cert->value ));
	if ( cert ) OCSP_basic_add1_cert(r->bs, cert->value);

	/* Ler's push the CA's certificate */
	// if ( issuer ) 
	//	OCSP_basic_add1_cert (r->bs, issuer->cb->dup ( issuer->value ));

	/* Now, if we have the otherCerts, let's add them to the response */
	/*
	if ( otherCerts ) {
		int i = 0;
		for( i = 0; i<PKI_STACK_X509_CERT_elements(otherCerts); i++ ) {
			PKI_X509_CERT *x_tmp = NULL;

			x_tmp = PKI_STACK_X509_CERT_get_num (otherCerts,i);
			if( x_tmp && x_tmp->value ) {
				OCSP_basic_add1_cert( r->bs,
					X509_dup( x_tmp->value ));
			}
		}
	}
	*/

	return PKI_X509_OCSP_RESP_DATA_sign(resp, keypair, digest);

}

/*! \brief Signs a PKI_X509_OCSP_RESP object by using a token */

int PKI_X509_OCSP_RESP_sign_tk(PKI_X509_OCSP_RESP *r, PKI_TOKEN *tk, PKI_DIGEST_ALG *digest)
{
	int ret = PKI_OK;

	// Input check
	if( !r || !tk ) return ( PKI_ERR );

	// Gets the Digest algorithm from the Token algor
	if (!digest) digest = PKI_ALGOR_get_digest(tk->algor);

	if (PKI_TOKEN_login(tk) != PKI_OK)
	{
		PKI_ERROR(PKI_ERR_HSM_LOGIN, "OCSP Response Signing");
		return PKI_ERR;
	}

	ret = PKI_X509_OCSP_RESP_sign(r, tk->keypair, tk->cert, tk->cacert,
			tk->otherCerts, digest);

	if (ret != PKI_OK) PKI_log_debug("Error while signing OCSP response");

	return ret;
}

/*! \brief Returns a pointer to the data present in the OCSP request
 */

void * PKI_X509_OCSP_RESP_get_data ( PKI_X509_OCSP_RESP *r, PKI_X509_DATA type )
{
	void * ret = NULL;
	PKI_OCSP_RESP *val = NULL;
	OCSP_BASICRESP *tmp_x = NULL;
	PKI_MEM *mem = NULL;
	int idx = -1;

	if( !r || !r->value ) return NULL;

	val = r->value;

	/* Let's check that the response data is there!! */
	if( !val->bs ) return NULL;

	tmp_x = val->bs;

	switch ( type )
	{
		case PKI_X509_DATA_NONCE:
			idx = OCSP_BASICRESP_get_ext_by_NID(tmp_x, NID_id_pkix_OCSP_Nonce, -1);
			if (idx >= 0)
			{
				X509_EXTENSION *ext = OCSP_BASICRESP_get_ext(tmp_x, idx);
				if (ext) ret = PKI_STRING_new(ext->value->type,
						(char *) ext->value->data, (ssize_t) ext->value->length);
			}
			break;

		case PKI_X509_DATA_NOTBEFORE:
		case PKI_X509_DATA_NOTAFTER:
			break;

		case PKI_X509_DATA_SIGNATURE:
			if ( tmp_x && tmp_x->signature ) {
				ret = tmp_x->signature;
			}
			break;

		case PKI_X509_DATA_ALGORITHM:
		case PKI_X509_DATA_SIGNATURE_ALG1:
			if ( tmp_x && tmp_x->signatureAlgorithm ) {
				ret = tmp_x->signatureAlgorithm;
			}
			break;

		case PKI_X509_DATA_SIGNATURE_ALG2:
			break;

		case PKI_X509_DATA_TBS_MEM_ASN1:
			if((mem = PKI_MEM_new_null()) == NULL )
			{
				PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL );
				break;
			}
			mem->size = (size_t) ASN1_item_i2d ( (void *) tmp_x->tbsResponseData, 
				&(mem->data), &OCSP_RESPDATA_it );
			ret = mem;
			break;

		default:
			return NULL;
	}

	return ret;
}

/*! \brief Returns a char * representation of the data present in the
 *         OCSP request
 */

char * PKI_X509_OCSP_RESP_get_parsed ( PKI_X509_OCSP_RESP *r, 
						PKI_X509_DATA type ) {

	char *ret = NULL;

	if( !r ) return ( NULL );

	switch ( type ) {
		case PKI_X509_DATA_NONCE:
			ret = (char *) PKI_STRING_get_parsed((PKI_STRING *)
				PKI_X509_OCSP_RESP_get_data ( r, type ));
			break;
		case PKI_X509_DATA_NOTBEFORE:
		case PKI_X509_DATA_NOTAFTER:
			ret = (char *) PKI_TIME_get_parsed((PKI_TIME *)
				PKI_X509_OCSP_RESP_get_data ( r, type ));
			break;
		case PKI_X509_DATA_ALGORITHM:
			ret = (char *) PKI_ALGOR_get_parsed ( (PKI_ALGOR *)
				PKI_X509_OCSP_RESP_get_data ( r, type ));
			break;
		case PKI_X509_DATA_SIGNATURE:
			ret = (char *) PKI_X509_SIGNATURE_get_parsed(
				(PKI_X509_SIGNATURE *) 
					PKI_X509_OCSP_RESP_get_data ( r, type ));
			break;
		default:
			return ( NULL );
	}

	return ( ret );
}

/*! \brief Copies the NONCE from a PKI_OCSP_RESP into the response */

int PKI_X509_OCSP_RESP_copy_nonce ( PKI_X509_OCSP_RESP *resp, 
						PKI_X509_OCSP_REQ *req ) {

	PKI_OCSP_RESP *r = NULL;

	if ( !resp || !resp->value || !req || !req->value )
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	r = resp->value;
	if (!r->bs)
	{
		PKI_log_err("Missing basic request in OCSP REQ value");

		return PKI_ERR;
	}

	if(!OCSP_copy_nonce( r->bs, req->value ))
	{
		PKI_log_err("Can not copy OCSP REQ nonce");
		return PKI_ERR;
	}

	return PKI_OK;
}

/*! \brief Prints the requested data from the OCSP request to the file
 *         descriptor passed as an argument
 */

int PKI_X509_OCSP_RESP_print_parsed ( PKI_X509_OCSP_RESP *r, 
				PKI_X509_DATA type, int fd ) {

	const char *str = NULL;
	int ret = PKI_OK;

	if( !r | !r->value ) return ( PKI_ERR );

	if((str = PKI_X509_OCSP_RESP_get_parsed ( r, type )) == NULL ) {
		return ( PKI_ERR );
	} else {
		if( fd == 0 ) fd = 2;
		if( write( fd, str, strlen(str)) == -1 ) {
			ret = PKI_ERR;
		}
		PKI_Free( (char *) str );
	}

	return ( ret );
}

/* PEM <-> INTERNAL Macros --- fix for errors in OpenSSL */
PKI_OCSP_RESP *PEM_read_bio_PKI_OCSP_RESP( PKI_IO *bp, void *a, 
						void *b, void *c ) {
	PKI_OCSP_RESP *ret = NULL;

	if (( ret = (PKI_OCSP_RESP *) 
			PKI_Malloc ( sizeof( PKI_OCSP_RESP ))) == NULL ) {
		return NULL;
	}

#if OPENSSL_VERSION_NUMBER < 0x0090800fL
        ret->resp = (PKI_X509_OCSP_RESP_VALUE *) PEM_ASN1_read_bio( 
			(char *(*)()) d2i_OCSP_RESPONSE,
                                PEM_STRING_OCSP_RESPONSE, bp, NULL, NULL, NULL);
#else
        ret->resp = (PKI_X509_OCSP_RESP_VALUE *) PEM_ASN1_read_bio( 
			(void *(*)()) d2i_OCSP_RESPONSE,
                                PEM_STRING_OCSP_RESPONSE, bp, NULL, NULL, NULL);
#endif

	if ( ret->resp == NULL ) {
		PKI_Free ( ret );
		return NULL;
	}

	ret->bs = OCSP_response_get1_basic(ret->resp);

	return ret;
}

int PEM_write_bio_PKI_OCSP_RESP( PKI_IO *bp, PKI_OCSP_RESP *o ) {

	if ( !o || !o->resp ) return PKI_ERR;

	return PEM_ASN1_write_bio ( (int (*)())i2d_OCSP_RESPONSE, 
			PEM_STRING_OCSP_RESPONSE, bp, (char *) o->resp, NULL, 
				NULL, 0, NULL, NULL );
}

PKI_OCSP_RESP *d2i_PKI_OCSP_RESP_bio ( PKI_IO *bp, PKI_OCSP_RESP **p ) {

	PKI_OCSP_RESP *ret = NULL;

	if (( ret = (PKI_OCSP_RESP *) 
			PKI_Malloc ( sizeof( PKI_OCSP_RESP ))) == NULL ) {
		return NULL;
	}

#if OPENSSL_VERSION_NUMBER < 0x0090800fL
        ret->resp = (PKI_X509_OCSP_RESP_VALUE *) ASN1_d2i_bio(
                        (char *(*)(void))OCSP_RESPONSE_new,
                        (char *(*)(void **, const unsigned char **, long))
							d2i_OCSP_RESPONSE,
                        bp, (unsigned char **) NULL);
#else
        ret->resp = (PKI_X509_OCSP_RESP_VALUE *) ASN1_d2i_bio(
                        (void *(*)(void))OCSP_RESPONSE_new,
                        (void *(*)(void **, const unsigned char **, long))
							d2i_OCSP_RESPONSE,
                        bp, (void **) NULL);
#endif
	if ( !ret->resp ) {
		PKI_Free ( ret );
		return NULL;
	}

	ret->bs = OCSP_response_get1_basic(ret->resp);

	return ret;
}

int i2d_PKI_OCSP_RESP_bio(PKI_IO *bp, PKI_OCSP_RESP *o ) {

	if ( !o || !o->resp ) return PKI_ERR;

#if OPENSSL_VERSION_NUMBER < 0x0090800fL
        return ASN1_i2d_bio( (int (*)(OCSP_RESPONSE *, unsigned char **)) 
		i2d_OCSP_RESPONSE, bp, (unsigned char *) o->resp);
#else
        return ASN1_i2d_bio( (i2d_of_void *) i2d_OCSP_RESPONSE, bp, 
		(unsigned char *) o->resp);
#endif
}

