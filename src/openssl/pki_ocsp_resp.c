/* PKI_X509_OCSP_RESP object management */

#include <libpki/pki.h>

/* ---------------------------- Memory Management ----------------------- */

/*! \brief Generates an empty OCSP request  */

PKI_OCSP_RESP *PKI_OCSP_RESP_new ( void )
{
	// Crypto Provider's specific data structures
	PKI_X509_OCSP_RESP_VALUE *r = NULL;
	OCSP_BASICRESP *bs = NULL;

	// Return container
	PKI_OCSP_RESP * ret = NULL;

	// Allocates the response object
	if ((r = OCSP_RESPONSE_new()) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	// Sets the initial state to "Success"
	if (!(ASN1_ENUMERATED_set(r->responseStatus, 
			PKI_X509_OCSP_RESP_STATUS_SUCCESSFUL)))
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);

		if (r) OCSP_RESPONSE_free (r);
		return NULL;
	}

	// Creates the basic response object
	if ((bs = OCSP_BASICRESP_new()) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);

		if( r ) OCSP_RESPONSE_free ( r );
		return ( NULL );
	}

	// Let's now create the outer container
	if(( ret = (PKI_OCSP_RESP *) 
			PKI_Malloc (sizeof(PKI_OCSP_RESP)))==NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);

		if ( bs ) OCSP_BASICRESP_free ( bs );
		if ( r  ) OCSP_RESPONSE_free ( r );

		return NULL;
	}

	// Transfer ownership of r and bs to the container
	ret->resp = r;
	ret->bs   = bs;

	// Success - object created
	return ret;
}


void PKI_OCSP_RESP_free( PKI_OCSP_RESP *x )
{
	// if no PKI_X509_OCSP_RESP is passed, let's return an error
	if (!x) return;

	// Free the memory
	if( x->resp ) OCSP_RESPONSE_free( x->resp );
	if( x->bs ) OCSP_BASICRESP_free ( x->bs );

	// Free the container
	PKI_Free ( x );

	// All done
	return;
}

PKI_X509_OCSP_RESP *PKI_X509_OCSP_RESP_new_null ( void )
{
	return PKI_X509_new(PKI_DATATYPE_X509_OCSP_RESP, NULL);
}

PKI_X509_OCSP_RESP *PKI_X509_OCSP_RESP_new ( void )
{
	PKI_X509_OCSP_RESP *ret = NULL;

	// Let's allocate the memory for the container
	if ((ret = PKI_X509_OCSP_RESP_new_null()) == NULL)
		return NULL;

	// If we have the create callback, let's allocate the
	// value for the object
	if (ret->cb && ret->cb->create)
	{
		ret->value = ret->cb->create();

		// If the internal value creation failed, let's fail
		// all the way
		if (!ret->value)
		{
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			PKI_X509_OCSP_RESP_free(ret);

			return NULL;
		}
	}

	// Success - object created
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

	if( !r->bs ) 
	{
		// Creates the basic response object
		if ((r->bs = OCSP_BASICRESP_new()) == NULL)
		{
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			return PKI_ERR;
		}
	}

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

/*!
 * \brief set the id-pkix-ocsp-extended-revoke extension in the response
 */ 

int PKI_X509_OCSP_RESP_set_extendedRevoke(PKI_X509_OCSP_RESP * resp) {

	PKI_X509_EXTENSION_VALUE * ext_val = NULL;
	OCSP_BASICRESP *bs = NULL;

	// Input Checks
	if (!resp || !resp->value) 
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// Checks we have the basic response
	bs = (OCSP_BASICRESP *) resp->value;
	if (!bs) return PKI_ERROR(PKI_ERR_POINTER_NULL, NULL);

	// Allocates the memory
	if ((ext_val = X509_EXTENSION_new()) == NULL) 
		return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, 0);

	// Let's create the extension and add it to the stack of extensions of
	// the OCSP response. Due to an error reported here:
	//
	// http://marc.info/?1=openssl-users&m=138573884214852&w=2
	//
	// We do specify the OID with the dotted notation {id-pkix-ocsp 9}
	ext_val->object = PKI_OID_get("1.3.6.1.5.5.7.48.1.9");

	// Let's now set the non-critical flag and the value should be NULL
	ext_val->critical = 0;
	ext_val->value = NULL;

	// Let's add the extension to the basicresponse
	if (!OCSP_BASICRESP_add_ext(bs, ext_val, -1)) {
		// Free memory and return error
		X509_EXTENSION_free(ext_val);
		return PKI_ERR;
	}

	// Done
	return PKI_OK;
}

int PKI_X509_OCSP_RESP_DATA_sign (PKI_X509_OCSP_RESP *resp, 
				PKI_X509_KEYPAIR *k, PKI_DIGEST_ALG *md ) {

	int ret = 0;
	OCSP_BASICRESP *bsrp = NULL;
	PKI_X509_OCSP_RESP_VALUE *resp_val = NULL;
	PKI_OCSP_RESP *r = NULL;

	if (!resp || !resp->value || !k || !k->value) 
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	r = resp->value;
	if (r->bs == NULL) 
	{
		PKI_ERROR(PKI_ERR_OCSP_RESP_SIGN, NULL);
		return PKI_ERR;
	}

	// If no digest is given, let's use the default one
	if (!md) md = PKI_DIGEST_ALG_SHA1;

	// DEBUG ONLY: Use this to check correctness
	/*
	PKI_X509_KEYPAIR_VALUE *key_val = NULL;
	key_val = PKI_X509_get_value(k);
	if (!OCSP_BASICRESP_sign(r->bs, key_val, md, 0))
	{
		PKI_log_debug("ERROR: Can not sign with OCSP_BASICRESP_sign! %s!", ERR_error_string(ERR_get_error(), NULL));
		return PKI_ERR;
	}
	*/

	// Using the generic signing function
	ret = PKI_X509_sign(resp, md, k);
	if (ret == PKI_ERR)
	{
		PKI_ERROR(PKI_ERR_OCSP_RESP_SIGN, ERR_error_string(ERR_get_error(), NULL));

		r->bs->signature = NULL;
		return PKI_ERR;
	}

	resp_val = r->resp;
	bsrp = r->bs;

	// In case the responseBytes are not already set, let's generate them ourselves
	if (!resp_val->responseBytes)
	{
		if (!(resp_val->responseBytes = OCSP_RESPBYTES_new()))
		{
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			return PKI_ERR;
		}

		resp_val->responseBytes->responseType = 
			OBJ_nid2obj(NID_id_pkix_OCSP_basic);
	}

	/* Now add the encoded data to the request bytes */
	if (!ASN1_item_pack(bsrp, ASN1_ITEM_rptr(OCSP_BASICRESP), &resp_val->responseBytes->response)) 
	{
		PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, NULL);
		return PKI_ERR;
	}

	return ( PKI_OK );
}

/*! \brief Signs a PKI_X509_OCSP_RESP, for a simpler API use PKI_X509_OCSP_RESP_sign_tk */
int PKI_X509_OCSP_RESP_sign ( PKI_X509_OCSP_RESP *resp, 
		PKI_X509_KEYPAIR *keypair, PKI_X509_CERT *cert, 
		PKI_X509_CERT *issuer, PKI_X509_CERT_STACK * otherCerts,
		PKI_DIGEST_ALG *digest, PKI_X509_OCSP_RESPID_TYPE respidType ) {

	OCSP_RESPID *rid;
	PKI_OCSP_RESP *r = NULL;

	if (!resp || !resp->value || !keypair || !keypair->value)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	// Let's get the value
	r = resp->value;

	//
	if (!r->resp)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	// If there is no bs, no need to sign the response
	// we do not consider this to be an error
	if (!r->bs)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	// Checks the certificates
	if (!cert || !cert->value )
	{
		PKI_log(PKI_LOG_WARNING,"Signing an OCSP_RESP without a cert");
	}

	if (!issuer || !issuer->value )
	{
		PKI_log( PKI_LOG_WARNING, "Signing an OCSP_RESP without the "
			"issuer's certificate!");
	}

	// Let's get the responderId
	rid = r->bs->tbsResponseData->responderId;

	// Sets the responderId
	if (cert && respidType == PKI_X509_OCSP_RESPID_TYPE_BY_NAME)
	{
		if (!cert) {
			PKI_log_err("PKI_OCSP_RESPID_TYPE_BY_NAME requires signer's certificate");
			return PKI_ERR;
		}

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
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
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

	if(X509_gmtime_adj(r->bs->tbsResponseData->producedAt, 0) == 0)
	{
		PKI_log_err("Error adding signed time to response");
	}

	if (!(r->resp->responseBytes = OCSP_RESPBYTES_new()))
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return PKI_ERR;
	}

	if((r->resp->responseBytes->responseType = 
			OBJ_nid2obj(NID_id_pkix_OCSP_basic)) == NULL )
	{
		PKI_log_debug("id-pkix-ocsp-basic OID error");
		return PKI_ERR;
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
			PKI_log_debug("ERROR, Can not Create stack of certs in signature!");
			return( PKI_ERR );
		}
	}

	/* Let's push the signer's certificate */
	if ( cert ) OCSP_basic_add1_cert(r->bs, cert->value);

	// Let's now perform the real signing operation
	return PKI_X509_OCSP_RESP_DATA_sign(resp, keypair, digest);

}

/*! \brief Signs a PKI_X509_OCSP_RESP object by using a token */

int PKI_X509_OCSP_RESP_sign_tk(PKI_X509_OCSP_RESP *r, PKI_TOKEN *tk, 
			       PKI_DIGEST_ALG *digest, PKI_X509_OCSP_RESPID_TYPE respidType)
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
			tk->otherCerts, digest, respidType);

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
			ret = tmp_x->tbsResponseData->producedAt;
			break;

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
			ret = (char *) PKI_TIME_get_parsed((PKI_TIME *)
				PKI_X509_OCSP_RESP_get_data ( r, type ));
			break;

		case PKI_X509_DATA_NOTAFTER:
			ret = NULL;
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
			ret = NULL;
	}

	return ret;
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
		PKI_ERROR(PKI_ERR_OCSP_NONCE_COPY, NULL);
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

	if (!r | !r->value) return ( PKI_ERR );

	// Let's get the parsed value
	if ((str = PKI_X509_OCSP_RESP_get_parsed(r, type)) == NULL)
		return PKI_ERR;

	// If the fd is 0, let's redirect to stdout
	if ( fd == 0 ) fd = 2;

	// Let's write the data to the fd and keep track of the
	// error(s) - if any occur
	if (write( fd, str, strlen(str)) == -1)
	{
		ret = PKI_ERR;
	}
	PKI_Free( (char *) str );

	return ret;
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

	// Let's re-pack the bytes
	/*
	if (o->resp->responseBytes->response) ASN1_OCTET_STRING_free(o->resp->responseBytes->response);
	if ((o->resp->responseBytes->response = ASN1_OCTET_STRING_new()) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return PKI_ERR;
	}

	if (!ASN1_item_pack(o->bs, ASN1_ITEM_rptr(OCSP_BASICRESP), &o->resp->responseBytes->response))
	{
		PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, NULL);
		return PKI_ERR;
	}
	*/

#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	return ASN1_i2d_bio( (int (*)(OCSP_RESPONSE *, unsigned char **)) 
		i2d_OCSP_RESPONSE, bp, (unsigned char *) o->resp);
#else
	return ASN1_i2d_bio( (i2d_of_void *) i2d_OCSP_RESPONSE, bp, 
		(unsigned char *) o->resp);
#endif
}

