/* PKI_X509_OCSP_REQ object management */

#include <libpki/pki.h>
#include "internal/x509_data_st.h"

PKI_X509_OCSP_REQ *PKI_X509_OCSP_REQ_new_null ( void ) {

	return PKI_X509_new ( PKI_DATATYPE_X509_OCSP_REQ, NULL );
}

/*! \brief Generates an empty OCSP request  */

PKI_X509_OCSP_REQ *PKI_X509_OCSP_REQ_new ( void ) {
	PKI_X509_OCSP_REQ *req = NULL;

	if((req = PKI_X509_OCSP_REQ_new_null()) == NULL ) return NULL;

	if((req->value = OCSP_REQUEST_new()) == NULL) {
		PKI_log_debug("OCSP_REQUEST::Memory Allocation Error!");
		PKI_X509_free ( req );
		return NULL;
	}

	return req;
}

void PKI_X509_OCSP_REQ_free_void( void *x ) {
	PKI_X509_OCSP_REQ_free( (PKI_X509_OCSP_REQ *) x);
}

/*! \brief Frees the memory associated with a PKI_X509_OCSP_REQ object */

void PKI_X509_OCSP_REQ_free( PKI_X509_OCSP_REQ *x ) {

	/* if no PKI_X509_OCSP_REQ is passed, let's return an error */
	if (!x) return;

	/* Free the memory */
	PKI_X509_free(x);

	/* Return success -- 1 */
	return;
}

/*! \brief Adds a random nonce to a request. If size = 0, the default size is
 *         used instead. */

int PKI_X509_OCSP_REQ_add_nonce ( PKI_X509_OCSP_REQ *req, size_t size ) {

	if (!req || !req->value)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	if (!OCSP_request_add1_nonce(req->value, NULL, 0))
		return PKI_ERR;

	return PKI_OK;
}

/*! \brief Adds one basic request (one certificate) to the request by using
 *         the passed PKI_INTEGER as the serial number of the certificate */

int PKI_X509_OCSP_REQ_add_serial ( PKI_X509_OCSP_REQ *req, PKI_INTEGER *serial,
			PKI_X509_CERT *issuer, PKI_DIGEST_ALG *digest ) {

	const PKI_X509_NAME *iname = NULL;
	ASN1_BIT_STRING *ikey = NULL;

	OCSP_CERTID *id = NULL;
	PKI_DIGEST_ALG * md = PKI_DIGEST_ALG_SHA1;

	if (!req || !req->value || !serial || !issuer || !issuer->value) 
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	if( digest ) md = digest;

	iname = PKI_X509_CERT_get_data(issuer, PKI_X509_DATA_SUBJECT);
	ikey = X509_get0_pubkey_bitstr(issuer->value);

	if((id = OCSP_cert_id_new(md, 
				  (PKI_X509_NAME *)iname,
				  ikey,
				  serial)) == NULL) {
		return PKI_ERR;
	}

	if(!OCSP_request_add0_id(req->value, id)) return PKI_ERR;

	return PKI_OK;
}

/*! \brief Adds one basic request (one certificate) to the request by using
 *         the passed PKI_INTEGER as the serial number of the certificate */

int PKI_X509_OCSP_REQ_add_cert ( PKI_X509_OCSP_REQ *req, PKI_X509_CERT *cert, 
			PKI_X509_CERT *issuer, PKI_DIGEST_ALG *digest ) {

	const PKI_INTEGER *serial = NULL;

	if (!req || !cert || !issuer) return PKI_ERR;

	if ((serial = PKI_X509_CERT_get_data(cert, 
					     PKI_X509_DATA_SERIAL)) == NULL) {
		return PKI_ERR;
	}

	return PKI_X509_OCSP_REQ_add_serial(req, 
					    (PKI_INTEGER *)serial, 
					    issuer,
					    digest);
}

/*! \brief Adds one basic request (one certificate) to the request by using
 *         the passed string (char *) as the serial number of the certificate
 */

int PKI_X509_OCSP_REQ_add_txt ( PKI_X509_OCSP_REQ *req, char *serial,
			PKI_X509_CERT *issuer, PKI_DIGEST_ALG *digest ) {

	PKI_INTEGER *s = NULL;
	int ret = PKI_OK;

	if (!req || !serial || !issuer)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	if ((s = PKI_INTEGER_new_char(serial)) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return PKI_ERR;
	}

	ret = PKI_X509_OCSP_REQ_add_serial(req, s, issuer, digest);

	if (s) PKI_INTEGER_free(s);

	return ret;
}

/*! \brief Adds one basic request (one certificate) to the request by using
 *         the passed num (long long) as the serial number of the certificate
 */

int PKI_X509_OCSP_REQ_add_longlong ( PKI_X509_OCSP_REQ *req, long long serial,
			PKI_X509_CERT *issuer, PKI_DIGEST_ALG *digest ) {

	PKI_INTEGER *s = NULL;
	int ret = PKI_OK;

	if (!req || !serial || !issuer) 
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	if ((s = PKI_INTEGER_new(serial)) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return PKI_ERR;
	}

	ret = PKI_X509_OCSP_REQ_add_serial(req, s, issuer, digest);

	if ( s ) PKI_INTEGER_free ( s );

	return ret;
}

/*! \brief Checks if a nonce is present in the request and returns 1 if found, 0 otherwise. */

int PKI_X509_OCSP_REQ_has_nonce(PKI_X509_OCSP_REQ *req)
{
	int idx = 0;

	// Input check
	if (!req || !req->value)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	// Retrieves the index of the NONCE extension
	idx = OCSP_REQUEST_get_ext_by_NID(req->value, NID_id_pkix_OCSP_Nonce, -1);

	// If found, we return 1. Otherwise we return 0.
	return (idx < 0 ? 0 : 1);
}

/*! \brief Returns the number of single requests present in the OCSP REQ */

int PKI_X509_OCSP_REQ_elements ( PKI_X509_OCSP_REQ *req ) {
	
	PKI_X509_OCSP_REQ_VALUE *val = NULL;

	if (!req || !req->value) 
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	val = req->value;

	return OCSP_request_onereq_count( val );

}


/*! \brief Returns the n-th PKI_OCSP_CERTID from an OCSP_REQ */

PKI_OCSP_CERTID * PKI_X509_OCSP_REQ_get_cid ( PKI_X509_OCSP_REQ *req, int num) {

	PKI_OCSP_REQ_SINGLE *single = NULL;
	PKI_X509_OCSP_REQ_VALUE *val = NULL;
	int count = -1;

	if ( !req || !req->value ) return NULL;

	if ((count = PKI_X509_OCSP_REQ_elements ( req )) < num)
	{
		return NULL;
	}

	val = req->value;

	if ((single = OCSP_request_onereq_get0(val, num)) == NULL)
	{
		return NULL;
	}

	return OCSP_onereq_get0_id( single );
}

PKI_STRING * PKI_OCSP_CERTID_get_issuerNameHash(PKI_OCSP_CERTID * c_id) {

	PKI_STRING * ret = NULL;
		// Return Value

	// Input checks
	if (!c_id) return NULL;

  // Gets the pointer to the issuerNameHas
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
	ret = &(c_id->issuerNameHash);
#else
	ret = c_id->issuerNameHash;
#endif

	// Returns the pointer to the OCTET string
  return ret;

}

PKI_STRING * PKI_OCSP_CERTID_get_issuerKeyHash(PKI_OCSP_CERTID * c_id) {

	PKI_STRING * ret = NULL;
		// Return Value

	// Input checks
	if (!c_id) return NULL;

  // Gets the pointer to the issuerNameHas
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
	ret = &(c_id->issuerKeyHash);
#else
	ret = c_id->issuerKeyHash;
#endif

  // Returns the pointer to the OCTET string
  return ret;
}

/*! \brief Returns the serial of the requested certificate from the n-th
 *         single request */

PKI_INTEGER * PKI_X509_OCSP_REQ_get_serial ( PKI_X509_OCSP_REQ *req, 
								int num) {
	PKI_OCSP_CERTID *cid = NULL;
	PKI_INTEGER *ret = NULL;

	if ((cid = PKI_X509_OCSP_REQ_get_cid(req, num)) == NULL)
	{
		return NULL;
	}

	OCSP_id_get0_info(NULL, NULL, NULL, &ret, cid);

	return ret;
}

int PKI_X509_OCSP_REQ_DATA_sign (PKI_X509_OCSP_REQ * req, 
				 PKI_X509_KEYPAIR  * k,
				 PKI_DIGEST_ALG    * md ) {

	int ret = 0;

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
	LIBPKI_X509_OCSP_REQ * val = NULL;
#else
	PKI_X509_OCSP_REQ_VALUE * val = NULL;
#endif

	if (!req || !req->value || !k || !k->value)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	if( !md ) md = PKI_DIGEST_ALG_SHA1;

	val = req->value;

	if (val->optionalSignature == NULL)
	{
		if((val->optionalSignature = OCSP_SIGNATURE_new()) == NULL)
		{
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			return PKI_ERR;
		}
	}

	ret = PKI_X509_sign(req, md, k);

	if (ret == PKI_ERR)
	{
		OCSP_SIGNATURE_free ( val->optionalSignature );
		val->optionalSignature = NULL;
		PKI_ERROR(PKI_ERR_OCSP_REQ_SIGN, ERR_error_string(ERR_get_error(), NULL));
		return PKI_ERR;
	}

	return ret;
}

/*! \brief Signs a PKI_X509_OCSP_REQ, for a simpler API use PKI_X509_OCSP_REQ_sign_tk */
int PKI_X509_OCSP_REQ_sign(PKI_X509_OCSP_REQ   * req,
			   PKI_X509_KEYPAIR    * keypair,
			   PKI_X509_CERT       * cert, 
			   PKI_X509_CERT       * issuer, 
			   PKI_X509_CERT_STACK * otherCerts, 
			   PKI_DIGEST_ALG      * digest) {

	PKI_X509_OCSP_REQ_VALUE *val = NULL;

	if (!req || !req->value || !keypair ) return PKI_ERR;

	if (!cert || !cert->value ) {
		PKI_log( PKI_LOG_WARNING,"Signing an OCSP_REQ without a cert!");
	}

	if (!issuer || !issuer->value ) {
		PKI_log( PKI_LOG_WARNING, "Signing an OCSP_REQ without the "
			"issuer's certificate!");
	}

	val = req->value;

	if (cert) {
		OCSP_request_set1_name (val,  
			(PKI_X509_NAME *)PKI_X509_CERT_get_data(cert, 
						PKI_X509_DATA_SUBJECT));
	}

	if ((PKI_X509_OCSP_REQ_DATA_sign(req,
					 keypair, 
					 digest )) == PKI_ERR ) {
		return PKI_ERR;
	}

#if OPENSSL_VERSION_NUMBER > 0x1010000fL
	if (cert && cert->value) OCSP_request_add1_cert(val, cert->value);

	if (otherCerts)
	{
		int i = 0;
		for (i = 0; i < PKI_STACK_X509_CERT_elements(otherCerts); i++) {
			PKI_X509_CERT *x = NULL;

			x = PKI_STACK_X509_CERT_get_num (otherCerts, i);
			if (x && x->value) {
				OCSP_request_add1_cert(val, x->value);
			}
		}
	}
#else

	OCSP_SIGNATURE *psig = NULL;
	psig = val->optionalSignature;

	if (psig)
	{
		if (psig->certs == NULL)
		{
			if((psig->certs = sk_X509_new_null()) == NULL)
			{
				PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
				return PKI_ERR;
			}
		}

		if ( cert && cert->value )
		{
			sk_X509_push( psig->certs, X509_dup ( cert->value ));
		}

		if (otherCerts)
		{
			int i = 0;
			for( i = 0; i < PKI_STACK_X509_CERT_elements(otherCerts); i++)
			{
				PKI_X509_CERT *x = NULL;

				x = PKI_STACK_X509_CERT_get_num (otherCerts, i);
				if (x && x->value)
				{
					sk_X509_push( psig->certs, X509_dup(x->value));
				}
			}
		}
	}
#endif

	return PKI_OK;

}

/*! \brief Signs a PKI_X509_OCSP_REQ object by using a token */

int PKI_X509_OCSP_REQ_sign_tk ( PKI_X509_OCSP_REQ *req, PKI_TOKEN *tk ) {

	const PKI_DIGEST_ALG *digest;

	if( !req || !tk ) return ( PKI_ERR );

	digest = PKI_X509_ALGOR_VALUE_get_digest(tk->algor);

	if (PKI_TOKEN_login(tk) != PKI_OK)
	{
		PKI_ERROR(PKI_ERR_HSM_LOGIN, NULL);
		return PKI_ERR;
	}

	return PKI_X509_OCSP_REQ_sign( req, tk->keypair, tk->cert, tk->cacert,
			tk->otherCerts, (EVP_MD *)digest );
}

/*! \brief Returns a pointer to the data present in the OCSP request
 */

void * PKI_X509_OCSP_REQ_get_data ( PKI_X509_OCSP_REQ *req,
						PKI_X509_DATA type ) {

	void * ret = NULL;
	int idx = -1;

#if OPENSSL_VERSION_NUMBER > 0x1010000fL
	LIBPKI_X509_OCSP_REQ *tmp_x = NULL;
#else
	PKI_X509_OCSP_REQ_VALUE *tmp_x = NULL;
#endif

	if( !req ) return NULL;

	tmp_x = req->value;

	switch ( type ) 
	{
		case PKI_X509_DATA_NONCE:
			idx = OCSP_REQUEST_get_ext_by_NID(tmp_x, NID_id_pkix_OCSP_Nonce, -1);
			if (idx >= 0)
			{
				X509_EXTENSION *ext = OCSP_REQUEST_get_ext(tmp_x, idx);
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
				if (ext) ret = X509_EXTENSION_get_data(ext);
#else
				if (ext) ret = ext->value;
/*
				if (ext) ret = PKI_STRING_new(ext->value->type,
						              (char *)ext->value->data,
							      (ssize_t) ext->value->length);
*/
#endif
			}
			break;

		case PKI_X509_DATA_NOTBEFORE:
		case PKI_X509_DATA_NOTAFTER:
			break;

		case PKI_X509_DATA_SIGNATURE:
			if ( tmp_x && tmp_x->optionalSignature ) {
				ret = tmp_x->optionalSignature->signature;
			}
			break;

		case PKI_X509_DATA_ALGORITHM:
		case PKI_X509_DATA_SIGNATURE_ALG1:
			if ( tmp_x && tmp_x->optionalSignature ) {
				ret = (void *) &(tmp_x->optionalSignature->signatureAlgorithm);
			}
			break;

		case PKI_X509_DATA_SIGNATURE_ALG2:
			break;

		/*
		case PKI_X509_DATA_TBS_MEM_ASN1:
			if((mem = PKI_MEM_new_null()) == NULL) break;
			mem->size = (size_t) ASN1_item_i2d ( (void *) tmp_x->tbsRequest, 
				&(mem->data), &OCSP_REQINFO_it );
			ret = mem;
			break;
		*/

		default:
			return NULL;
	}

	return ret;
}

/*! \brief Returns a char * representation of the data present in the
 *         OCSP request
 */

char * PKI_X509_OCSP_REQ_get_parsed ( PKI_X509_OCSP_REQ *req, 
						PKI_X509_DATA type ) {

	char *ret = NULL;

	if( !req ) return ( NULL );

	switch ( type ) {
		case PKI_X509_DATA_NONCE:
			ret = (char *) PKI_STRING_get_parsed((PKI_STRING *)
				PKI_X509_OCSP_REQ_get_data ( req, type ));
			break;
		case PKI_X509_DATA_NOTBEFORE:
		case PKI_X509_DATA_NOTAFTER:
			ret = (char *) PKI_TIME_get_parsed((PKI_TIME *)
				PKI_X509_OCSP_REQ_get_data ( req, type ));
			break;
		case PKI_X509_DATA_ALGORITHM:
			ret = (char *) PKI_X509_ALGOR_VALUE_get_parsed ( (PKI_X509_ALGOR_VALUE *)
				PKI_X509_OCSP_REQ_get_data ( req, type ));
			break;
		case PKI_X509_DATA_SIGNATURE:
			ret = (char *) PKI_X509_SIGNATURE_get_parsed(
				(PKI_X509_SIGNATURE *) 
					PKI_X509_OCSP_REQ_get_data ( req, type ));
			break;
		default:
			return ( NULL );
	}

	return ( ret );
}

/*! \brief Prints the requested data from the OCSP request to the file
 *         descriptor passed as an argument
 */

int PKI_X509_OCSP_REQ_print_parsed ( PKI_X509_OCSP_REQ *req, 
				PKI_X509_DATA type, int fd ) {

	const char *str = NULL;
	int ret = PKI_OK;

	if( !req ) return ( PKI_ERR );

	if((str = PKI_X509_OCSP_REQ_get_parsed ( req, type )) == NULL ) {
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

/*! \brief Checks the NONCE between a Request and a Response */
int PKI_OCSP_nonce_check ( PKI_X509_OCSP_REQ *req, 
						PKI_X509_OCSP_RESP *resp ) {

	PKI_OCSP_RESP *r = NULL;

	if (!req || !req->value || !resp || !resp->value ) return PKI_ERR;

	r = resp->value;

	if (!r->bs) return PKI_ERR;

	if (OCSP_check_nonce (req->value, r->bs ) < 0 ) {
		PKI_log_debug("Cryto Lib Err::%s",
			ERR_error_string(ERR_get_error(), NULL ));
		return PKI_ERR;
	}

	return PKI_OK;
}


/* PEM <-> INTERNAL Macros --- fix for errors in OpenSSL */
PKI_X509_OCSP_REQ_VALUE *PEM_read_bio_OCSP_REQ( PKI_IO *bp, void *a, 
						void *b, void *c ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
        return (PKI_X509_OCSP_REQ_VALUE *) PEM_ASN1_read_bio( (char *(*)()) d2i_OCSP_REQUEST,
                                PEM_STRING_OCSP_REQUEST, bp, NULL, NULL, NULL);
#else
        return (PKI_X509_OCSP_REQ_VALUE *) PEM_ASN1_read_bio( (void *(*)()) d2i_OCSP_REQUEST,
                                PEM_STRING_OCSP_REQUEST, bp, NULL, NULL, NULL);
#endif
}

int PEM_write_bio_OCSP_REQ( PKI_IO *bp, PKI_X509_OCSP_REQ_VALUE *o ) {
	return PEM_ASN1_write_bio ( (int (*)())i2d_OCSP_REQUEST, 
			PEM_STRING_OCSP_REQUEST, bp, (char *) o, NULL, 
				NULL, 0, NULL, NULL );
}

PKI_X509_OCSP_REQ_VALUE *d2i_OCSP_REQ_bio ( PKI_IO *bp, 
					PKI_X509_OCSP_REQ_VALUE *p ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
        return (PKI_X509_OCSP_REQ_VALUE *) ASN1_d2i_bio(
                        (char *(*)(void))OCSP_REQUEST_new,
                        (char *(*)(void **, const unsigned char **, long))
							d2i_OCSP_REQUEST,
                        bp, (unsigned char **) &p);
#else
        return (PKI_X509_OCSP_REQ_VALUE *) ASN1_d2i_bio(
                        (void *(*)(void))OCSP_REQUEST_new,
                        (void *(*)(void **, const unsigned char **, long))
							d2i_OCSP_REQUEST,
                        bp, (void **) &p);
#endif
}

int i2d_OCSP_REQ_bio(PKI_IO *bp, PKI_X509_OCSP_REQ_VALUE *o ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
        return ASN1_i2d_bio( (int (*)(OCSP_REQUEST *, unsigned char **)) i2d_OCSP_REQUEST, bp, (unsigned char *) o);
#else
        return ASN1_i2d_bio( (i2d_of_void *) i2d_OCSP_REQUEST, bp, (unsigned char *) o);
#endif
}

