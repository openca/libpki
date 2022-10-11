/* PKI_X509_OCSP_RESP object management */

#include <libpki/pki.h>
#include "internal/x509_data_st.h"

/* ---------------------------- Memory Management ----------------------- */

/*! \brief Generates an empty OCSP request  */

PKI_OCSP_RESP *PKI_OCSP_RESP_new ( void )
{
	// Crypto Provider's specific data structures
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
	LIBPKI_X509_OCSP_RESPONSE  * r = NULL;
	LIBPKI_X509_OCSP_BASICRESP * bs = NULL;
#else
	PKI_X509_OCSP_RESP_VALUE * r = NULL;
	OCSP_BASICRESP           * bs = NULL;
#endif

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
			const PKI_TIME *revokeTime, 
			const PKI_TIME *thisUpdate,
			const PKI_TIME *nextUpdate, 
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
			(int)status, (int)reason, 
			(ASN1_TIME *)revokeTime, 
			(ASN1_TIME*)myThisUpdate,
			(ASN1_TIME*)nextUpdate))== NULL)
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
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
	PKI_OID * obj = NULL;
	
	if ((obj = PKI_OID_get("1.3.6.1.5.5.7.48.1.9")) != NULL) {

		// Sets the Object, Criticality, and Value
		X509_EXTENSION_set_object(ext_val, obj);
		X509_EXTENSION_set_critical(ext_val, 0);
		X509_EXTENSION_set_data(ext_val, NULL);

		// Free the Allocated Memory
		PKI_OID_free(obj);
	}
#else
	ext_val->object = PKI_OID_get("1.3.6.1.5.5.7.48.1.9");

	// Let's now set the non-critical flag and the value should be NULL
	ext_val->critical = 0;
	ext_val->value = NULL;
#endif

	// Let's add the extension to the basicresponse
	if (!OCSP_BASICRESP_add_ext(bs, ext_val, -1)) {
		// Free memory and return error
		X509_EXTENSION_free(ext_val);
		return PKI_ERR;
	}

	// Done
	return PKI_OK;
}

int PKI_X509_OCSP_RESP_DATA_sign (PKI_X509_OCSP_RESP * resp, 
								  PKI_X509_KEYPAIR   * k, 
								  PKI_DIGEST_ALG     * md ) {

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
	if (!md) md = (PKI_DIGEST_ALG *) PKI_DIGEST_ALG_get_default(k);

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

int PKI_X509_OCSP_RESP_set_keytype_by_key_value(PKI_X509_OCSP_RESP     		 * x, 
										  		const PKI_X509_KEYPAIR_VALUE * const key) {

	// Input Checks
	if (!x || !key) {
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
	}

	// Basic Response Checks
	PKI_OCSP_RESP * resp = PKI_X509_get_value(x);
	if (!resp) {
		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Missing internal value");
	}

	OCSP_RESPDATA * data = (OCSP_RESPDATA *)OCSP_resp_get0_respdata(resp->bs);
	if (!data) {
		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot retrieve the respdata");
	}

	OCSP_RESPID * rid = NULL;

	// Assigns the value to the response
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
	rid = &(data->responderId);
#else
	rid = data->responderId;
#endif

	// Exports the Key into a PKI_MEM (ASN1/DER)
	PKI_MEM * mem_der = PKI_X509_put_mem_value((void *)key, PKI_DATATYPE_X509_KEYPAIR, NULL, PKI_DATA_FORMAT_ASN1, NULL, NULL);
	if (!mem_der) {
		// Error Condition
		return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
	}

	// Calculates the digest over the DER representation
	PKI_DIGEST * digest = PKI_DIGEST_MEM_new(PKI_DIGEST_ALG_SHA1, mem_der);
	if (!digest) {
		if (mem_der) PKI_MEM_free(mem_der);
		return PKI_ERROR(PKI_ERR_DIGEST_VALUE_NULL, NULL);
	}

	// Free Memory
	PKI_MEM_free(mem_der);
	mem_der = NULL;

	// Builds the value string
	PKI_STRING * value = PKI_STRING_new(PKI_STRING_OCTET, 
										(char *) digest->digest,
										(ssize_t) digest->size);

	// Free the Digest memory
	if (digest) PKI_DIGEST_free(digest);
	digest = NULL;

	// Checks the result of the allocation
	if (!value) {
		return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
	}

	// Assigns the value
	rid->type = PKI_X509_OCSP_RESPID_TYPE_BY_KEYID;
	rid->value.byKey = value;

	// All Done
	return PKI_OK;
}

int PKI_X509_OCSP_RESP_set_keytype_by_key(PKI_X509_OCSP_RESP     * x, 
										  const PKI_X509_KEYPAIR * const key) {

	// Input Checks
	if (!x || !key || !key->value) {
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
	}

	return PKI_X509_OCSP_RESP_set_keytype_by_key_value(x, (const PKI_X509_KEYPAIR_VALUE *)PKI_X509_get_value(key));

// 	// Basic Response Checks
// 	PKI_OCSP_RESP * resp = PKI_X509_get_value(x);
// 	if (!resp) {
// 		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Missing internal value");
// 	}

// 	OCSP_RESPDATA * data = OCSP_resp_get0_respdata(resp->bs);
// 	if (!data) {
// 		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot retrieve the respdata");
// 	}

// 	OCSP_RESPID * rid = NULL;

// 	// Assigns the value to the response
// #if OPENSSL_VERSION_NUMBER > 0x1010000fL
// 	rid = &(data->responderId);
// #else
// 	rid = data->responderId;
// #endif

// 	// Exports the Key into a PKI_MEM (ASN1/DER)
// 	PKI_MEM * mem_der = PKI_X509_put_mem(key, PKI_DATA_FORMAT_ASN1, NULL, NULL);
// 	if (!mem_der) {
// 		// Error Condition
// 		return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
// 	}

// 	// Calculates the digest over the DER representation
// 	PKI_DIGEST * digest = PKI_DIGEST_MEM_new(PKI_DIGEST_ALG_SHA1, mem_der);
// 	if (!digest) {
// 		if (mem_der) PKI_MEM_free(mem_der);
// 		return PKI_ERROR(PKI_ERR_DIGEST_VALUE_NULL, NULL);
// 	}

// 	// Free Memory
// 	PKI_MEM_free(mem_der);
// 	mem_der = NULL;

// 	// Builds the value string
// 	PKI_STRING * value = PKI_STRING_new(PKI_STRING_OCTET, 
// 										digest->digest,
// 										digest->size);

// 	// Checks the result of the allocation
// 	if (!value) {
// 		PKI_DIGEST_free(digest);
// 		return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
// 	}

// 	// Assigns the value
// 	rid->type = PKI_X509_OCSP_RESPID_TYPE_BY_KEYID;
// 	rid->value.byKey = value;

// 	// All Done
// 	return PKI_OK;
}

int PKI_X509_OCSP_RESP_set_keytype_by_cert(PKI_X509_OCSP_RESP  * x,
										   const PKI_X509_CERT * const cert) {

	unsigned char dst_buffer[EVP_MAX_MD_SIZE];
		// Output buffer for digest calculation

	OCSP_RESPID * rid = NULL;
		// Pointer to the internal responder Id

	// Input Checks
	if (!x || !cert || !cert->value) {
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
	}

	// Basic Response Checks
	PKI_OCSP_RESP * resp = PKI_X509_get_value(x);
	if (!resp) {
		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Missing internal value");
	}

	OCSP_RESPDATA * data = (OCSP_RESPDATA *)OCSP_resp_get0_respdata(resp->bs);
	if (!data) {
		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot retrieve the respdata");
	}

	// Let's extract the key
	PKI_BIT_STRING * key = (PKI_BIT_STRING *)PKI_X509_CERT_get_data(cert, PKI_X509_DATA_PUBKEY_BITSTRING);
	if (!key) {
		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot extract the key from the certificate");
	}

	if (PKI_OK != PKI_DIGEST_new_value((unsigned char **)&dst_buffer,
									   PKI_DIGEST_ALG_SHA1, 
									   key->data, 
									   (size_t) key->length)) {
        return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot calculate the key identifier");
	}

	// Builds the value string
	PKI_STRING * value = PKI_STRING_new(PKI_STRING_OCTET, 
										(char *) dst_buffer,
										EVP_MD_size(PKI_DIGEST_ALG_SHA1));

	// Checks the result of the allocation
	if (!value) {
		// Error Condition
		return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
	}

	// Assigns the value to the response
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
	rid = &(data->responderId);
#else
	rid = data->responderId;
#endif

	// Assigns the value
	rid->type = PKI_X509_OCSP_RESPID_TYPE_BY_KEYID;
	rid->value.byKey = value;

	// All Done
	return PKI_OK;

}

int PKI_X509_OCSP_RESP_set_nametype_by_cert(PKI_X509_OCSP_RESP * x,
											const PKI_X509     * const cert) {
	
	// Input Checks
	if (!x || !cert || !cert->value) 
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	OCSP_RESPID * rid = NULL;
		// Pointer to the internal responder Id

	// Basic Response Checks
	PKI_OCSP_RESP * resp = PKI_X509_get_value(x);
	if (!resp) {
		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Missing internal value");
	}

	// Gets the OCSP response data
	OCSP_RESPDATA * data = (OCSP_RESPDATA *)OCSP_resp_get0_respdata(resp->bs);
	if (!data) {
		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot retrieve the respdata");
	}

	// Assigns the value to the response
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
	rid = &(data->responderId);
#else
	rid = data->responderId;
#endif

	// Sets the Name
	if (!X509_NAME_set(&rid->value.byName, (PKI_X509_NAME *)PKI_X509_CERT_get_data(cert, PKI_X509_DATA_SUBJECT))) {
		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot extract the name from the signer's certificate");
	}

	// Sets the Responder Type
	rid->type = PKI_X509_OCSP_RESPID_TYPE_BY_NAME;

	// All Done
	return PKI_OK;
}

int PKI_X509_OCSP_RESP_set_nametype_by_name(PKI_X509_OCSP_RESP  * x, 
											const PKI_X509_NAME * const name) {

	// Input Checks
	if (!x || !name) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	OCSP_RESPID * rid = NULL;
		// Pointer to the internal responder Id

	// Basic Response Checks
	PKI_OCSP_RESP * resp = PKI_X509_get_value(x);
	if (!resp) {
		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Missing internal value");
	}

	// Gets the OCSP response data
	OCSP_RESPDATA * data = (OCSP_RESPDATA *)OCSP_resp_get0_respdata(resp->bs);
	if (!data) {
		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot retrieve the respdata");
	}

	// Assigns the value to the response
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
	rid = &(data->responderId);
#else
	rid = data->responderId;
#endif

	// Sets the Name
	if (!X509_NAME_set(&rid->value.byName, (PKI_X509_NAME *)name)) {
		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot extract the name from the signer's certificate");
	}

	// Sets the Responder Type
	rid->type = PKI_X509_OCSP_RESPID_TYPE_BY_NAME;

	// All Done
	return PKI_OK;
}

int PKI_X509_OCSP_RESP_set_createdAt(PKI_X509_OCSP_RESP * x, int offset) {

	// Input Checks
	if (!x) return PKI_ERR;

	PKI_TIME * time = NULL;
		// Time String

	// Basic Response Checks
	PKI_OCSP_RESP * resp = PKI_X509_get_value(x);
	if (!resp) {
		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Missing internal value");
	}

	// Gets the OCSP response data
	OCSP_RESPDATA * data = (OCSP_RESPDATA *)OCSP_resp_get0_respdata(resp->bs);
	if (!data) {
		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot retrieve the respdata");
	}

	// Assigns the value to the response
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
	time = data->producedAt;
#else
	time = data->producedAt;
#endif

	// Adjust the offset (0) to the GMT time
	if (X509_gmtime_adj(time, 0) == NULL) {
		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot set the createdAt time");
	}

	// All Done
	return PKI_OK;
}

/*! \brief Signs a PKI_X509_OCSP_RESP, for a simpler API use PKI_X509_OCSP_RESP_sign_tk */
int PKI_X509_OCSP_RESP_sign(PKI_X509_OCSP_RESP        * resp, 
							PKI_X509_KEYPAIR          * keypair,
							PKI_X509_CERT             * cert, 
							PKI_X509_CERT             * issuer,
							PKI_X509_CERT_STACK       * otherCerts,
							PKI_DIGEST_ALG            * digest,
							PKI_X509_OCSP_RESPID_TYPE   respidType) {

	PKI_OCSP_RESP *r = NULL;
		// LibPKI's OCSP Response representation

	if (!resp || !resp->value || !keypair || !keypair->value) {
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
	}

	// Let's get the value
	r = resp->value;
	if (!r->resp || !r->bs) {
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
	}

	// Checks the certificates
	if (!cert || !cert->value ) {
		PKI_DEBUG("Signing an OCSP_RESP without a cert");
	}

	if (!issuer || !issuer->value ) {
		PKI_DEBUG("Signing an OCSP_RESP without the issuer's certificate!");
	}

	// Sets the Responder ID
	if (respidType == PKI_X509_OCSP_RESPID_TYPE_BY_NAME) {
		// Name is required
		if (!cert) {
			return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Signer's certificate is required for name respID types");
		}
		// Name Type
		if (PKI_OK != PKI_X509_OCSP_RESP_set_nametype_by_cert(resp, cert)) {
			return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot set responder type to name by cert");
		}
	} else {
PKI_DEBUG("[TEST]");

		// Key Type
		if (PKI_OK != PKI_X509_OCSP_RESP_set_keytype_by_key(resp, keypair)) {
			return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot set responder type to key by key");
		}
	}
PKI_DEBUG("[TEST]");

	// Sets the createdAt time
	if (PKI_OK != PKI_X509_OCSP_RESP_set_createdAt(resp, 0)) {
		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot set the createdAt field");
	}
PKI_DEBUG("[TEST]");

// #if OPENSSL_VERSION_NUMBER > 0x1010000fL
	
// 	if (PKI_OK != PKI_X509_OCSP_RESP_set_keytype_by_cert(resp, cert)) {
// 		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot set responder type to key");
// 	}

// 	// // Let's get the responderId
// 	// rid = &(r->bs->tbsResponseData.responderId);

// 	// // Set the appropriate by name or by key
// 	// if (respidType == PKI_X509_OCSP_RESPID_TYPE_BY_NAME) {

// 	// 	if (!cert) {
// 	// 		return PKI_ERROR(PKI_ERR, 
// 	// 		"PKI_OCSP_RESPID_TYPE_BY_NAME requires signer's certificate");
// 	// 	}

// 	// 	if (1 != OCSP_RESPID_set_by_name(rid, cert->value)) {
// 	// 		return PKI_ERROR(PKI_ERR, "Can not set RESPID by name");
// 	// 	}

// 	// } else {

// 	// 	if (1 != OCSP_RESPID_set_by_key(rid, cert->value)) {
// 	// 		return PKI_ERROR(PKI_ERR, "Can not set RESPID by key");
// 	// 	}
// 	// }

// 	if ((time = X509_gmtime_adj(r->bs->tbsResponseData.producedAt, 0)) == 0)
// 		PKI_log_err("Error adding signed time to response");

// 	// if (!r->bs->tbsResponseData.producedAt)
// 	//	r->bs->tbsResponseData.producedAt = time;

// #else

// 	// Gets the responderId
// 	rid = r->bs->tbsResponseData->responderId;

// 	// Only if we do have a certificate we might want
// 	// to set the ResponderID
// 	if (!cert) {
// 		// We can not add the responder's ID because
// 		// there is no signer's certificate
// 		PKI_log_err("Can not set the responder ID (missing signer's cert) [RID Type: %d (%s)]",
// 			respidType, respidType == PKI_X509_OCSP_RESPID_TYPE_BY_NAME ? "name" : "keyid");
// 		// Failed
// 		return PKI_ERR;
// 	}

// 	// Sets the responderId
// 	if (respidType == PKI_X509_OCSP_RESPID_TYPE_BY_NAME)
// 	{
// 		char * parsed = PKI_X509_CERT_get_parsed(cert, PKI_X509_DATA_SUBJECT);
// 		PKI_log_debug("RESPONDER BY NAME => BY NAME [%s]", parsed);
// 		PKI_Free(parsed);
// 		parsed = NULL;

// 		if (!cert) {
// 			PKI_log_err("PKI_OCSP_RESPID_TYPE_BY_NAME requires signer's certificate");
// 			return PKI_ERR;
// 		}

// 		if (!X509_NAME_set(&rid->value.byName, X509_get_subject_name(cert->value)))
// 		{
// 			PKI_log_err("Internal Error");
// 			return PKI_ERR;
// 		}

// 		rid->type = V_OCSP_RESPID_NAME;

// 	}
// 	else if (respidType == PKI_X509_OCSP_RESPID_TYPE_BY_KEYID)
// 	{
// 		PKI_MEM * mem_buf = PKI_MEM_new_data(SHA_DIGEST_LENGTH, NULL);

// 		if (1 != X509_pubkey_digest(cert->value, EVP_sha1(), mem_buf->data, NULL)) {
// 			PKI_log_err("Can not get the ResponderID (SHA1 of PublicKey)"
// 					" from the server's certificate, aborting.");
// 			return PKI_ERR;
// 		}

// 		rid->type = V_OCSP_RESPID_KEY;
// 		if ((rid->value.byKey = ASN1_OCTET_STRING_new()) == NULL)
// 		{
// 			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
// 			PKI_MEM_free(mem_buf);
// 			return PKI_ERR;
// 		}

// 		if (!ASN1_OCTET_STRING_set(rid->value.byKey, mem_buf->data, (int) mem_buf->size))
// 		{
// 			PKI_log_err("Can not assign Responder Id by Key (Internal Error!)");
// 			PKI_MEM_free(mem_buf);
// 			return PKI_ERR;
// 		}

// 		// All done here.
// 		PKI_MEM_free(mem_buf);
// 	}
// 	else
// 	{
// 		// Error, we have a value we do not recognize
// 		PKI_log_err("ResponderID Type NOT recognized, skipped.");
// 	}


// 	if ((time = X509_gmtime_adj(r->bs->tbsResponseData->producedAt, 0)) == 0)
// 		PKI_log_err("Error adding signed time to response");

// 	// if (!r->bs->tbsResponseData->producedAt)
// 	//	r->bs->tbsResponseData->producedAt = time;

// #endif

	if (!(r->resp->responseBytes = OCSP_RESPBYTES_new())) {
		return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate the responseBytes structure");
	}
PKI_DEBUG("[TEST]");

	OCSP_RESPBYTES * r_bytes = OCSP_RESPBYTES_new();
	if (!r_bytes) {
		return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate the RESP");
	}
PKI_DEBUG("[TEST]");

	PKI_OID * OCSP_basic = OBJ_nid2obj(NID_id_pkix_OCSP_basic);
	if (!OCSP_basic) {
		return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate the OID for responseType");
	}
	r_bytes->responseType = OCSP_basic;
PKI_DEBUG("[TEST]");

	r->resp->responseBytes = r_bytes;
PKI_DEBUG("[TEST]");
	
	// if (!r_bytes) {
	// 	return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate the RESP")
	// if((r->resp->responseBytes->responseType = 
	// 		OBJ_nid2obj(NID_id_pkix_OCSP_basic)) == NULL )
	// {
	// 	PKI_log_debug("id-pkix-ocsp-basic OID error");
	// 	return PKI_ERR;
	// }

	/* If there's old certs, let's clean the stack */
	if (r && r->bs && r->bs->certs)	{

PKI_DEBUG("[TEST]");
		PKI_X509_CERT_VALUE *tmp_cert = NULL;
			// Certificate Pointer

		// Cycle through the list of certificates and
		// free them after removing them from the list
		while((tmp_cert = sk_X509_pop( r->bs->certs )) != NULL ) {
			// Free Memory
			X509_free(tmp_cert);
		}
	} else {
PKI_DEBUG("[TEST]");
		// Creates a new empty stack & check for errors
		r->bs->certs = sk_X509_new_null();
		if (r->bs->certs == NULL) {
			return PKI_ERROR(PKI_ERR_OCSP_RESP_SIGN, "ERROR, Can not Create stack of certificate in the response");
		}
	}
PKI_DEBUG("[TEST]");

	/* Let's push the signer's certificate */
	if ( cert ) OCSP_basic_add1_cert(r->bs, cert->value);
PKI_DEBUG("[TEST]");

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
	if (!digest) digest = (PKI_DIGEST_ALG *)PKI_X509_ALGOR_VALUE_get_digest(tk->algor);

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

const void * PKI_X509_OCSP_RESP_get_data(PKI_X509_OCSP_RESP * r,
					 PKI_X509_DATA        type) {

	const void * ret = NULL;
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
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
				if (ext) ret = X509_EXTENSION_get_data(ext);
#else
				if (ext) ret = ext->value;
				/*
				if (ext) ret = PKI_STRING_new(ext->value->type,
						(char *) ext->value->data, (ssize_t) ext->value->length);
				*/
#endif
			}
			break;

		case PKI_X509_DATA_NOTBEFORE:
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
			ret = OCSP_resp_get0_produced_at(tmp_x);
#else
			ret = tmp_x->tbsResponseData->producedAt;
#endif
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
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
			if (tmp_x) ret = &(tmp_x->signatureAlgorithm);
#else
			if ( tmp_x && tmp_x->signatureAlgorithm ) {
				ret = tmp_x->signatureAlgorithm;
			}
#endif
			break;

		case PKI_X509_DATA_SIGNATURE_ALG2:
			break;

		case PKI_X509_DATA_TBS_MEM_ASN1:
			if ((mem = PKI_MEM_new_null()) == NULL)
			{
				PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL );
				break;
			}
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
			mem->size = (size_t)ASN1_item_i2d((void *)&(tmp_x->tbsResponseData),
				&(mem->data), &OCSP_RESPDATA_it );
#else
			mem->size = (size_t)ASN1_item_i2d((void *)tmp_x->tbsResponseData, 
				&(mem->data), &OCSP_RESPDATA_it );
#endif
			ret = mem;
			break;

		default:
			PKI_log_err("Requested data not supported [Type: %d]", type);
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
			ret = (char *) PKI_X509_ALGOR_VALUE_get_parsed ( (PKI_X509_ALGOR_VALUE *)
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

int PKI_X509_OCSP_resp_bytes_encode (PKI_X509_OCSP_RESP * resp) {

	PKI_OCSP_RESP * r = NULL;
		// OCSP Value

  OCSP_BASICRESP *bsrp = NULL;
    // OCSP Basic Response Value

	PKI_X509_OCSP_RESP_VALUE *resp_val = NULL;
	  // OCSP Response Value

	// Input Check
	if (!resp || !resp->value) return PKI_ERR;

	// Shortcut for the value
	r = resp->value;

  // Now we need to re-encode the basicresp
  resp_val = r->resp;
  bsrp = r->bs;

  // If an already encoded value exists, remove it
  if (resp_val->responseBytes)
  	OCSP_RESPBYTES_free(resp_val->responseBytes);

  // Allocates the memory
  if (!(resp_val->responseBytes = OCSP_RESPBYTES_new()))
    return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);

  // Sets the OCSP basic bit
  resp_val->responseBytes->responseType = 
  	OBJ_nid2obj(NID_id_pkix_OCSP_basic);

  // Encodes the basic response
  if (bsrp) {

	  // Now add the encoded data to the request bytes
	  if (!ASN1_item_pack(bsrp,
	  	                  ASN1_ITEM_rptr(OCSP_BASICRESP),
	  	                  &resp_val->responseBytes->response)) {

	  	// Error while encoding the basic response
	    return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, NULL);
	  }
  }

  // Success
  return PKI_OK;
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

