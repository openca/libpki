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
	PKI_X509_OCSP_RESP_VALUE * ret = NULL;

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
	ret = (PKI_X509_OCSP_RESP_VALUE *) PKI_Malloc (sizeof(PKI_X509_OCSP_RESP_VALUE));
	if (!ret) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		if ( bs ) OCSP_BASICRESP_free ( bs );
		if ( r  ) OCSP_RESPONSE_free ( r );
		return NULL;
	}

	// Sets the CTX for the OCSP_RESPONSE generation (at encoding time)
	ret->status = PKI_X509_OCSP_RESP_STATUS_SUCCESSFUL;

	// Transfer ownership of bs to the container
	ret->bs   = bs;
	ret->resp = r;

	// Success - object created
	return ret;
}


void PKI_OCSP_RESP_free( PKI_OCSP_RESP *x )
{
	// if no PKI_X509_OCSP_RESP is passed, let's return an error
	if (!x) return;

	// Free the memory
	if( x->resp ) OCSP_RESPONSE_free(x->resp);
	if( x->bs ) OCSP_BASICRESP_free (x->bs);

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

int PKI_X509_OCSP_RESP_set_status (PKI_X509_OCSP_RESP 		 * x, 
								   PKI_X509_OCSP_RESP_STATUS   status ) {

	PKI_X509_OCSP_RESP_VALUE * r = NULL;
		// LibPKI OCSP Response representation
	
	// Input Checks
	if ( !x || !x->value ) return PKI_ERR;

	// Gets the internal value
	r = PKI_X509_get_value(x);
	if (!r) {
		PKI_ERROR(PKI_ERR_POINTER_NULL, NULL);
		return PKI_ERR;
	}

	// Sets the value
	r->status = status;

	// if (!(ASN1_ENUMERATED_set(r->resp->responseStatus, status)))
	// 		return PKI_ERR;

	// All Done
	return PKI_OK;
}

/*! \brief Adds one basic request (one certificate) to the request by using
 *         the passed PKI_INTEGER as the serial number of the certificate */

int PKI_X509_OCSP_RESP_add (PKI_X509_OCSP_RESP *resp, 
							OCSP_CERTID *cid, 
							PKI_OCSP_CERTSTATUS status,
							const PKI_TIME *revokeTime, 
							const PKI_TIME *thisUpdate,
							const PKI_TIME *nextUpdate, 
							PKI_X509_CRL_REASON reason,
							PKI_X509_EXTENSION *invalidityDate ) {

	OCSP_SINGLERESP *single = NULL;
	PKI_TIME *myThisUpdate = NULL;

	PKI_X509_OCSP_RESP_VALUE *r = NULL;

	// Input Checks
	if (!resp || !resp->value|| !cid) {
		PKI_DEBUG("Missing resp (%p) or cid (%p)", resp, cid);
		return PKI_ERR;
	}

	// Gets the internal value
	r = (PKI_X509_OCSP_RESP_VALUE *) PKI_X509_get_value(resp);
	if (!r->bs) {
		// Creates the basic response object
		if ((r->bs = OCSP_BASICRESP_new()) == NULL) {
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			return PKI_ERR;
		}
	}

	// If no thisUpdate is passed, let's use the current time
	if (thisUpdate == NULL) {
		myThisUpdate = X509_gmtime_adj(NULL,0);
	} else {
		myThisUpdate = PKI_TIME_dup(thisUpdate);
	}

	single = OCSP_basic_add1_status(r->bs, 
									cid,
									(int) status, 
									(int) reason, 
									(ASN1_TIME *) revokeTime, 
									(ASN1_TIME *) myThisUpdate,
									(ASN1_TIME *) nextUpdate);

	// Free allocated memory
	if (myThisUpdate) PKI_TIME_free(myThisUpdate);
	
	// Checks the result
	if (single == NULL)	{
		PKI_log_err ("Can not create basic entry!");
		return PKI_ERR;
	}

	// Let's add the invalidity date if present
	if (invalidityDate) {
		if (!OCSP_SINGLERESP_add1_ext_i2d(single,
                						  NID_invalidity_date, 
										  invalidityDate, 
										  0, 
										  0)) {
			PKI_log_err("Can not create extension entry for response!");
			return PKI_ERR;
		}
	}

	// All Done
	return PKI_OK;
}

/*!
 * \brief set the id-pkix-ocsp-extended-revoke extension in the response
 */ 

int PKI_X509_OCSP_RESP_set_extendedRevoke(PKI_X509_OCSP_RESP * resp) {

	PKI_X509_OCSP_RESP_VALUE * resp_val = NULL;
	PKI_X509_EXTENSION_VALUE * ext_val = NULL;
	OCSP_BASICRESP *bs = NULL;

	// Input Checks
	if (!resp || !resp->value) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	// Checks we have the basic response
	resp_val = (PKI_X509_OCSP_RESP_VALUE *) PKI_X509_get_value(resp);
	if (!resp_val) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	// Gets the basic response
	bs = resp_val->bs;
	if (!bs) {
		PKI_ERROR(PKI_ERR_POINTER_NULL, NULL);
		return PKI_ERR;
	}

	// Allocates the memory
	if ((ext_val = X509_EXTENSION_new()) == NULL) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, 0);
		return PKI_ERR;
	}

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

// int PKI_X509_OCSP_RESP_set_keytype_by_key_value(PKI_X509_OCSP_RESP     		 * x, 
// 										  		const PKI_X509_KEYPAIR_VALUE * const key) {

// 	// Input Checks
// 	if (!x || !key) {
// 		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
// 	}

// 	// Basic Response Checks
// 	PKI_X509_OCSP_RESP_VALUE * resp = PKI_X509_get_value(x);
// 	if (!resp) {
// 		PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Missing internal value");
// 		return PKI_ERR;
// 	}

// 	OCSP_RESPDATA * data = (OCSP_RESPDATA *)OCSP_resp_get0_respdata(resp->bs);
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

// 	// Calculates the digest over the DER representation
// 	PKI_DIGEST * digest = PKI_X509_KEYPAIR_VALUE_pub_digest(key, PKI_DIGEST_ALG_SHA1);
// 	if (!digest) {
// 		return PKI_ERROR(PKI_ERR_DIGEST_VALUE_NULL, NULL);
// 	}

// 	// Builds the value string
// 	PKI_STRING * value = PKI_STRING_new(PKI_STRING_OCTET, 
// 										(char *) digest->digest,
// 										(ssize_t) digest->size);

// 	// Free the Digest memory
// 	if (digest) PKI_DIGEST_free(digest);
// 	digest = NULL;

// 	// Checks the result of the allocation
// 	if (!value) {
// 		return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
// 	}

// 	// Assigns the value
// 	rid->type = PKI_X509_OCSP_RESPID_TYPE_BY_KEYID;
// 	rid->value.byKey = value;

// 	// All Done
// 	return PKI_OK;
// }

// int PKI_X509_OCSP_RESP_set_keytype_by_key(PKI_X509_OCSP_RESP     * x, 
// 										  const PKI_X509_KEYPAIR * const key) {

// 	// Input Checks
// 	if (!x || !key || !key->value) {
// 		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
// 	}

// 	return PKI_X509_OCSP_RESP_set_keytype_by_key_value(x, key->value);
// }

// int PKI_X509_OCSP_RESP_set_keytype_by_cert(PKI_X509_OCSP_RESP  * x,
// 										   const PKI_X509_CERT * const cert) {

// 	unsigned char dst_buffer[EVP_MAX_MD_SIZE];
// 		// Output buffer for digest calculation

// 	OCSP_RESPID * rid = NULL;
// 		// Pointer to the internal responder Id

// 	// Input Checks
// 	if (!x || !cert || !cert->value) {
// 		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
// 	}

// 	// Basic Response Checks
// 	PKI_OCSP_RESP * resp = PKI_X509_get_value(x);
// 	if (!resp) {
// 		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Missing internal value");
// 	}

// 	OCSP_RESPDATA * data = (OCSP_RESPDATA *)OCSP_resp_get0_respdata(resp->bs);
// 	if (!data) {
// 		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot retrieve the respdata");
// 	}

// 	// Let's extract the key
// 	PKI_BIT_STRING * key = (PKI_BIT_STRING *)PKI_X509_CERT_get_data(cert, PKI_X509_DATA_PUBKEY_BITSTRING);
// 	if (!key) {
// 		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot extract the key from the certificate");
// 	}

// 	if (PKI_OK != PKI_DIGEST_new_value((unsigned char **)&dst_buffer,
// 									   PKI_DIGEST_ALG_SHA1, 
// 									   key->data, 
// 									   (size_t) key->length)) {
//         return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot calculate the key identifier");
// 	}

// 	// Builds the value string
// 	PKI_STRING * value = PKI_STRING_new(PKI_STRING_OCTET, 
// 										(char *) dst_buffer,
// 										EVP_MD_size(PKI_DIGEST_ALG_SHA1));

// 	// Checks the result of the allocation
// 	if (!value) {
// 		// Error Condition
// 		return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
// 	}

// 	// Assigns the value to the response
// #if OPENSSL_VERSION_NUMBER > 0x1010000fL
// 	rid = &(data->responderId);
// #else
// 	rid = data->responderId;
// #endif

// 	// Assigns the value
// 	rid->type = PKI_X509_OCSP_RESPID_TYPE_BY_KEYID;
// 	rid->value.byKey = value;

// 	// All Done
// 	return PKI_OK;

// }

// int PKI_X509_OCSP_RESP_set_nametype_by_cert(PKI_X509_OCSP_RESP * x,
// 											const PKI_X509     * const cert) {
	
// 	// Input Checks
// 	if (!x || !cert || !cert->value) 
// 		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

// 	OCSP_RESPID * rid = NULL;
// 		// Pointer to the internal responder Id

// 	// Basic Response Checks
// 	PKI_OCSP_RESP * resp = PKI_X509_get_value(x);
// 	if (!resp) {
// 		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Missing internal value");
// 	}

// 	// Gets the OCSP response data
// 	OCSP_RESPDATA * data = (OCSP_RESPDATA *)OCSP_resp_get0_respdata(resp->bs);
// 	if (!data) {
// 		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot retrieve the respdata");
// 	}

// 	// Assigns the value to the response
// #if OPENSSL_VERSION_NUMBER > 0x1010000fL
// 	rid = &(data->responderId);
// #else
// 	rid = data->responderId;
// #endif

// 	// Sets the Name
// 	if (!X509_NAME_set(&rid->value.byName, (PKI_X509_NAME *)PKI_X509_CERT_get_data(cert, PKI_X509_DATA_SUBJECT))) {
// 		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot extract the name from the signer's certificate");
// 	}

// 	// Sets the Responder Type
// 	rid->type = PKI_X509_OCSP_RESPID_TYPE_BY_NAME;

// 	// All Done
// 	return PKI_OK;
// }

// int PKI_X509_OCSP_RESP_set_nametype_by_name(PKI_X509_OCSP_RESP  * x, 
// 											const PKI_X509_NAME * const name) {

// 	// Input Checks
// 	if (!x || !name) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

// 	OCSP_RESPID * rid = NULL;
// 		// Pointer to the internal responder Id

// 	// Basic Response Checks
// 	PKI_OCSP_RESP * resp = PKI_X509_get_value(x);
// 	if (!resp) {
// 		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Missing internal value");
// 	}

// 	// Gets the OCSP response data
// 	OCSP_RESPDATA * data = (OCSP_RESPDATA *)OCSP_resp_get0_respdata(resp->bs);
// 	if (!data) {
// 		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot retrieve the respdata");
// 	}

// 	OCSP_RESPDATA_new();

// 	// Assigns the value to the response
// #if OPENSSL_VERSION_NUMBER > 0x1010000fL
// 	rid = &(data->responderId);
// #else
// 	rid = data->responderId;
// #endif

// 	// Sets the Name
// 	if (!X509_NAME_set(&rid->value.byName, (PKI_X509_NAME *)name)) {
// 		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot extract the name from the signer's certificate");
// 	}

// 	// Sets the Responder Type
// 	rid->type = PKI_X509_OCSP_RESPID_TYPE_BY_NAME;

// 	// All Done
// 	return PKI_OK;
// }

// int PKI_X509_OCSP_RESP_set_createdAt(PKI_X509_OCSP_RESP * x, int offset) {

// 	// Input Checks
// 	if (!x) return PKI_ERR;

// 	PKI_TIME * gmt_time = NULL;
// 		// Time String

// 	// Basic Response Checks
// 	PKI_OCSP_RESP * resp = PKI_X509_get_value(x);
// 	if (!resp) {
// 		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Missing internal value");
// 	}

// 	gmt_time = (PKI_TIME *)OCSP_resp_get0_produced_at(resp->bs);
// 	if (!gmt_time) {
// 		PKI_DEBUG("ERROR, Can not get the createdAt time!");
// 		return PKI_ERR;
// 	}

// // 	// Assigns the value to the response
// // #if OPENSSL_VERSION_NUMBER > 0x1010100fL
// // 	gmt_time = OCSP_resp_get0_produced_at(resp->bs);
// // #elif OPENSSL_VERSION_NUMBER > 0x1010000fL
// // 	// Gets the OCSP response data
// // 	OCSP_RESPDATA * data = (OCSP_RESPDATA *)OCSP_resp_get0_respdata(resp->bs);
// // 	if (!data) {
// // 		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot retrieve the respdata");
// // 	}
// // 	gmt_time = data->producedAt;
// // #else
// // 	// Gets the OCSP response data
// // 	OCSP_RESPDATA * data = (OCSP_RESPDATA *)OCSP_resp_get0_respdata(resp->bs);
// // 	if (!data) {
// // 		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot retrieve the respdata");
// // 	}
// // 	gmt_time = data->producedAt;
// // #endif

// // 	if (!gmt_time) {
// // 		PKI_DEBUG("ERROR, Can not get the createdAt time!");
// // 		return PKI_ERR;
// // 	}

// 	// time_t now = time(NULL);
// 	// if (ASN1_GENERALIZEDTIME_set(gmt_time, now) == NULL) {
// 	// 	return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot set the createdAt time");
// 	// }

// 	// Adjust the offset (0) to the GMT time
// 	if (X509_gmtime_adj(gmt_time, 0) == NULL) {
// 		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot set the createdAt time");
// 	}

// 	// All Done
// 	return PKI_OK;
// }


// int PKI_X509_OCSP_RESP_DATA_sign (PKI_X509_OCSP_RESP * resp, 
// 								  PKI_X509_KEYPAIR   * k, 
// 								  PKI_DIGEST_ALG     * md ) {

// 	int ret = 0;
// 	OCSP_BASICRESP *bsrp = NULL;
// 	PKI_X509_OCSP_RESP_VALUE *r = NULL;

// 	// Input Checks
// 	if (!resp || !resp->value || !k || !k->value) {
// 		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
// 		return PKI_ERR;
// 	}

// 	// Gets the internal value
// 	r = resp->value;
// 	if (r->bs == NULL){
// 		PKI_ERROR(PKI_ERR_OCSP_RESP_SIGN, NULL);
// 		return PKI_ERR;
// 	}

// 	// If no digest is given, let's use the default one
// 	if (!md) md = (PKI_DIGEST_ALG *) PKI_DIGEST_ALG_get_default(k);

// 	// Using the generic signing function
// 	ret = PKI_X509_sign(resp, md, k);
// 	if (ret == PKI_ERR)	{
// 		PKI_ERROR(PKI_ERR_OCSP_RESP_SIGN, ERR_error_string(ERR_get_error(), NULL));

// 		r->bs->signature = NULL;
// 		return PKI_ERR;
// 	}

// 	// Gets the reference to the basic response
// 	bsrp = r->bs;

// 	// If a previous response was memoized, let's free it
// 	if (r->resp) OCSP_RESPONSE_free(r->resp);
// 	r->resp = NULL;

// 	// Let's create the OCSP final response by setting
// 	// the status in the responseStatus and packing the
// 	// basic response in the responseBytes
// 	r->resp = OCSP_response_create((int)r->status, bsrp);
// 	if (!r->resp) {
// 		PKI_ERROR(PKI_ERR_OCSP_RESP_SIGN, NULL);
// 		return PKI_ERR;
// 	}

// 	// // In case the responseBytes are not already set, let's generate them ourselves
// 	// if (!resp_val->responseBytes)
// 	// {
// 	// 	if (!(resp_val->responseBytes = OCSP_RESPBYTES_new()))
// 	// 	{
// 	// 		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
// 	// 		return PKI_ERR;
// 	// 	}

// 	// 	resp_val->responseBytes->responseType = 
// 	// 		OBJ_nid2obj(NID_id_pkix_OCSP_basic);
// 	// }

// 	// /* Now add the encoded data to the request bytes */
// 	// if (!ASN1_item_pack(bsrp, ASN1_ITEM_rptr(OCSP_BASICRESP), &resp_val->responseBytes->response)) 
// 	// {
// 	// 	PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, NULL);
// 	// 	return PKI_ERR;
// 	// }

// 	// All Done
// 	return PKI_OK;
// }


int PKI_X509_OCSP_RESP_sign(PKI_X509_OCSP_RESP        * resp, 
							PKI_X509_KEYPAIR          * keypair,
							PKI_X509_CERT             * cert, 
							PKI_X509_CERT             * issuer,
							PKI_X509_CERT_STACK       * otherCerts,
							PKI_DIGEST_ALG            * digest,
							PKI_X509_OCSP_RESPID_TYPE   respidType) {

	PKI_X509_OCSP_RESP_VALUE *r = NULL;
		// LibPKI's OCSP Response representation

	int success = 0;
		// Tracks the success of the operation

	// Input Checks
	if (!resp || !keypair) {
		if (!resp) {
			PKI_DEBUG("Missing resp value (%p)", resp);
		} else {
			PKI_DEBUG("Missing keypair value (%p)", keypair);
		}
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	// Let's get the value
	r = (PKI_X509_OCSP_RESP_VALUE *) PKI_X509_get_value(resp);
	if (!r || !r->bs) {
		PKI_DEBUG("Missing resp or bs value in response (value: %p, bs: %p)", 
			r, r ? r->bs : NULL);
		return PKI_ERR;
	}
	
	// // Sets the Responder ID
	// if (respidType == PKI_X509_OCSP_RESPID_TYPE_BY_NAME) {
	// 	// Name is required
	// 	if (!cert) {
	// 		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Signer's certificate is required for name respID types");
	// 	}
	// 	// Name Type
	// 	if (PKI_OK != PKI_X509_OCSP_RESP_set_nametype_by_cert(resp, cert)) {
	// 		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot set responder type to name by cert");
	// 	}
	// } else {

	// 	// Key Type
	// 	if (PKI_OK != PKI_X509_OCSP_RESP_set_keytype_by_key(resp, keypair)) {
	// 		return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot set responder type to key by key");
	// 	}
	// }

	// // Sets the createdAt time
	// if (PKI_OK != PKI_X509_OCSP_RESP_set_createdAt(resp, 0)) {
	// 	return PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, "Cannot set the createdAt field");
	// }

	// if (!(r->resp->responseBytes = OCSP_RESPBYTES_new())) {
	// 	return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate the responseBytes structure");
	// }

	// OCSP_RESPBYTES * r_bytes = OCSP_RESPBYTES_new();
	// if (!r_bytes) {
	// 	return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate the RESP");
	// }

	// PKI_OID * OCSP_basic = OBJ_nid2obj(NID_id_pkix_OCSP_basic);
	// if (!OCSP_basic) {
	// 	return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Cannot allocate the OID for responseType");
	// }
	// // Sets the responder's Type
	// r_bytes->responseType = OCSP_basic;

	// // Sets the responseBytes
	// r->resp->responseBytes = r_bytes;
	
	// // /* If there's old certs, let's clean the stack */
	// // if (r->bs->certs)	{

	// // 	// Cycle through the list of certificates and
	// // 	// free them after removing them from the list
	// // 	while (sk_X509_num(r->bs->certs) > 0 ) {

	// // 		PKI_X509_CERT_VALUE * tmp_cert = NULL;
	// // 			// Pointer to the certificate to be freed
			
	// // 		if ((tmp_cert = sk_X509_pop(r->bs->certs)) != NULL) {
	// // 			// Free Memory
	// // 			X509_free(tmp_cert);
	// // 		}
	// // 	}
	// // } else 
	// if (cert) {
	// 	// Creates a new empty stack & check for errors
	// 	r->bs->certs = sk_X509_new_null();
	// 	if (r->bs->certs == NULL) {
	// 		PKI_DEBUG("ERROR, Can not Create stack of certificate in the response");
	// 		return PKI_ERR;
	// 	}
	// }

	// /* Let's push the signer's certificate */
	// if (cert && !OCSP_basic_add1_cert(r->bs, cert->value)) {
	// 	PKI_DEBUG("ERROR, Can not add signer's certificate to the response");
	// 	return PKI_ERR;
	// }

	// Sets the responder id's type
	unsigned long flags = OCSP_NOCERTS;
	if (respidType == PKI_X509_OCSP_RESPID_TYPE_BY_KEYID) {
		flags |= OCSP_RESPID_KEY;
	}

	// Signs the OCSP basic response
	success = OCSP_basic_sign(r->bs, cert->value, keypair->value, digest, NULL, flags);
	if (!success) {
		PKI_DEBUG("ERROR::Cannot sign the basic response for the certificate to the response.");
		return 0;
	}

	// Using the generic signing function
	success = PKI_X509_sign(resp, digest, keypair);
	if (!success)	{
		PKI_ERROR(PKI_ERR_OCSP_RESP_SIGN, ERR_error_string(ERR_get_error(), NULL));
		return PKI_ERR;
	}

	// Packs the response bytes
	success = PKI_X509_OCSP_RESP_bytes_encode(resp);
	if (!success) {
		PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, NULL);
		return PKI_ERR;
	}

	// // If a previous response was memoized, let's free it
	// if (r->resp) OCSP_RESPONSE_free(r->resp);
	// r->resp = NULL;

	// // Let's create the OCSP final response by setting
	// // the status in the responseStatus and packing the
	// // basic response in the responseBytes
	// r->resp = OCSP_response_create((int)r->status, bsrp);
	// if (!r->resp) {
	// 	PKI_ERROR(PKI_ERR_OCSP_RESP_SIGN, NULL);
	// 	return PKI_ERR;
	// }

	// // Let's now perform the real signing operation
	// return PKI_X509_OCSP_RESP_DATA_sign(resp, keypair, digest);

	// All Done
	return PKI_OK;
}

int PKI_X509_OCSP_RESP_sign_tk(PKI_X509_OCSP_RESP 		 * r,
							   PKI_TOKEN 		  		 * tk, 
			       			   PKI_DIGEST_ALG     		 * digest,
							   PKI_X509_OCSP_RESPID_TYPE   respidType) {

	int ret = PKI_OK;
		// Return value

	// Input check
	if( !r || !tk ) return ( PKI_ERR );

	// Gets the Digest algorithm from the Token algor
	if (!digest) digest = (PKI_DIGEST_ALG *)PKI_X509_ALGOR_VALUE_get_digest(tk->algor);

	// Let's login to the token
	if (PKI_TOKEN_login(tk) != PKI_OK) {
		PKI_ERROR(PKI_ERR_HSM_LOGIN, "OCSP Response Signing");
		return PKI_ERR;
	}

	// Let's sign the response
	ret = PKI_X509_OCSP_RESP_sign(r, tk->keypair, tk->cert, tk->cacert,
			tk->otherCerts, digest, respidType);

	// Checks for possible errors
	if (ret != PKI_OK) {
		PKI_log_debug("Error while signing OCSP response");
	}

	// All Done
	return ret;
}

const void * PKI_X509_OCSP_RESP_get_data(PKI_X509_OCSP_RESP * r,
					 					 PKI_X509_DATA        type) {

	const void * ret = NULL;
	PKI_OCSP_RESP *val = NULL;
	OCSP_BASICRESP *tmp_x = NULL;
	PKI_MEM *mem = NULL;
	int idx = -1;

	// Input Checks
	if (!r || !r->value) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	// Gets the internal value
	val = PKI_X509_get_value(r);
	if (!val || !val->bs) {
		PKI_ERROR(PKI_ERR_POINTER_NULL, NULL);
		return NULL;
	}

	// Gets the reference to the basic response
	tmp_x = val->bs;

	switch ( type )	{

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
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
			mem->size = (size_t)ASN1_item_i2d((void *)&(tmp_x->tbsResponseData),
				&(mem->data), (ASN1_ITEM *) OCSP_RESPDATA_it );
#elif OPENSSL_VERSION_NUMBER > 0x1010000fL
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


char * PKI_X509_OCSP_RESP_get_parsed (PKI_X509_OCSP_RESP * r, 
									  PKI_X509_DATA 	   type) {

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


int PKI_X509_OCSP_RESP_copy_nonce (PKI_X509_OCSP_RESP * resp, 
								   PKI_X509_OCSP_REQ  * req ) {

	PKI_X509_OCSP_RESP_VALUE *r = NULL;
		// LibPKI's OCSP Response representation

	if ( !resp || !resp->value || !req || !req->value ) {
		if (!resp || !resp->value) PKI_ERROR(PKI_ERR_POINTER_NULL, "resp or resp->value");
		if (!req || !req->value) PKI_ERROR(PKI_ERR_POINTER_NULL, "req or req->value");
		return PKI_ERR;
	}

	// Retrieve the internal value
	r = PKI_X509_get_value(resp);
	if (!r || !r->bs) {
		PKI_log_err("Missing basic request in OCSP REQ value");
		return PKI_ERR;
	}

	// Copy the nonce from the request to the response
	if (!OCSP_copy_nonce(r->bs, req->value)) {
		PKI_ERROR(PKI_ERR_OCSP_NONCE_COPY, NULL);
		return PKI_ERR;
	}

	// All Done
	return PKI_OK;
}


int PKI_X509_OCSP_RESP_print_parsed(PKI_X509_OCSP_RESP * r, 
									PKI_X509_DATA 	     type,
									int 				 fd) {

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

int PKI_X509_OCSP_RESP_bytes_encode (PKI_X509_OCSP_RESP * resp) {

	PKI_X509_OCSP_RESP_VALUE *resp_val = NULL;
	  // OCSP Response Value

	// Input Check
	if (!resp) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	// Shortcut for the value
	resp_val = PKI_X509_get_value(resp);
	if (!resp_val) {
		PKI_ERROR(PKI_ERR_POINTER_NULL, NULL);
		return PKI_ERR;
	}

	// Free any existing encoded message
	if (resp_val->resp) {
		OCSP_RESPONSE_free(resp_val->resp);
		resp_val->resp = NULL;
	}

	// Generates a new OCSP response
	resp_val->resp = OCSP_response_create((int) resp_val->status, resp_val->bs);
	if (!resp_val->resp) {
		PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, NULL);
		return PKI_ERR;
	}

	// Success
	return PKI_OK;
}



PKI_X509_OCSP_RESP_VALUE * PEM_read_bio_PKI_X509_OCSP_RESP_VALUE(PKI_IO * bp, 
										  			 			 void 	 * a, 
										  						 void   * b,
										  						 void   * c ) {

	OCSP_RESPONSE * resp = NULL;
		// The internal response

	PKI_X509_OCSP_RESP_VALUE * ret = NULL;
		// The LibPKI structure to be returned

	// Input checks
	if (!bp) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

#if OPENSSL_VERSION_NUMBER < 0x0090800fL
        resp = (PKI_X509_OCSP_RESP_VALUE *) PEM_ASN1_read_bio( 
							(char *(*)()) d2i_OCSP_RESPONSE,
                            PEM_STRING_OCSP_RESPONSE,
							bp,
							NULL,
							NULL,
							NULL);
#else
        resp = (OCSP_RESPONSE *) PEM_ASN1_read_bio( 
							(void *(*)()) d2i_OCSP_RESPONSE,
                            PEM_STRING_OCSP_RESPONSE,
							bp,
							NULL,
							NULL,
							NULL);
#endif

	// Checks for errors
	if (!resp) {
		return NULL;
	}

	// Allocate the needed memory
	ret = (PKI_X509_OCSP_RESP_VALUE *) PKI_Malloc(sizeof(PKI_X509_OCSP_RESP_VALUE));
	if (!ret) {
		if (resp) OCSP_RESPONSE_free(resp);
		return NULL;
	}

	// Unpacks the response
	ret->bs = OCSP_response_get1_basic(ret->resp);
	if (!ret->bs) {
		if (resp) OCSP_RESPONSE_free(resp);
		if (ret) PKI_Free(ret);
		return NULL;
	}

	// Upacks the status
	ret->status = (PKI_X509_OCSP_RESP_STATUS) OCSP_response_status(ret->resp);

	// All Done
	return ret;
}

int PEM_write_bio_PKI_X509_OCSP_RESP_VALUE( PKI_IO *bp, PKI_X509_OCSP_RESP_VALUE *o ) {

	if (!o || !o->bs) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	// Free any existing response
	if (o->resp) OCSP_RESPONSE_free(o->resp);

	// Encodes the response
	o->resp = OCSP_response_create((int) o->status, o->bs);
	if (!o->resp) {
		PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, NULL);
		return PKI_ERR;
	}

	return PEM_ASN1_write_bio((int (*)())i2d_OCSP_RESPONSE, 
							  PEM_STRING_OCSP_RESPONSE, 
							  bp, 
							  (char *) o->resp, 
							  NULL, 
							  NULL, 
							  0, 
							  NULL, 
							  NULL );
}

PKI_X509_OCSP_RESP_VALUE *d2i_PKI_X509_OCSP_RESP_VALUE_bio(PKI_IO 					 * bp, 
														   PKI_X509_OCSP_RESP_VALUE ** out_pnt) {

	OCSP_RESPONSE * resp = NULL;
		// The internal response

	PKI_X509_OCSP_RESP_VALUE * ret = NULL;
		// The LibPKI structure to be returned

	// Input Check
	if (!bp) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	resp = (OCSP_RESPONSE *) ASN1_d2i_bio(
					(char *(*)(void))OCSP_RESPONSE_new,
					(char *(*)(void **, const unsigned char **, long)) d2i_OCSP_RESPONSE,
					bp, 
					(unsigned char **) NULL);
#else
	resp = (OCSP_RESPONSE *) ASN1_d2i_bio(
					(void *(*)(void)) OCSP_RESPONSE_new,
					(void *(*)(void **, const unsigned char **, long)) d2i_OCSP_RESPONSE,
					bp, 
					(void **) NULL);
#endif

	// Checks for errors
	if (!resp) {
		return NULL;
	}

	// Allocate the needed memory
	ret = (PKI_X509_OCSP_RESP_VALUE *) PKI_Malloc (sizeof(PKI_X509_OCSP_RESP_VALUE));
	if (!ret) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		if (resp) OCSP_RESPONSE_free(resp);
		return NULL;
	}

	// Sets the internal response
	ret->resp = resp;

	// Extracts the basic response
	ret->bs = OCSP_response_get1_basic(ret->resp);
	if (!ret->bs) {
		PKI_ERROR(PKI_ERR_OCSP_RESP_DECODE, NULL);
		if (resp) OCSP_RESPONSE_free(resp);
		if (ret) PKI_Free(ret);
		return NULL;
	}

	// Updates the status
	ret->status = (PKI_X509_OCSP_RESP_STATUS) OCSP_response_status(ret->resp);

	// Sets the output pointer
	if (out_pnt) *out_pnt = ret;

	// All Done
	return ret;
}

int i2d_PKI_X509_OCSP_RESP_VALUE_bio(PKI_IO *bp, PKI_X509_OCSP_RESP_VALUE *o ) {

	if (!o || !o->bs) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	if (o->resp) {
		OCSP_RESPONSE_free(o->resp);
		o->resp = NULL;
	}

	// Generates a new OCSP response
	o->resp = OCSP_response_create((int) o->status, o->bs);
	if (!o->resp) {
		PKI_ERROR(PKI_ERR_OCSP_RESP_ENCODE, NULL);
		return PKI_ERR;
	}

#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	return ASN1_i2d_bio((int (*)(OCSP_RESPONSE *, unsigned char **)) i2d_OCSP_RESPONSE, 
						bp, 
						(unsigned char *) o->resp);
#else
	return ASN1_i2d_bio((i2d_of_void *) i2d_OCSP_RESPONSE,
						 bp, 
						 (unsigned char *) o->resp);
#endif
}

