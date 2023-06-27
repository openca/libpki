/* PKI_X509 object management */

#include <libpki/pki.h>

#include "openssl/internal/x509_data_st.h"

typedef struct parsed_datatypes_st {
	const char *descr;
	int nid;
} LIBPKI_PARSED_DATATYPES;

typedef struct tbs_asn1_st {
	const ASN1_ITEM * it;
	const void * data;
} PKI_TBS_ASN1;

struct parsed_datatypes_st __parsed_datatypes[] = {
	/* X509 types */
	{ "Unknown", PKI_DATATYPE_UNKNOWN },
	{ "Public KeyPair", PKI_DATATYPE_X509_KEYPAIR },
	{ "X509 Public Key Certificate", PKI_DATATYPE_X509_CERT },
	{ "X509 CRL", PKI_DATATYPE_X509_CRL },
	{ "PKCS#10 Certificate Request", PKI_DATATYPE_X509_REQ },
	{ "PKCS#7 Message", PKI_DATATYPE_X509_PKCS7 },
	{ "CMS Message", PKI_DATATYPE_X509_CMS },
	{ "PKCS#12 PMI Object", PKI_DATATYPE_X509_PKCS12 },
	{ "OCSP Request", PKI_DATATYPE_X509_OCSP_REQ },
	{ "OCSP Response", PKI_DATATYPE_X509_OCSP_RESP },
	{ "PRQP Request", PKI_DATATYPE_X509_PRQP_REQ },
	{ "PRQP Response", PKI_DATATYPE_X509_PRQP_RESP },
	{ "Cross Certificate Pair", PKI_DATATYPE_X509_XPAIR },
	{ "CMS Message", PKI_DATATYPE_X509_CMS_MSG },
	{ NULL, -1 }
};

PKI_TBS_ASN1 * __datatype_get_asn1_ref(PKI_DATATYPE   type, 
                                       const void   * v) {

	PKI_TBS_ASN1 * ret = NULL;
	const ASN1_ITEM * it = NULL;
	const void * p = NULL;

	// Gets the ASN1_ITEM * needed to get the tbSigned
	switch (type) {

		case PKI_DATATYPE_X509_CERT : {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		        it = (ASN1_ITEM *) X509_CINF_it;
#else
			it = &X509_CINF_it;
#endif
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
			p = &(((LIBPKI_X509_CERT *)v)->cert_info);
#else
			p = ((PKI_X509_CERT_VALUE *)v)->cert_info;
#endif
		} break;

		case PKI_DATATYPE_X509_CRL : {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
			it = (ASN1_ITEM *) X509_CRL_INFO_it;
#else
			it = &X509_CRL_INFO_it;
#endif
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
			p = &(((PKI_X509_CRL_VALUE *)v)->crl);
#else
			p = ((PKI_X509_CRL_VALUE *)v)->crl;
#endif
		} break;

		case PKI_DATATYPE_X509_REQ : {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
			it = (ASN1_ITEM *) X509_REQ_INFO_it;
#else
			it = &X509_REQ_INFO_it;
#endif
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
			p = &(((LIBPKI_X509_REQ *)v)->req_info);
#else
			p = ((PKI_X509_REQ_VALUE *)v)->req_info;
#endif
		} break;

		case PKI_DATATYPE_X509_OCSP_REQ : {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
			it = (ASN1_ITEM *) OCSP_REQINFO_it;
#else
			it = &OCSP_REQINFO_it;
#endif
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
			p = &(((PKI_X509_OCSP_REQ_VALUE *)v)->tbsRequest);
#else
			p = ((PKI_X509_OCSP_REQ_VALUE *)v)->tbsRequest;
#endif
		} break;

		case PKI_DATATYPE_X509_OCSP_RESP : {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
			it = (ASN1_ITEM *) OCSP_RESPDATA_it;
#else
			it = &OCSP_RESPDATA_it;
#endif
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
			p = &(((PKI_OCSP_RESP *)v)->bs->tbsResponseData);
#else
			p = ((PKI_OCSP_RESP *)v)->bs->tbsResponseData;
#endif
		} break;

		case PKI_DATATYPE_X509_PRQP_REQ : {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
			it = (ASN1_ITEM *) PKI_PRQP_REQ_it;
#else
			it = &PKI_PRQP_REQ_it;
#endif
			p = ((PKI_X509_PRQP_REQ_VALUE *)v)->requestData;
		} break;

		case PKI_DATATYPE_X509_PRQP_RESP : {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
			it = (ASN1_ITEM *) PKI_PRQP_RESP_it;
#else
			it = &PKI_PRQP_RESP_it;
#endif
			p = ((PKI_X509_PRQP_RESP_VALUE *)v)->respData;
		} break;

		case PKI_DATATYPE_X509_CMS : {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
			it = (ASN1_ITEM *) CMS_ContentInfo_it;
#else
			it = &CMS_ContentInfo_it;
#endif
			p = NULL;
		}

		default: {
			PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED, 
				  "Not Supported Datatype [%d]", type);
			return NULL;
		}
	}

	if ((ret = PKI_Malloc(sizeof(PKI_TBS_ASN1))) == NULL) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	// Builds the return data
	ret->it = it;
	ret->data = p;

	// Return the Pointer
	return ret;

}

/*! \brief Returns the callbacks for a specific PKI_DATATYPE */

const PKI_X509_CALLBACKS *PKI_X509_CALLBACKS_get (PKI_DATATYPE type, 
						struct hsm_st *hsm) {

	if ( !hsm ) hsm = (HSM *) HSM_get_default();

	if ( !hsm || !hsm->callbacks || !hsm->callbacks->x509_get_cb )
		return NULL;

	return hsm->callbacks->x509_get_cb ( type );

}

/*! \brief Allocs the memory associated with an empty PKI_X509 object */

PKI_X509 *PKI_X509_new ( PKI_DATATYPE type, struct hsm_st *hsm ) {

	PKI_X509 *ret = NULL;
	const PKI_X509_CALLBACKS *cb = NULL;

	// If no hsm, let's get the default
	if ( !hsm ) hsm = (HSM *) HSM_get_default();

	// Now we need the callbacks for object creation and handling
	if (( cb = PKI_X509_CALLBACKS_get ( type, hsm )) == NULL ) {
		PKI_ERROR(PKI_ERR_CALLBACK_NULL, NULL);
		return NULL;
	}

	// Let's allocate the required memory
	if((ret = PKI_Malloc (sizeof( PKI_X509 ))) == NULL ) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	// Object Type
	ret->type = type;

	// X509_Callbacks
	ret->cb = cb;

	// URL Reference
	ret->ref = NULL;

	// HSM to use
	ret->hsm = hsm;

	// Crypto provider's specific data structure
	ret->value = NULL;

	// Auxillary Data
	ret->aux_data = NULL;

	// Internal Status
	ret->status = -1;

	// All Done
	return ret;
}

/*! \brief Frees the memory associated with a PKI_X509 object */

void PKI_X509_free_void ( void *x ) {
	PKI_X509_free ( (PKI_X509 *) x );
	return;
}

void PKI_X509_free ( PKI_X509 *x ) {

	if (!x ) return;

	if (x->value)
	{
		if (x->cb->free)
			x->cb->free(x->value);
		else
			PKI_Free(x->value);
	}

	if (x->cred) PKI_CRED_free(x->cred);

	if (x->ref ) URL_free(x->ref);

	if (x->aux_data && x->free_aux_data)
		x->free_aux_data(x->aux_data);

	PKI_ZFree ( x, sizeof(PKI_X509) );

	return;
}

/*! \brief Allocates the memory for a new PKI_X509 and sets the data */

PKI_X509 *PKI_X509_new_value (PKI_DATATYPE type, void *value, 
						struct hsm_st *hsm){

	PKI_X509 *ret = NULL;

	if (( ret = PKI_X509_new ( type, hsm )) == NULL ) {
		PKI_log_debug ( "Can not initialized a new PKI_X509 object.");
		return NULL;
	}

	if (value) {
		if((PKI_X509_set_value ( ret, value )) == PKI_ERR ) {
			PKI_DEBUG( "Error setting value in the PKI_X509 obj");
			PKI_X509_free ( ret );
			return NULL;
		}
	}

	return ret;
}

/*! \brief Allocates the memory for a new PKI_X509 and duplicates the data */

PKI_X509 *PKI_X509_new_dup_value (PKI_DATATYPE type, 
				  const void *value, 
				  struct hsm_st *hsm ) {

	PKI_X509 *ret = NULL;

	if( !value ) return NULL;

	if (( ret = PKI_X509_new ( type, hsm )) == NULL ) {
		PKI_log_debug ( "Can not initialized a new PKI_X509 object.");
		return NULL;
	}

	if ( !ret->cb || !ret->cb->dup )  {
		PKI_log_debug ( "ERROR, no 'dup' callback!");
		PKI_X509_free ( ret );
		return NULL;
	}

	if ((ret->value = ret->cb->dup((void *)value)) == NULL) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Can not duplicate internal value");
		PKI_X509_free(ret);
		return NULL;
	};
	
	return ret;
}

/*!
 * \brief Sets the Modified bit (required in some crypto lib to force re-encoding)
 */

int PKI_X509_set_modified ( PKI_X509 *x ) {

#if ( OPENSSL_VERSION_NUMBER >= 0x0090900f )
	PKI_X509_CERT_VALUE *cVal = NULL;
	PKI_X509_CRL_VALUE *cRLVal = NULL;
#endif
	int type;
	
	if ( !x || !x->value ) return PKI_ERR;

	type = PKI_X509_get_type ( x );

	// This should be implemented via callbacks!!!
	switch ( type )
	{
		case PKI_DATATYPE_X509_CERT:
#if ( OPENSSL_VERSION_NUMBER >= 0x0090900f )
				cVal = (PKI_X509_CERT_VALUE *) x->value;
				// cVal->cert_info->enc.modified = 1;
# if OPENSSL_VERSION_NUMBER > 0x10100000L
				if (cVal) {
					LIBPKI_X509_CINF *cFull = NULL;
					cFull = (LIBPKI_X509_CINF *) &(cVal->cert_info);
					cFull->enc.modified = 1;
				}
# else
				if (cVal && cVal->cert_info) {
					X509_CINF *cFull = NULL;
					cFull = (X509_CINF *) cVal->cert_info;
					cFull->enc.modified = 1;
				}
# endif
#endif
				break;

		case PKI_DATATYPE_X509_CRL:
#if ( OPENSSL_VERSION_NUMBER >= 0x0090900f )
				cRLVal = (PKI_X509_CRL_VALUE *) x->value;
# if ( OPENSSL_VERSION_NUMBER >= 0x1010000f )
				cRLVal->crl.enc.modified = 1;
# else
				cRLVal->crl->enc.modified = 1;
# endif
#endif
				break;
	};

	return PKI_OK;

};

/*! \brief Returns the type of a PKI_X509 object */

PKI_DATATYPE PKI_X509_get_type(const PKI_X509 *x) {

	if (!x) return PKI_DATATYPE_UNKNOWN;

	return x->type;
}

/*!
 * \brief Returns a TXT description of the Object Type
 */

const char * PKI_X509_get_type_parsed(const PKI_X509 *obj) {
	int i = 0;
	int type = 0;

	type = PKI_X509_get_type( obj );
	while( __parsed_datatypes[i].descr != NULL ) {
		if ( __parsed_datatypes[i].nid == type ) {
			return __parsed_datatypes[i].descr;
		};
		i++;
	};
	return __parsed_datatypes[0].descr;
};

/*! \brief Sets the HSM reference in a PKI_X509 object */

int PKI_X509_set_hsm ( PKI_X509 *x, struct hsm_st *hsm ) {

	if ( !x || !hsm ) return PKI_ERR;

	if ( hsm ) HSM_free ( hsm );

	x->hsm = hsm;

	return PKI_OK;
}

/*! \brief Retrieves the HSM reference from a PKI_X509 object */

struct hsm_st *PKI_X509_get_hsm(const PKI_X509 *x) {

	if (!x) return NULL;

	return x->hsm;
}

/*! \brief Sets (duplicates) the reference URL of a PKI_X509 object */
int PKI_X509_set_reference ( PKI_X509 *x, URL *url ) {
	if ( !x || !url ) return PKI_ERR;

	if ( x->ref ) URL_free ( x->ref );

	x->ref = URL_new ( url->url_s );

	return PKI_OK;
}

/*! \brief Retrieves the reference URL from a PKI_X509 object */

URL *PKI_X509_get_reference(const PKI_X509 *x) {

	if ( !x ) return NULL;

	return x->ref;
}


/*! \brief Returns the reference to the PKI_X509_XXX_VALUE withing a PKI_X509
	   object */

void * PKI_X509_get_value(const PKI_X509 *x) {

	if ( !x ) return NULL;

	return x->value;
}


/*! \brief Sets the pointer to the internal value in a PKI_X509 */

int PKI_X509_set_value ( PKI_X509 *x, void *data ) {

	if ( !x || !data ) return PKI_ERR;

	if ( x->value && x->cb ) {
		if ( !x->cb || !x->cb->free ) {
			PKI_log_debug ("ERROR, no 'free' callback!");
			return PKI_ERR;
		}
		x->cb->free ( x->value );
	}

	x->value = data;

	return PKI_OK;
}

/*! \brief Duplicates the PKI_X509_XXX_VALUE from the passed PKI_X509 object */

void * PKI_X509_dup_value (const PKI_X509 *x ) {

	void *ret = NULL;

	if (!x || !x->cb || !x->cb->dup || !x->value ) 
		return NULL;

	ret = x->cb->dup ((void *) x->value );

	return ret;
}

/*! \brief Duplicates a PKI_X509 object */

PKI_X509 * PKI_X509_dup (const PKI_X509 *x ) {

	PKI_X509 *ret = NULL;

	if (!x ) return NULL;

	if(( ret = PKI_Malloc(sizeof(PKI_X509))) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	memcpy ( ret, x, sizeof ( PKI_X509 ));

	if( x->value )
	{
		ret->value = PKI_X509_dup_value(x);
		if ( ret->value == NULL )
		{
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			PKI_ZFree(ret, sizeof(PKI_X509));
			return NULL;
		}
	}

	if (x->ref)
	{
		// The origin of this new object is memory, so the ref
		// should be set to NULL
		ret->ref = NULL;	
	}

	if (x->hsm)
	{
		ret->hsm = x->hsm;
	}

	if (x->cb) {
		ret->cb = x->cb;
	}

	return ret;
}

/*! \brief Returns a ref to the X509 data (e.g., SUBJECT) within the passed PKI_X509 object */

void * PKI_X509_get_data(const PKI_X509 *x, PKI_X509_DATA type ) {

	if (!x || !x->cb || !x->value || !x->cb->get_data) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	// TODO: eventually this should be changed
	// to use a const value in the callback
	return x->cb->get_data((void *)x, type );
}

/*! \brief Returns PKI_OK if the PKI_X509 object is signed */

int PKI_X509_is_signed(const PKI_X509 *obj ) {

	if ( !obj || !obj->value ) return PKI_ERR;

	if ( PKI_X509_get_data ( obj, PKI_X509_DATA_SIGNATURE ) == NULL ) {
		return PKI_ERR;
	}

	return PKI_OK;
}

/*! \brief Returns the DER encoded version of the toBeSigned portion of
 *         the PKI_X509_VALUE structure
 */

PKI_MEM * PKI_X509_VALUE_get_tbs_asn1(const void         * v, 
                                      const PKI_DATATYPE   type) {

	PKI_TBS_ASN1 * ta = NULL;
	PKI_MEM      * mem = NULL;

	// Input Checks
	if (v == NULL) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	// Gets the template and data pointer
	if ((ta = __datatype_get_asn1_ref(type, v)) == NULL) return NULL;

	// Allocates the PKI_MEM data structure
	if ((mem = PKI_MEM_new_null()) == NULL) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	// distinction between openssl versions is done inside __datatype_get_asn1_ref 
	mem->size = (size_t) ASN1_item_i2d((void *)ta->data,
                                               &(mem->data),
                                               ta->it);

	 // Free the TA Data
	 PKI_Free(ta);

	return mem;
}


PKI_MEM * PKI_X509_get_tbs_asn1(const PKI_X509 *x) {
	
	return PKI_X509_VALUE_get_tbs_asn1(x->value, x->type);

}

/*! \brief Returns the parsed (char *, int *, etc.) version of the data in
           a PKI_X509 object */

void * PKI_X509_get_parsed(const PKI_X509 *x, PKI_X509_DATA type ) {

	if ( !x || !x->cb || !x->cb->get_parsed || !x->value ) return NULL;

	return x->cb->get_parsed((PKI_X509 *)x, type );
}


/*! \brief Prints the parsed data from a PKI_X509 object to a file descriptor */

int PKI_X509_print_parsed(const PKI_X509 *x, PKI_X509_DATA type, int fd ) {

	if ( !x || !x->cb->print_parsed || !x->value ) return PKI_ERR;

	return x->cb->print_parsed((PKI_X509 *)x, type, fd );
}

/*! \brief Deletes the hard copy (eg., file, hsm file, etc.) of the PKI_X509
 *         object. */

int PKI_X509_delete ( PKI_X509 *x )
{
	int ret = PKI_OK;
	PKI_X509_STACK *sk = NULL;

	if (!x || !x->ref) return PKI_ERR;

	if (x->hsm && x->hsm->callbacks)
	{
		sk = PKI_STACK_new_type( x->type );
		PKI_STACK_X509_push ( sk, x );

		ret = HSM_X509_STACK_del ( sk );
		x = PKI_STACK_X509_pop ( sk );

		PKI_STACK_X509_free ( sk );
		return ret;
	}

	switch ( x->ref->proto )
	{
		case URI_PROTO_FILE:
			ret = unlink ( x->ref->url_s );
			break;
		default:
			ret = PKI_ERR;
			break;
	}

	return ret;
}

/*! \brief Sets the Aux Data into an PKI_X509 structure */
int PKI_X509_aux_data_set (PKI_X509 * x,
	                         void     * data, 
	                         void       (*data_free_func)(void *),
	                         void     * (*data_dup_func )(void *)) {

	// Input Check
	if (!x || !data) return PKI_ERR_PARAM_NULL;

	// Requires at least the free function
	if (!data_free_func) {
		PKI_ERROR(PKI_ERR_X509_AUX_DATA_MEMORY_FREE_CB_NULL, NULL);
		return 0;
	}
	
	// Checks if we do have data already set
	if (x->aux_data) {
		// If we have the free function, let's use it
		if (x->free_aux_data) x->free_aux_data(x->aux_data);
		else PKI_ERROR(PKI_ERR_X509_AUX_DATA_MEMORY_FREE_CB_NULL, NULL);
	}

	// Assignment
	x->aux_data      = data;
	x->free_aux_data = data_free_func;
	x->dup_aux_data  = data_dup_func;

  // All Done
	return 1;
}

void * PKI_X509_aux_data_get(PKI_X509 * x) {

	// Input Check
	if (!x || !x->aux_data) return NULL;

	// Returns the pointer to the data
	return x->aux_data;
}

void * PKI_X509_aux_data_dup(PKI_X509 * x) {
	// Input Check
	if (!x || !x->aux_data) return NULL;

	// Checks we have the dup function
	if (!x->dup_aux_data) return NULL;

	// Returns the duplicate of the aux_data
	return x->dup_aux_data(x->aux_data);
}

int PKI_X509_aux_data_del(PKI_X509 * x) {

	// Input Check
	if (!x || !x->aux_data) return PKI_ERR;

  // Error Condition: Missing the 'free' callback
	if (!x->free_aux_data) 
		return PKI_ERROR(PKI_ERR_X509_AUX_DATA_MEMORY_FREE_CB_NULL, NULL);

	// Free the memory
	x->free_aux_data(x->aux_data);

	// All Done
	return PKI_OK;
}

int PKI_X509_set_status(PKI_X509 *x, int status) {

	// Input Check
	if (!x) return PKI_ERR;

	// Sets the Status field of X509
	x->status = status;

	// All done
	return PKI_OK;
}

int PKI_X509_get_status(PKI_X509 *x) {

	// Input Check
	if (!x) return -1;

	// Returns the internal status
	return x->status;
}
