/*
 * OpenCA SCEP -- signed attributes handling routines
 * (c) 2009 by Massimiliano Pala and OpenCA Group
 *
 */

#include <libpki/pki.h>

#define SCEP_CONF_LIST_SIZE	8

SCEP_CONF_ATTRIBUTE SCEP_ATTRIBUTE_list [SCEP_CONF_LIST_SIZE] = {
	{ SCEP_ATTRIBUTE_MESSAGE_TYPE, "2.16.840.1.113733.1.9.2", 
			"scepMessageType", "SCEP Message Type", -1 },
	{ SCEP_ATTRIBUTE_PKI_STATUS, "2.16.840.1.113733.1.9.3", 
			"pkiStatus", "Status", -1 },
	{ SCEP_ATTRIBUTE_FAIL_INFO, "2.16.840.1.113733.1.9.4", 
			"failInfo", "Failure Info", -1 },
	{ SCEP_ATTRIBUTE_SENDER_NONCE, "2.16.840.1.113733.1.9.5", 
			"senderNonce", "Sender Nonce", -1 },
	{ SCEP_ATTRIBUTE_RECIPIENT_NONCE, "2.16.840.1.113733.1.9.6", 
			"recipientNonce", "Recipient Nonce", -1 },
	{ SCEP_ATTRIBUTE_TRANS_ID, "2.16.840.1.113733.1.9.7", 
			"transId", "Transaction Identifier", -1 },
	{ SCEP_ATTRIBUTE_EXTENSION_REQ, "2.16.840.1.113733.1.9.8", 
			"extensionReq", "Extension Request", -1 },
	{ SCEP_ATTRIBUTE_PROXY_AUTH, "1.3.6.1.4.1.4263.5.5", 
			"proxyAuth", "Proxy Authenticator", -1 },
};

void PKI_X509_SCEP_init ( void ) {
        int i = 0;
	int nid = NID_undef;

	SCEP_CONF_ATTRIBUTE *curr_oid = NULL;

        i = 0;
        while( i < SCEP_CONF_LIST_SIZE ) {
		curr_oid = &SCEP_ATTRIBUTE_list[i];
                if(( nid = OBJ_create(curr_oid->oid_s, curr_oid->descr,
			 curr_oid->long_descr)) == NID_undef) {
                        return;
                }

		curr_oid->nid = nid;
		i++;
        }

        return;
}

/*! \brief Returns the SCEP_ATTRIBUTE_TYPE from the attribute name */

SCEP_ATTRIBUTE_TYPE PKI_X509_SCEP_ATTRIBUTE_get_txt(const char * txt) {

	SCEP_CONF_ATTRIBUTE *curr = NULL;
	int i = 0;

    while( i < SCEP_CONF_LIST_SIZE ) {

    	// Gets the i-th attribute
		curr = &SCEP_ATTRIBUTE_list[i];

		// Check if the attribute matches
		if (strcmp_nocase(curr->descr, txt) == 0) break;

		i++;
	}

    // Returns the type value
	if (curr) return (SCEP_ATTRIBUTE_TYPE)curr->attr_type;

	// Not found
	return SCEP_ATTRIBUTE_TYPE_UNKNOWN;
}

/*! \brief Returns the PKI_ID of the specified SCEP_ATTRIBUTE_TYPE */

PKI_ID PKI_X509_SCEP_ATTRIBUTE_get_nid ( SCEP_ATTRIBUTE_TYPE num ) {

	SCEP_CONF_ATTRIBUTE *curr = NULL;
	int i = 0;

	i = 0;
        while( i < SCEP_CONF_LIST_SIZE ) {
		curr = &SCEP_ATTRIBUTE_list[i];
		if ( curr->attr_type == num ) 
			break;
		i++;
	}

	if ( curr ) return curr->nid;

	return NID_undef;
}

/*! \brief Returns the PKI_OID for the specified SCEP attribute */

PKI_OID *PKI_X509_SCEP_MSG_get_oid ( SCEP_ATTRIBUTE_TYPE scep_attribute ) {

	SCEP_CONF_ATTRIBUTE *curr = NULL;

	int i = 0;

	i = 0;
        while( i < SCEP_CONF_LIST_SIZE ) {
		curr = &SCEP_ATTRIBUTE_list[i];
		if ( curr->attr_type == scep_attribute )
			break;
		i++;
	}

	if ( curr ) return PKI_OID_get ( curr->descr );

	return NULL;
}

/*! \brief Sets the message type attribute in a SCEP message (signed P7) */
int PKI_X509_SCEP_MSG_set_attribute(PKI_X509_SCEP_MSG   * msg,
                                    SCEP_ATTRIBUTE_TYPE   type,
									const unsigned char * const data,
									size_t                size) {

	PKI_X509_ATTRIBUTE *a = NULL;
	PKI_ID id = 0;

	if (!msg || !data) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// Gets the Type of the attribute
	if ((id = PKI_X509_SCEP_ATTRIBUTE_get_nid ( type )) == NID_undef ) {
		return PKI_ERROR(PKI_ERR_SCEP_ATTRIBUTE_UNKNOWN, NULL);
	}

	// Creates the Attribute based on the type
	switch (type) {

		// PRINTABLESTRING Attributes
		case SCEP_ATTRIBUTE_MESSAGE_TYPE:
		case SCEP_ATTRIBUTE_PKI_STATUS:
		case SCEP_ATTRIBUTE_FAIL_INFO:
		case SCEP_ATTRIBUTE_TRANS_ID:
		case SCEP_ATTRIBUTE_EXTENSION_REQ:
		case SCEP_ATTRIBUTE_PROXY_AUTH: {
			a = PKI_X509_ATTRIBUTE_new(id,
				                       V_ASN1_PRINTABLESTRING,
									   data,
									   size );
		} break;

		// OCTET_STRING Attributes
		case SCEP_ATTRIBUTE_SENDER_NONCE:
		case SCEP_ATTRIBUTE_RECIPIENT_NONCE: {
			a = PKI_X509_ATTRIBUTE_new(id,
				                       V_ASN1_OCTET_STRING,
									   data,
									   size);
		} break;

		default:
			return PKI_ERROR(PKI_ERR_SCEP_ATTRIBUTE_UNKNOWN, NULL);
	}

	// Checks we have a valid object
	if (!a) return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);

	// Removes the attribute (if already present)
	PKI_X509_PKCS7_delete_signed_attribute(msg, id);

	// Returns the result of adding the signed attribute
    return PKI_X509_PKCS7_add_signed_attribute( msg, a);
}

/*! \brief Adds an attribute (identified by its name) to a SCEP message */

int PKI_X509_SCEP_MSG_set_attribute_by_name(PKI_X509_SCEP_MSG   * msg,
                                            const char          * const name,
											const unsigned char * const data,
											size_t                size) {

	PKI_ID type = 0;

	// Input Check
	if (!msg || !data || !name)
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// Gets the Attribute Type
	if ((type = PKI_X509_SCEP_ATTRIBUTE_get_txt(name)) == -1)
		return PKI_ERROR(PKI_ERR_SCEP_ATTRIBUTE_UNKNOWN, NULL);

	// Sets the Attribute in the Message
	return PKI_X509_SCEP_MSG_set_attribute(msg, type, data, size);

}

/*! \brief Adds the specified attribute (int) as a string */

int PKI_X509_SCEP_MSG_set_attribute_int(PKI_X509_SCEP_MSG * msg,
                                        PKI_ID              id,
										int                 val) {

	char buf[BUFF_MAX_SIZE];

	if (!msg ) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	snprintf(buf, sizeof(buf), "%d%c", val, '\x0');

	return PKI_X509_SCEP_MSG_set_attribute(msg, id,
					(const unsigned char*) buf, strlen(buf));
}

/*! \brief Returns the value of the specified attribute in a PKI_MEM */

PKI_MEM * PKI_X509_SCEP_MSG_get_attr_value(const PKI_X509_SCEP_MSG * const msg,
		                                   SCEP_ATTRIBUTE_TYPE             type) {

	const PKI_X509_ATTRIBUTE *attr = NULL;
	PKI_MEM *ret = NULL;

	const PKI_STRING *st = NULL;
	int nid = NID_undef;

	// Input Check
	if (!msg || msg->value) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	// Attribute Type Check
	if ((nid = PKI_X509_SCEP_ATTRIBUTE_get_nid(type)) == NID_undef) {
		PKI_ERROR(PKI_ERR_SCEP_ATTRIBUTE_UNKNOWN, NULL);
		return NULL;
	}

	// Retrieves the Signed Attribute from the message
	if ((attr = PKI_X509_PKCS7_get_signed_attribute(msg, nid)) == NULL) {

		// Attribute not present
		return NULL;
	}

	// If we have a value, let's return it in a PKI_MEM container
	if ((st = PKI_X509_ATTRIBUTE_get_value(attr)) != NULL) {

		// Build the container
		ret = PKI_MEM_new_null ();
		ret->data = PKI_Malloc((size_t) st->length);
		ret->size = (size_t) st->length;

		// Copy the data from the attribute to the container
		memcpy(ret->data, st->data, (size_t)st->length);
	}

	// Returns the container
	return ret;
}

int PKI_X509_SCEP_MSG_get_attr_value_int(const PKI_X509_SCEP_MSG * const msg,
		                                 SCEP_ATTRIBUTE_TYPE             type) {


	PKI_MEM *mem = NULL;
	int ret = -1;

	// Input Checks
	if (!msg || !msg->value) return -1;

	// Gets the Value from the message
	if ((mem = PKI_X509_SCEP_MSG_get_attr_value(msg, type)) == NULL) {

		// Attribute not found, let's return -1 as the error value
		return -1;
	}

	// If we have a good value, let's convert it to an integer
	if ( mem && mem->data && mem->size > 0 ) {

		// Gets the integer
		ret = atoi((const char *) mem->data);
	}

	// Free the allocated memory
	PKI_MEM_free(mem);

	// Returns the Attribute value as an integer
	return ret;
}


/* ------------------------ Specific Attributes ------------------------ */

/*! \brief Generates a new PKI_MEM suitable for the transId of a SCEP message */

PKI_MEM *PKI_X509_SCEP_MSG_new_trans_id(const PKI_X509_KEYPAIR * key) {

	CRYPTO_DIGEST *dgst = NULL;
	PKI_MEM *mem = NULL;

	if (!key || !key->value ) return NULL;

	if((dgst = PKI_X509_KEYPAIR_pub_digest(key, PKI_DIGEST_ALG_DEFAULT ))
																== NULL ) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC,
				  "Can not retrieve digest of public key (%d)",
				  PKI_DIGEST_ALG_DEFAULT);

		return NULL;
	}

	// Allocates a new PKI_MEM container
	if(( mem = PKI_MEM_new_null()) == NULL ) {

		// Memory Allocation Error
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		PKI_DIGEST_free ( dgst );
		return NULL;
	}

	// Retrieves the parsed digest value
	if ((mem->data = (unsigned char *) PKI_DIGEST_get_parsed(dgst))
								== NULL ) {
		// Error while getting the parsed digest
		PKI_ERROR(PKI_ERR_DIGEST_VALUE_NULL, NULL);

		// Free Allocated Memory
		PKI_MEM_free(mem);
		PKI_DIGEST_free(dgst);

		// Nothing to return
		return NULL;
	}

	// Sets the Size of the data
	mem->size = strlen((const char *) mem->data);

	// Free the DIGEST structure
	if (dgst) PKI_DIGEST_free(dgst);

	// All Done
	return mem;
}

/*! \brief Sets the transactionId attribute in a SCEP message */

int PKI_X509_SCEP_MSG_set_trans_id(PKI_X509_SCEP_MSG * msg,
	                           const PKI_MEM     * const mem) {

	int ret = PKI_OK;

	// Input Checks
	if (!msg || !mem) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return ( PKI_ERR );
	}

	// Sets the Attribute
	ret = PKI_X509_SCEP_MSG_set_attribute(msg,
		                              SCEP_ATTRIBUTE_TRANS_ID,
		                              mem->data,
					      mem->size );

	// Returns the return code from setting the attribute
	return ret;
}

char * PKI_X509_SCEP_MSG_get_trans_id(const PKI_X509_SCEP_MSG * const msg) {

	PKI_MEM * mem = NULL;
	char    * ret = NULL;

	if((mem = PKI_X509_SCEP_MSG_get_attr_value(msg,
						SCEP_ATTRIBUTE_TRANS_ID)) == NULL) {
		return NULL;
	}

	// Checks the returned MEM structure for data
	if (!mem->data || mem->size <= 0) {
		PKI_MEM_free(mem);
		return NULL;
	}

	// Get a reference
	ret = (char *) mem->data;
	mem->data = NULL;
	mem->size = 0;

	// Releases the PKI_MEM structure
	PKI_MEM_free(mem);

	// Returns the duplicated value
	return ret;
}

/*! \brief Sets the senderNonce attribute in a SCEP message */

int PKI_X509_SCEP_MSG_set_sender_nonce(PKI_X509_SCEP_MSG * msg,
		                               const PKI_MEM     * const mem) {

	int ret = PKI_OK;

	// Input Check
	if (!msg) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if (mem != NULL) {
		ret = PKI_X509_SCEP_MSG_set_attribute(msg,
			                                  SCEP_ATTRIBUTE_SENDER_NONCE,
										      mem->data,
											  mem->size);
	} else {

		PKI_MEM * aMem = NULL;
			// Locally allocated entry

		// Allocates the local mem structure
		if ((aMem = PKI_MEM_new(NONCE_SIZE)) == NULL)
			return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);

		// Use random bytes to fill in the data
		RAND_bytes(aMem->data, NONCE_SIZE);

		// Sets the Attribute
		ret = PKI_X509_SCEP_MSG_set_attribute(msg,
				                              SCEP_ATTRIBUTE_SENDER_NONCE,
											  aMem->data,
											  aMem->size);

		// Free locally allocated memory
		if (aMem) PKI_MEM_free(aMem);

	}

	return ret;
}


/*! \brief Sets the recipientNonce attribute from a SCEP message */

int PKI_X509_SCEP_MSG_set_recipient_nonce(PKI_X509_SCEP_MSG * msg,
		                                  const PKI_MEM     * const mem) {

	int ret = PKI_OK;

	// Input Check
	if (!msg || !msg->value) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	if( mem != NULL ) {
		ret = PKI_X509_SCEP_MSG_set_attribute(msg,
			                                  SCEP_ATTRIBUTE_RECIPIENT_NONCE,
											  mem->data,
											  mem->size );
	} else {

		PKI_MEM * aMem = NULL;
			// Locally allocated structure

		// Allocate the structure
		if ((aMem = PKI_MEM_new(NONCE_SIZE)) ==  NULL)
			return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);

		// Fill in with random bytes
		RAND_bytes(aMem->data, NONCE_SIZE);

		// Sets the attribute
		ret = PKI_X509_SCEP_MSG_set_attribute(msg,
				                              SCEP_ATTRIBUTE_RECIPIENT_NONCE,
											  aMem->data,
											  aMem->size);

		// Free locally allocated memory
		PKI_MEM_free(aMem);
	}

	// All Done
	return ret;
}

/*! \brief Sets the messageType attribute in a SCEP message */

int PKI_X509_SCEP_MSG_set_type(PKI_X509_SCEP_MSG * msg,
		                       SCEP_MESSAGE_TYPE   type) {

	return PKI_X509_SCEP_MSG_set_attribute_int(msg,
				                               SCEP_ATTRIBUTE_MESSAGE_TYPE,
											   type);
}

/*! \brief Returns the messageType attribute from a SCEP message */

SCEP_MESSAGE_TYPE PKI_X509_SCEP_MSG_get_type(const PKI_X509_SCEP_MSG * const msg) {

	return PKI_X509_SCEP_MSG_get_attr_value_int(msg,
			                                    SCEP_ATTRIBUTE_MESSAGE_TYPE);
}

/*! \brief Sets the pkiStatus attribute in a SCEP message */

int PKI_X509_SCEP_MSG_set_status(PKI_X509_SCEP_MSG * msg,
		                         SCEP_STATUS         status) {

	return PKI_X509_SCEP_MSG_set_attribute_int(msg,
				                               SCEP_ATTRIBUTE_PKI_STATUS,
											   (int)status);
}


/*! \brief Returns the pkiStatus attribute from a SCEP message */

SCEP_STATUS PKI_X509_SCEP_MSG_get_status(const PKI_X509_SCEP_MSG * const msg) {

	return (SCEP_STATUS) PKI_X509_SCEP_MSG_get_attr_value_int(msg,
			                                                  SCEP_ATTRIBUTE_PKI_STATUS);
}

/*! \brief Sets the failInfo attribute in a SCEP message */

int PKI_X509_SCEP_MSG_set_failinfo(PKI_X509_SCEP_MSG * msg,
		                           int                 fail) {

	return PKI_X509_SCEP_MSG_set_attribute_int(msg,
				                               SCEP_ATTRIBUTE_FAIL_INFO,
											   fail);
}

/*! \brief Returns the failInfo attribute from a SCEP message */

SCEP_FAILURE PKI_X509_SCEP_MSG_get_failinfo(const PKI_X509_SCEP_MSG * const msg) {

	return (SCEP_FAILURE) PKI_X509_SCEP_MSG_get_attr_value_int(msg,
				                                               SCEP_ATTRIBUTE_FAIL_INFO);
}


/*! \brief Returns the senderNonce attribute from a SCEP message */

PKI_MEM *PKI_X509_SCEP_MSG_get_sender_nonce(const PKI_X509_SCEP_MSG * const msg) {

	return PKI_X509_SCEP_MSG_get_attr_value(msg,
				                            SCEP_ATTRIBUTE_SENDER_NONCE);
}

/*! \brief Returns the recipientNonce attribute from a SCEP message */

PKI_MEM *PKI_X509_SCEP_MSG_get_recipient_nonce(PKI_X509_SCEP_MSG * const msg) {

	return PKI_X509_SCEP_MSG_get_attr_value ( msg,
			SCEP_ATTRIBUTE_RECIPIENT_NONCE );
}

/*! \brief Sets the proxyAuthenticator attribute from a SCEP message */

int PKI_X509_SCEP_MSG_set_proxy(PKI_X509_SCEP_MSG * msg,
		                        int                 auth) {

	return PKI_X509_SCEP_MSG_set_attribute_int(msg,
			                                   SCEP_ATTRIBUTE_PROXY_AUTH,
											   auth );
}

int PKI_X509_SCEP_MSG_get_proxy(const PKI_X509_SCEP_MSG * const msg) {

	return PKI_X509_SCEP_MSG_get_attr_value_int(msg,
			                                    SCEP_ATTRIBUTE_PROXY_AUTH );

}

