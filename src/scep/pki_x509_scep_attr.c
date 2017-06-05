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

SCEP_ATTRIBUTE_TYPE PKI_X509_SCEP_ATTRIBUTE_get_txt ( char * txt ) {

	SCEP_CONF_ATTRIBUTE *curr = NULL;
	int i = 0;

	i = 0;
        while( i < SCEP_CONF_LIST_SIZE ) {
		curr = &SCEP_ATTRIBUTE_list[i];
		if ( strcmp_nocase ( curr->descr, txt ) == 0 ) {
			break;
		}
		i++;
	}

	if ( curr ) return (SCEP_ATTRIBUTE_TYPE)curr->attr_type;

	return (SCEP_ATTRIBUTE_TYPE) -1;
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
int PKI_X509_SCEP_MSG_set_attribute ( PKI_X509_PKCS7 *msg, SCEP_ATTRIBUTE_TYPE type,
					unsigned char *data, size_t size ) {

	PKI_X509_ATTRIBUTE *a = NULL;
	PKI_ID id = 0;

	PKI_log_debug("PKI_X509_SCEP_MSG_set_attribute()::Start");

	if (!msg || !data ) return ( PKI_ERR );

	if((id = PKI_X509_SCEP_ATTRIBUTE_get_nid ( type )) == NID_undef ) {
		PKI_log_debug("PKI_X509_SCEP_MSG_set_attribute()::ID %d is not a valid "
			"SCEP attribute ID!", id );
		return PKI_ERR;
	}
		
	switch ( type ) {
		case SCEP_ATTRIBUTE_MESSAGE_TYPE:
		case SCEP_ATTRIBUTE_PKI_STATUS:
		case SCEP_ATTRIBUTE_FAIL_INFO:
		case SCEP_ATTRIBUTE_TRANS_ID:
		case SCEP_ATTRIBUTE_EXTENSION_REQ:
		case SCEP_ATTRIBUTE_PROXY_AUTH:
			a = PKI_X509_ATTRIBUTE_new( id,
				V_ASN1_PRINTABLESTRING, data, size );
			break;
		case SCEP_ATTRIBUTE_SENDER_NONCE:
		case SCEP_ATTRIBUTE_RECIPIENT_NONCE:
			a = PKI_X509_ATTRIBUTE_new( id,
				V_ASN1_OCTET_STRING, data, size );
			break;
		default:
			return PKI_ERR;
	}

	if( !a ) return ( PKI_ERR );

	PKI_X509_PKCS7_delete_signed_attribute ( msg, id );

        return (PKI_X509_PKCS7_add_signed_attribute( msg, a));
}

/*! \brief Adds an attribute (identified by its name) to a SCEP message */

int PKI_X509_SCEP_MSG_set_attribute_by_name ( PKI_X509_PKCS7 *msg, 
		char *name, unsigned char *data, size_t size ) {

	PKI_ID type = 0;
	// PKI_OID *oid = NULL;

	if( !msg || !data || !name ) return ( PKI_ERR );

	// if((oid = PKI_OID_new ( name )) == NULL ) return PKI_ERR;

	if((type = PKI_X509_SCEP_ATTRIBUTE_get_txt ( name )) == -1 ) {
		return PKI_ERR;
	}

	return PKI_X509_SCEP_MSG_set_attribute( msg, type, data, size );

}

/*! \brief Adds the specified attribute (int) as a string */

int PKI_X509_SCEP_MSG_set_attribute_int ( PKI_X509_PKCS7 *msg, PKI_ID id, int val ) {

	char buf[1024];

	if (!msg ) return ( PKI_ERR );

	snprintf( buf, sizeof(buf), "%d%c", val, '\x0' );

	return ( PKI_X509_SCEP_MSG_set_attribute( msg, id, 
					(unsigned char*) buf, strlen(buf)));
}

/*! \brief Returns the value of the specified attribute in a PKI_MEM */

PKI_MEM * PKI_X509_SCEP_MSG_get_attr_value ( PKI_X509_SCEP_MSG *msg,
		SCEP_ATTRIBUTE_TYPE type ) {

	PKI_X509_ATTRIBUTE *attr = NULL;
	PKI_MEM *ret = NULL;

	PKI_STRING *st = NULL;
	int nid = NID_undef;

	if( !msg || msg->value ) return ( NULL );

	if((nid = PKI_X509_SCEP_ATTRIBUTE_get_nid ( type )) == NID_undef ) {
		return NULL;
	}

	if((attr = PKI_X509_PKCS7_get_signed_attribute ( msg, nid )) == NULL ) {
		return NULL;
	}

	st = PKI_X509_ATTRIBUTE_get_value ( attr );

	ret = PKI_MEM_new_null ();
	ret->data = PKI_Malloc((size_t) st->length);
	ret->size = (size_t) st->length;

	memcpy( ret->data, st->data, (size_t) st->length );

	return ret;
}

int PKI_X509_SCEP_MSG_get_attr_value_int ( PKI_X509_SCEP_MSG *msg,
		SCEP_ATTRIBUTE_TYPE type ) {

	PKI_MEM *mem = NULL;
	int ret = -1;

	if ( !msg || !msg->value ) return -1;

	if (( mem = PKI_X509_SCEP_MSG_get_attr_value ( msg, type )) == NULL ) {
		return -1;
	}

	if ( mem && mem->data && mem->size > 0 ) {
		ret = atoi ( (const char *) mem->data );
	}

	PKI_MEM_free ( mem );

	return ret;
}


/* ------------------------ Specific Attributes ------------------------ */

/*! \brief Generates a new PKI_MEM suitable for the transId of a SCEP message */

PKI_MEM *PKI_X509_SCEP_MSG_new_trans_id ( PKI_X509_KEYPAIR *key ) {

	PKI_DIGEST *dgst = NULL;
	PKI_MEM *mem = NULL;

	if (!key || !key->value ) return NULL;

	if((dgst = PKI_X509_KEYPAIR_pub_digest ( key, 
			PKI_DIGEST_ALG_DEFAULT )) == NULL ) {
		return NULL;
	}

	if(( mem = PKI_MEM_new_null()) == NULL ) {
		PKI_DIGEST_free ( dgst );
		return NULL;
	}

	if(( mem->data = (unsigned char *) PKI_DIGEST_get_parsed ( dgst )) 
								== NULL ) {
		PKI_MEM_free ( mem );
		PKI_DIGEST_free ( dgst );
		return NULL;
	}

	mem->size = strlen ( (const char *) mem->data );

	if ( dgst ) PKI_DIGEST_free ( dgst );

	return mem;
}

/*! \brief Sets the transactionId attribute in a SCEP message */

int PKI_X509_SCEP_MSG_set_trans_id ( PKI_X509_PKCS7 *msg, PKI_MEM *mem ) {

	PKCS7_SIGNER_INFO *si = NULL;

	int ret = 0;

	if ( !msg ) return ( PKI_ERR );

	/* If mem is not null, we use its content for the TRANSACTION ID */
	if ( mem ) {
		return PKI_X509_SCEP_MSG_set_attribute( msg, SCEP_ATTRIBUTE_TRANS_ID,
			mem->data, mem->size );
	}

	if(( si = PKI_X509_PKCS7_get_signer_info ( msg, -1 )) == NULL ) {
		PKI_log_debug("PKI_X509_SCEP_MSG_set_transaction_id()::Please add signer"
			" before adding the transaction id!");
		return ( PKI_ERR );
	}
	
	/*
	// If no mem, calculate the TRANSACTION_ID by hashing the p7 key
	if((dgst = PKI_X509_KEYPAIR_VALUE_pub_digest(si->pkey, 
				PKI_DIGEST_ALG_DEFAULT )) == NULL) {
		PKI_log_err("Can not calculate SCEP TransID");
		return ( PKI_ERR );
	}

	if((num = PKI_INTEGER_new_bin ( dgst->digest, dgst->size )) == NULL ){
		PKI_log_debug( "ERROR::Can not convert to Integer!");
		if( dgst ) PKI_DIGEST_free (dgst);
		return ( PKI_ERR );
	}

	if((num_s = PKI_INTEGER_get_parsed ( num )) == NULL ) {
		PKI_log_debug("ERRO::Can not convert integer to string!");
		if( dgst ) PKI_DIGEST_free ( dgst );
		return (PKI_ERR);
	}
	
	ret = PKI_X509_SCEP_MSG_set_attribute( msg, SCEP_TRANS_ID_ATTRIBUTE,
				(unsigned char *) num_s, strlen(num_s) );

	if ( num_s ) PKI_Free ( num_s );
	if ( num ) PKI_INTEGER_free ( num );
	if ( dgst ) PKI_DIGEST_free ( dgst );
	*/

	return ( ret );
}

char * PKI_X509_SCEP_MSG_get_trans_id ( PKI_X509_SCEP_MSG * msg ) {

	PKI_MEM *mem = NULL;
	char *ret = NULL;

	if((mem = PKI_X509_SCEP_MSG_get_attr_value ( msg,
			SCEP_ATTRIBUTE_TRANS_ID )) == NULL ) {
		return NULL;
	}

	if ( !mem->data || mem->size <= 0 ) {
		PKI_MEM_free ( mem );
		return NULL;
	}

	ret = strdup ( (const char *) mem->data );
	PKI_MEM_free ( mem );

	return ret;
}

/*! \brief Sets the messageType attribute in a SCEP message */

int PKI_X509_SCEP_MSG_set_type ( PKI_X509_PKCS7 *msg, SCEP_MESSAGE_TYPE type ) {

	if ( !msg || !msg->value ) return PKI_ERR;

	return PKI_X509_SCEP_MSG_set_attribute_int ( msg, 
				SCEP_ATTRIBUTE_MESSAGE_TYPE, type );
}


/*! \brief Returns the messageType attribute from a SCEP message */

SCEP_MESSAGE_TYPE PKI_X509_SCEP_MSG_get_type ( PKI_X509_PKCS7 *msg ) {

	return PKI_X509_SCEP_MSG_get_attr_value_int ( msg,
			SCEP_ATTRIBUTE_MESSAGE_TYPE );
}

/*! \brief Sets the pkiStatus attribute in a SCEP message */

int PKI_X509_SCEP_MSG_set_status ( PKI_X509_PKCS7 *msg, SCEP_STATUS status ) {

	if ( !msg || !msg->value ) return PKI_ERR;

	return PKI_X509_SCEP_MSG_set_attribute_int ( msg, 
				SCEP_ATTRIBUTE_PKI_STATUS, status );
}

/*! \brief Returns the pkiStatus attribute from a SCEP message */

SCEP_STATUS PKI_X509_SCEP_MSG_get_status ( PKI_X509_PKCS7 *msg ) {

	return (SCEP_STATUS) PKI_X509_SCEP_MSG_get_attr_value_int ( msg, 
			SCEP_ATTRIBUTE_PKI_STATUS );
}

/*! \brief Sets the failInfo attribute in a SCEP message */

int PKI_X509_SCEP_MSG_set_failinfo ( PKI_X509_PKCS7 *msg, int fail ) {
	if ( !msg || !msg->value ) return PKI_ERR;

	return PKI_X509_SCEP_MSG_set_attribute_int ( msg, 
				SCEP_ATTRIBUTE_FAIL_INFO, fail );
}

/*! \brief Returns the failInfo attribute from a SCEP message */

SCEP_FAILURE PKI_X509_SCEP_MSG_get_failinfo ( PKI_X509_PKCS7 *msg ) {

	return (SCEP_FAILURE) PKI_X509_SCEP_MSG_get_attr_value_int ( msg,
				SCEP_ATTRIBUTE_FAIL_INFO );
}

/*! \brief Sets the senderNonce attribute in a SCEP message */

int PKI_X509_SCEP_MSG_set_sender_nonce ( PKI_X509_PKCS7 *msg, PKI_MEM *mem ) {

	int ret = PKI_OK;

	if( !msg ) return ( PKI_ERR );

	if( mem ) {
		return ( PKI_X509_SCEP_MSG_set_attribute( msg, 
			SCEP_ATTRIBUTE_SENDER_NONCE, mem->data, mem->size ));
	};

	if((mem = PKI_MEM_new( NONCE_SIZE )) ==  NULL ) {
		PKI_log_debug( "PKI_X509_SCEP_MSG_set_nonce_sender()::Memory Error!");
		return ( PKI_ERR );
	}

	RAND_bytes(mem->data, NONCE_SIZE);

	ret = PKI_X509_SCEP_MSG_set_attribute( msg, 
			SCEP_ATTRIBUTE_SENDER_NONCE, mem->data, mem->size);

	if( mem ) PKI_MEM_free ( mem );

	return ( ret );
}

/*! \brief Returns the senderNonce attribute from a SCEP message */

PKI_MEM *PKI_X509_SCEP_MSG_get_sender_nonce ( PKI_X509_PKCS7 *msg ) {
	if( !msg || !msg->value ) return NULL;

	return PKI_X509_SCEP_MSG_get_attr_value ( msg, 
				SCEP_ATTRIBUTE_SENDER_NONCE );
	return ( NULL );
}

/*! \brief Sets the recipientNonce attribute from a SCEP message */

int PKI_X509_SCEP_MSG_set_recipient_nonce ( PKI_X509_PKCS7 *msg, PKI_MEM *mem ) {

	int ret = PKI_OK;

	if( !msg ) return ( PKI_ERR );

	if( mem ) {
		return ( PKI_X509_SCEP_MSG_set_attribute( msg, 
			SCEP_ATTRIBUTE_RECIPIENT_NONCE, mem->data, mem->size ));
	};

	if((mem = PKI_MEM_new( NONCE_SIZE )) ==  NULL ) {
		PKI_log_debug( "PKI_X509_SCEP_MSG_set_nonce_sender()::Memory Error!");
		return ( PKI_ERR );
	}

	RAND_bytes(mem->data, NONCE_SIZE);

	ret = PKI_X509_SCEP_MSG_set_attribute( msg, 
			SCEP_ATTRIBUTE_RECIPIENT_NONCE, mem->data, mem->size);

	if( mem ) PKI_MEM_free ( mem );

	return ( ret );
}

/*! \brief Returns the recipientNonce attribute from a SCEP message */

PKI_MEM *PKI_X509_SCEP_MSG_get_recipient_nonce ( PKI_X509_PKCS7 *msg ) {
	if ( !msg || !msg->value ) return NULL;

	return PKI_X509_SCEP_MSG_get_attr_value ( msg,
			SCEP_ATTRIBUTE_RECIPIENT_NONCE );
	return ( NULL );
}

/*! \brief Sets the proxyAuthenticator attribute from a SCEP message */

int PKI_X509_SCEP_MSG_set_proxy ( PKI_X509_PKCS7 *msg, int auth ) {

	if ( !msg || !msg->value ) return PKI_ERR;

	return PKI_X509_SCEP_MSG_set_attribute_int ( msg,
			SCEP_ATTRIBUTE_PROXY_AUTH, auth );
}

/*! \brief Returns the proxyAuthenticator attribute from a SCEP message */

int PKI_X509_SCEP_MSG_get_proxy ( PKI_X509_PKCS7 *msg ) {

	return PKI_X509_SCEP_MSG_get_attr_value_int ( msg,
			SCEP_ATTRIBUTE_PROXY_AUTH );

}

