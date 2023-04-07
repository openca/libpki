/* src/pki_msg_resp.c - General PKI message (responses)
 * (c) 2009 by Massimiliano Pala and OpenCA Labs
 * All Rights Reserved
 */

#include <libpki/pki.h>

/*! \brief Returns an empty generic PKI response message */
PKI_MSG_RESP *PKI_MSG_RESP_new_null ( void ) {

	PKI_MSG_RESP *ret = NULL;

	if((ret = PKI_Malloc(sizeof(PKI_MSG_RESP))) == NULL ) {
		return NULL;
	}

	return ret;
}

/*! \brief Free a PKI_MSG_REQ data structure */
void PKI_MSG_RESP_free ( PKI_MSG_RESP *msg ) {

	if( !msg ) return;

	if( msg->data ) PKI_MEM_free ( msg->data );
}

/*! \brief Adds data to the Message body */
int PKI_MSG_RESP_add_data (PKI_MSG_RESP *msg, unsigned char *data, size_t size){

	if( !msg || !data || size <= 0 ) return ( PKI_ERR );

	if( msg->data == NULL ) {
		if((msg->data = PKI_MEM_new_null()) == NULL ) {
			PKI_log_debug("PKI_MSG_REQ_add_data()::Memory Error!");
			return ( PKI_ERR );
		}
	}

	if((PKI_MEM_add( msg->data, data, size)) == PKI_ERR ) {
		return PKI_ERR;
	}

	return ( PKI_OK );
}

/*! \brief Replaces data in a PKI_MSG_RESP message */

int PKI_MSG_RESP_replace_data ( PKI_MSG_RESP *msg, unsigned char *data,
							size_t size ) {
	if( !msg || !data || size <= 0 ) return ( PKI_ERR );

	if(PKI_MSG_RESP_clear_data ( msg ) == PKI_ERR ) return PKI_ERR;

	return ( PKI_MSG_RESP_add_data ( msg, data, size ));
}

/*! \brief Clears the data of the Message body */
int PKI_MSG_RESP_clear_data ( PKI_MSG_RESP *msg ) {

	if ( !msg ) return (PKI_ERR);

	if ( msg->data ) PKI_MEM_free ( msg->data );

	msg->data = NULL;

	return ( PKI_OK );
}

/*! \brief Sets the messaging protocol to be used */
int PKI_MSG_RESP_set_proto ( PKI_MSG_RESP *msg, PKI_MSG_PROTO proto ) {

	if ( !msg ) return ( PKI_ERR );

	switch ( proto ) {
		case PKI_MSG_PROTO_SCEP:
		case PKI_MSG_PROTO_CMC:
			msg->proto = proto;
			break;
		default:
			return ( PKI_ERR );
	}

	return PKI_OK;
}

/*! \brief Returns the PKI_MSG_PROTO from a PKI_MSG_RESP object */
PKI_MSG_PROTO PKI_MSG_RESP_get_proto ( PKI_MSG_RESP *msg ) {

	if( !msg ) return ( PKI_MSG_PROTO_UNKNOWN );

	return ( msg->proto );
}

/*! \brief Gets the certificate from the Response */
PKI_X509_CERT *PKI_MSG_RESP_get_issued_cert ( PKI_MSG_RESP *msg ) {

	if( !msg || !msg->issued_cert ) return ( NULL );

	return ( msg->issued_cert );
}

/*! \brief Sets the certificate from the Response */
int PKI_MSG_RESP_set_issued_cert ( PKI_MSG_RESP *msg, PKI_X509_CERT *x ) {

	if( !msg || !x ) return ( PKI_ERR );

	if( msg->issued_cert ) PKI_X509_CERT_free ( msg->issued_cert );

	if((msg->issued_cert = PKI_X509_CERT_dup ( x )) == NULL ) {
		return ( PKI_ERR );
	}

	return ( PKI_OK );
}


/*! \brief Gets the CA certificate from the Response */
PKI_X509_CERT *PKI_MSG_RESP_get_cacert ( PKI_MSG_RESP *msg ) {

	if( !msg || !msg->cacert ) return ( NULL );

	return ( msg->cacert );
}

/*! \brief Sets the CA certificate in the Response */
int PKI_MSG_RESP_set_cacert ( PKI_MSG_RESP *msg, PKI_X509_CERT *x ) {

	if( !msg || !x ) return ( PKI_ERR );

	if( msg->cacert ) PKI_X509_CERT_free ( msg->cacert );

	if((msg->cacert = PKI_X509_CERT_dup ( x )) == NULL ) {
		return ( PKI_ERR );
	}

	return ( PKI_OK );
}


/*! \brief Sets the status in a PKI_MSG_RESP message */
int PKI_MSG_RESP_set_status ( PKI_MSG_RESP *msg, PKI_MSG_STATUS status ) {

	if( !msg ) return ( PKI_ERR );

	msg->status = status;

	return ( PKI_OK );
}

/*! \brief Gets the status in a PKI_MSG_RESP message */
PKI_MSG_STATUS PKI_MSG_RESP_get_status ( PKI_MSG_RESP *msg ) {

	if( !msg ) return ( PKI_ERR );

	return ( msg->status );
}


/*! \brief Sets the basic action in a PKI_MSG_RESP message */
int PKI_MSG_RESP_set_action ( PKI_MSG_RESP *msg, PKI_MSG_RESP_ACTION action ) {

	if( !msg ) return ( PKI_ERR );

	/* We should check that the provided action is one within
	   the enum, something like:
		switch ( action ) {
			case PKI_MSG_RESP_ACTION_XX:
			case PKI_MSG_RESP_ACTION_YY:
				msg->action = action;
				break;
			default:
				return ( PKI_ERR );
		}
	*/

	msg->action = action;
	return ( PKI_OK );
}

/*! \brief Gets the basic action in a PKI_MSG_RESP message */
PKI_MSG_RESP_ACTION PKI_MSG_RESP_get_action ( PKI_MSG_RESP *msg ) {

	if( !msg ) return ( PKI_ERR );

	return ( msg->action );
}

/*! \brief Sets the Keypair to be used when generating the response */
int PKI_MSG_RESP_set_keypair ( PKI_MSG_RESP *msg, PKI_X509_KEYPAIR * pkey ) {

	if( !msg || !pkey || !pkey->value ) return ( PKI_ERR );

	if( msg->sign_key ) PKI_X509_KEYPAIR_free ( msg->sign_key );

	msg->sign_key = pkey;

	return ( PKI_OK );
}

/*! \brief Gets the Keypair to be used when generating the response */
PKI_X509_KEYPAIR * PKI_MSG_RESP_get_keypair ( PKI_MSG_RESP *msg ) {

	if( !msg ) return ( NULL );

	return ( msg->sign_key );
}

/*! \brief Sets the Signer Certificate */
int PKI_MSG_RESP_set_signer ( PKI_MSG_RESP *msg, PKI_X509_CERT *signer ) {

	if( !msg || !signer ) return ( PKI_ERR );

	if ( msg->sign_cert ) PKI_X509_CERT_free ( msg->sign_cert );

	if((msg->sign_cert = PKI_X509_CERT_dup ( signer )) == NULL ) {
		return PKI_ERR;
	}

	return ( PKI_OK );
}

/*! \brief Gets the Signer Certificate */
PKI_X509_CERT * PKI_MSG_RESP_get_signer ( PKI_MSG_RESP *msg ) {

	if( !msg || !msg->sign_cert ) return ( NULL );

	return ( msg->sign_cert );
}

/*! \brief Adds a certificate to the list of recipients */
int PKI_MSG_RESP_add_recipient ( PKI_MSG_RESP *msg, PKI_X509_CERT *x ) {

	PKI_X509_CERT *cert = NULL;

	if( !msg || !x ) return ( PKI_ERR );

	if( msg->recipients == NULL ) {
		if((msg->recipients = PKI_STACK_X509_CERT_new()) == NULL){
			PKI_log_debug("PKI_MSG_RESP_add_recipient():: Memory "
								"Error");
			return ( PKI_ERR );
		}
	}

	if(( cert = PKI_X509_CERT_dup ( x )) == NULL ) {
		return ( PKI_ERR );
	}

	return PKI_STACK_X509_CERT_push( msg->recipients, cert );
}

/*! \brief Clears the list of recipients in a PKI_MSG_RESP */
int PKI_MSG_RESP_clear_recipients( PKI_MSG_RESP *msg ) {

	if( !msg ) return ( PKI_ERR );

	if( !msg->recipients ) return ( PKI_OK );

	PKI_STACK_X509_CERT_free_all ( msg->recipients );

	return ( PKI_OK );
}

/*! \brief Gets the list of recipients in a PKI_MSG_RESP */
PKI_X509_CERT_STACK *PKI_MSG_RESP_get_recipients( PKI_MSG_RESP *msg ) {

	if( !msg || !msg->recipients ) return ( NULL );

	return ( msg->recipients );
}

/*! \brief Sets the list of recipients in a PKI_MSG_RESP */
int PKI_MSG_RESP_set_recipients( PKI_MSG_RESP *msg, PKI_X509_CERT_STACK *x_sk) {

	int i = 0;
	PKI_X509_CERT *x = NULL;

	if( !msg || !x_sk ) return ( PKI_ERR );

	if( msg->recipients ) PKI_STACK_X509_CERT_free_all ( msg->recipients );

	if((msg->recipients = PKI_STACK_X509_CERT_new()) == NULL ) {
		PKI_log_debug("PKI_MSG_REQ_set_recipients()::Memory Error!");
		return ( PKI_ERR );
	}

	for( i = 0; i < PKI_STACK_X509_CERT_elements (x_sk); i++ ) {
		x = PKI_STACK_X509_CERT_get_num( x_sk, i );
		if( x == NULL ) continue;

		PKI_STACK_X509_CERT_push( msg->recipients, x );
	}

	return ( PKI_OK );
}

/*! \brief Gets the encoded version of the Response message */
void *PKI_MSG_RESP_get_encoded ( PKI_MSG_RESP *msg ) {

	if( !msg ) return ( NULL );

	return msg->msg_data;
}

/*! \brief Encodes the message according to the selected PKI_MSG_PROTO */
void *PKI_MSG_RESP_encode ( PKI_MSG_RESP *msg, PKI_MSG_PROTO proto ) {

	if( !msg ) return ( NULL );

	if( PKI_MSG_RESP_set_proto ( msg, proto ) == PKI_ERR ) {
		PKI_log_debug( "PKI_MSG_RESP_encode::Unknown proto %d", proto );
		return ( NULL );
	}

	switch ( proto ) {
		case PKI_MSG_PROTO_SCEP:
			// msg->msg_data = PKI_MSG_REQ_SCEP_new ( msg );
			// break;
		case PKI_MSG_PROTO_CMC:
		case PKI_MSG_PROTO_XKMS:
		default:
			PKI_log_err("PKI_MSG_REQ_encode()::Protocol %d "
				"not supported", msg->proto );
	}

	return ( msg->msg_data );
}

/*! Builds a new PKI Response message by using a PKI_TOKEN */
PKI_MSG_RESP *PKI_MSG_RESP_new_tk( PKI_MSG_RESP_ACTION action, 
		PKI_MSG_STATUS status, PKI_TOKEN *tk ) {

	return PKI_MSG_RESP_new ( action, status, tk->keypair,
						tk->cert, tk->cacert );
}


/*! \brief Builds a new message */
PKI_MSG_RESP * PKI_MSG_RESP_new( PKI_MSG_RESP_ACTION action, 
		PKI_MSG_STATUS status, PKI_X509_KEYPAIR *sign_key, 
			PKI_X509_CERT *signer, PKI_X509_CERT *cacert ) {

	PKI_MSG_RESP *ret = NULL;

	if((ret = PKI_MSG_RESP_new_null()) == NULL ) {
		PKI_log_debug("PKI_MSG_RESP_new()::Memory error");
		return NULL;
	}

	switch ( action ) {
		case PKI_MSG_RESP_ACTION_CERTREQ:
			/*
			if( !sign_key || !subject || !cacert ) goto err;
			break;
			*/
		default:
			goto err;
	}

	switch ( status ) {
		case PKI_MSG_STATUS_OK:
			/*
			if( !sign_key || !subject || !cacert ) goto err;
			break;
			*/
		default:
			goto err;
	}

	if ( PKI_MSG_RESP_set_action  (ret, action   ) == PKI_ERR ) goto err;
	if ( PKI_MSG_RESP_set_keypair (ret, sign_key ) == PKI_ERR ) goto err;
	if ( PKI_MSG_RESP_set_cacert  (ret, cacert   ) == PKI_ERR ) goto err;

	if( signer ) {
		if( PKI_MSG_RESP_set_signer ( ret, signer ) == PKI_ERR )
			goto err;
	}

	/* Additional data to be encoded in the body (could be another msg) */
	ret->data = NULL;

	ret->recipients = NULL;

	/* The encoded message */
	ret->msg_data = NULL;

	return ( ret );

err:
	if( ret ) PKI_MSG_RESP_free ( ret );
	return ( NULL );
}


/*! Returns a SCEP_MSG from the passed PKI_MSG_RESP */
PKI_X509_SCEP_MSG *PKI_MSG_RESP_SCEP_new ( PKI_MSG_RESP *msg ) {

	PKI_X509_PKCS7 *ret = NULL;

	if ( !msg ) return ( NULL );

	if( !msg->sign_key ) {
		PKI_log_debug("PKI_MSG_RESP_SCEP_new()::Missing Signing Key!"); 
		return ( NULL );
	}

	if( !msg->cacert ) {
		PKI_log_debug("PKI_MSG_RESP_SCEP_new()::Missing cacert!");
		return ( NULL );
	};

	if ( !msg->recipients ) {
		PKI_MSG_RESP_add_recipient ( msg, msg->cacert );
	}

	/*
	switch ( msg->action ) {
		case PKI_MSG_RESP_ACTION_CERTREQ:
			ret = SCEP_MSG_new_certreq( msg->subject, 
				msg->template_name,
				msg->sign_cert, msg->sign_key,
				msg->cacert, msg->recipients, NULL );
			break;
		default:
			PKI_log_debug("PKI_MSG_REQ_SCEP_put_mem()::Msg type "
				"not supported (%d)", msg->action );
			return ( NULL );
	}
	*/

	PKI_log_debug( "PKI_MSG_RESP_SCEP_new()::Generated Message Ok!");

	if( !ret ) {
		PKI_log_debug("ERROR::Message generation failed!");
	}

	msg->msg_data = ret;

	return ( (PKI_X509_SCEP_MSG *) msg->msg_data );

}

