/* src/io/pki_msg_req.c - General PKI message I/O
 * (c) 2009 by Massimiliano Pala and OpenCA Labs
 * All Rights Reserved
 */

#include <libpki/pki.h>

/*! \brief Writes the message in a memory buffer */

PKI_MEM *PKI_MSG_REQ_put_mem ( PKI_MSG_REQ *msg, PKI_DATA_FORMAT format,
			PKI_MEM **pki_mem, PKI_CRED *cred, HSM *hsm ) {

	if( !msg ) return ( NULL );

	if( !msg->msg_data || !msg->msg_data->value ) {
		int proto = 0;
		proto = PKI_MSG_REQ_get_proto ( msg );

		if (PKI_MSG_REQ_encode ( msg, proto ) == PKI_ERR ) {
			PKI_log_err ("Can not encode message (Proto::%d)", proto);
			return ( NULL );
		}
	}

	PKI_log_debug("PKI_MSG_REQ_put_mem()::Start");

	switch ( msg->proto ) {
		case PKI_MSG_PROTO_SCEP:
			return PKI_X509_PKCS7_put_mem ( msg->msg_data, 
						format, pki_mem, cred, hsm );
			break;
		case PKI_MSG_PROTO_CMC:
		case PKI_MSG_PROTO_XKMS:
		default:
			PKI_log_debug("MSG protocol not supported!");
	}

	return ( NULL );
}


/*! \brief Writes the message to a URL */

int PKI_MSG_REQ_put ( PKI_MSG_REQ *msg, PKI_DATA_FORMAT format, 
			char *url, char *mime, PKI_CRED *cred, 
				HSM *hsm, PKI_MEM_STACK **ret_sk ) {

	PKI_MEM *mem = NULL;

	if( !msg ) return ( PKI_ERR );

	if( !msg->msg_data ) {
		int proto;

		proto = PKI_MSG_REQ_get_proto ( msg );

		if (PKI_MSG_REQ_encode ( msg, proto ) == PKI_ERR ) {
			return ( PKI_ERR );
		}
	}

	PKI_log_debug("PKI_MSG_REQ_put()::Start");

	switch ( msg->proto ) {
		case PKI_MSG_PROTO_SCEP:
			mem = PKI_X509_PKCS7_put_mem ( msg->msg_data, 
					format, NULL, cred, hsm );
			break;
		case PKI_MSG_PROTO_CMC:
		case PKI_MSG_PROTO_XKMS:
		default:
			PKI_log_debug("MSG protocol not supported!");
	}

	if (!mem || !mem->data ) return ( PKI_ERR );

	return URL_put_data( url, mem, "application/x-pki-message", 
					ret_sk, 120, 64*1024, NULL);
}

