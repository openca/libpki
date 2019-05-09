/* EST msg handling
 * (c) 2009-2019 by Massimiliano Pala and OpenCA Labs
 * All Rights Reserved
 */

#include <libpki/pki.h>

/*! \brief Generates a new PKI_X509_EST message */

PKI_X509_EST_MSG *PKI_X509_EST_MSG_new ( EST_MESSAGE_TYPE type ) {

	PKI_X509_EST_MSG * ret = NULL;

	if ((ret = PKI_X509_PKCS7_new (PKI_X509_PKCS7_TYPE_SIGNED)) == NULL){
		return NULL;
	}

	return ret;
}

/*! \brief Frees the memory associated with a PKI_X509_EST_MSG */

void PKI_X509_EST_MSG_free ( PKI_X509_EST_MSG *msg ) {

	PKI_X509_PKCS7_free ( msg );

	return;
}

/*! \brief Encodes a EST_MSG to a PKCS7 structure */

int PKI_X509_EST_MSG_encode ( PKI_X509_EST_MSG *msg, 
					PKI_X509_EST_DATA *data ) {

	PKI_MEM *mem = NULL;
	int ret = PKI_OK;

	if ((mem = PKI_X509_PKCS7_put_mem ( data, PKI_DATA_FORMAT_ASN1,
			NULL, NULL, NULL )) == NULL ) {
		return PKI_ERR;
	}

	ret = PKI_X509_PKCS7_encode ( msg, mem->data, mem->size );
	PKI_MEM_free ( mem );

	return ret;
}

/*! \brief Retrieves the decoded data (raw) from a EST_MSG */

PKI_MEM *PKI_X509_EST_MSG_decode ( PKI_X509_EST_MSG *msg,
		PKI_X509_KEYPAIR * key, PKI_X509_CERT *x ) {

	return PKI_X509_PKCS7_decode ( msg, key, x );
}

/*!
 *  \brief Retrieves the X509 object from the EST_MSG
 */

PKI_X509 *PKI_X509_EST_MSG_get_x509_obj ( PKI_X509_EST_MSG *msg,
		PKI_DATATYPE type, PKI_X509_KEYPAIR *key, PKI_X509_CERT *x ) {

	PKI_MEM *mem = NULL;
	PKI_X509 *ret = NULL;

	if((mem = PKI_X509_PKCS7_decode ( msg, key, x )) == NULL ) {
		PKI_log_debug("Can not decode EST message");
		return NULL;
	};

	if((ret = PKI_X509_get_mem( mem, type, NULL, NULL )) == NULL ) {
		PKI_log_debug("Can not get X509 object (%d) from raw data.", type);
	};

	if(mem) PKI_MEM_free ( mem );

	return ret;
}

/*! \brief Add a signer to a EST_MSG */

int PKI_X509_EST_MSG_add_signer ( PKI_X509_EST_MSG *msg,
		PKI_X509_CERT *signer, PKI_X509_KEYPAIR *key,
			PKI_DIGEST_ALG *md ) {

	return PKI_X509_PKCS7_add_signer (msg, signer, key, md);
}

/*! \brief Add a signer to a EST_MSG by using the passed toke data */

int PKI_X509_EST_MSG_add_signer_tk ( PKI_X509_EST_MSG *msg,
		PKI_TOKEN *tk, PKI_DIGEST_ALG *md ) {

	return PKI_X509_PKCS7_add_signer_tk ( msg, tk, md );
}

/*! \brief Generates a PKCSReq message from a keypair and a subject */

PKI_X509_EST_MSG * PKI_X509_EST_MSG_new_certreq ( PKI_X509_KEYPAIR *key,
		PKI_X509_REQ *req, PKI_X509_CERT *signer,
		PKI_X509_CERT_STACK *recipients, PKI_DIGEST_ALG *md ) {

	PKI_X509_EST_MSG *ret = NULL;
	PKI_X509_EST_DATA *est_data = NULL;

	PKI_X509_REQ *my_request = NULL;
	PKI_X509_CERT *my_signer = NULL;

	if ( !key || !key->value ) {
		PKI_log_err ( "Signing Key is required!");
		return NULL;
	}

	if ( ( !req || !req->value ) && (!signer || !signer->value ) ) {
		PKI_log_err ( "ERROR, a request or singer is required!");
		return NULL;
	}

	if ( !recipients ) {
		PKI_log_err ("Recipients are required to encrypt EST messge!");
		return NULL;
	}

	if ( req && req->value ) {
		my_request = req;
	} else {
		char *subject = NULL;

		subject = PKI_X509_CERT_get_parsed( signer,
				PKI_X509_DATA_SUBJECT );

		if ( !subject ) return NULL;

		/* We need the request for the inner P7 (encrypted) */
        	if((my_request = PKI_X509_REQ_new( key, subject, NULL,
                                        NULL, NULL, NULL )) == NULL ) {
                	PKI_log_err( "EST_MSG_new_certreq()::Can not generate "
                        	"a new PKCS#10 request");
			PKI_Free ( subject );
                	goto err;
		};

		PKI_Free ( subject );
        }

	if ( signer && signer->value ) {
		my_signer = signer;
	} else {
		// char * subject = NULL;

		// if (( subject = PKI_X509_REQ_get_parsed ( my_request,
		// 		PKI_X509_DATA_SUBJECT )) == NULL ) {
		// 	return NULL;
		// }

		if ((my_signer = PKI_X509_CERT_new ( NULL, key,
			my_request, NULL, NULL, PKI_VALIDITY_ONE_MONTH, NULL,
				NULL, NULL, NULL )) == NULL ) {

			PKI_log_err ( "Can not generate a self-sign cert for "
					"EST message");
			goto err;
		}
		// PKI_Free ( subject );
	}

	if ( (est_data = PKI_X509_EST_DATA_new ()) == NULL ) {
		PKI_log_err ( "Memory Failure");
		goto err;
	}

	if ( PKI_X509_EST_DATA_set_recipients ( est_data, 
				recipients ) == PKI_ERR ) {
		PKI_log_err ( "Can not set recipients in EST message!");
		goto err;
	}

	if ( PKI_X509_EST_DATA_set_x509_obj( est_data, 
				my_request ) == PKI_ERR ) {
		goto err;
	}

	// Now we have the encrypted content, let's generate the outer
	// message and set the content
	
	if(( ret = PKI_X509_EST_MSG_new(PKI_X509_EST_MSG_PKCSREQ)) == NULL ) {
		PKI_log_err ( "Memory Failure");
		goto err;
	}

	if( PKI_X509_EST_MSG_add_signer ( ret, my_signer, key, md ) 
			== PKI_ERR ) {
		PKI_log_err ( "Can not set the EST message signer");
		goto err;
	}

	PKI_X509_EST_MSG_set_sender_nonce ( ret, NULL );
	PKI_X509_EST_MSG_set_type ( ret, PKI_X509_EST_MSG_PKCSREQ );

	if (PKI_X509_EST_MSG_encode ( ret, est_data ) == PKI_ERR ) {
		PKI_log_err ( "Can not encode EST message!");
		goto err;
	}

	return ret;

err:
	if ( my_request && !req ) PKI_X509_REQ_free (my_request);
	if ( my_signer && !signer ) PKI_X509_CERT_free (my_signer);
	if ( est_data ) PKI_X509_EST_DATA_free ( est_data );
	if ( ret ) PKI_X509_EST_MSG_free ( ret );

	return NULL;
}
