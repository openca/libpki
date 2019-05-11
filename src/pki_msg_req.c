/* src/pki_msg_req.c - General PKI message
 * (c) 2009 by Massimiliano Pala and OpenCA Labs
 * All Rights Reserved
 */

#include <libpki/pki.h>

/*! \brief Returns an empty generic PKI request message */
PKI_MSG_REQ *PKI_MSG_REQ_new_null ( void ) {

	PKI_MSG_REQ *ret = NULL;

	if((ret = PKI_Malloc(sizeof(PKI_MSG_REQ))) == NULL ) {
		return NULL;
	}

	return ret;
}

/*! \brief Free a PKI_MSG_REQ data structure */
void PKI_MSG_REQ_free ( PKI_MSG_REQ *msg ) {

	if( !msg ) return;

	if( msg->subject ) PKI_Free ( msg->subject );
	if( msg->template_name ) PKI_Free ( msg->template_name );
	if( msg->loa ) PKI_Free ( msg->loa );
	if( msg->cacert  ) PKI_X509_CERT_free ( msg->cacert );
	if( msg->cred    ) PKI_CRED_free ( msg->cred );
	if( msg->data    ) PKI_MEM_free ( msg->data );
	if( msg->msg_data ) PKI_X509_free ( msg->msg_data );
}

/*! \brief Adds data to the Message body */
int PKI_MSG_REQ_add_data (PKI_MSG_REQ *msg, unsigned char *data, size_t size ){

	if( !msg || !data || size <= 0 ) return ( PKI_ERR );

	if( msg->data == NULL ) {
		if((msg->data = PKI_MEM_new_null()) == NULL ) {
			PKI_log_debug("PKI_MSG_REQ_add_data()::Memory Error!");
			return ( PKI_ERR );
		}
	}

	if((PKI_MEM_add( msg->data, (char *)data, size)) == PKI_ERR ) {
		PKI_log_debug("PKI_MSG_REQ_add_data()::PKI_MEM grow error!");
		return (PKI_ERR);
	}

	return ( PKI_OK );
}

/*! \brief Replaces data in a PKI_MSG_REQ message */
int PKI_MSG_REQ_replace_data ( PKI_MSG_REQ *msg, unsigned char *data,
							size_t size ) {
	if( !msg || !data || size <= 0 ) return ( PKI_ERR );

	if(PKI_MSG_REQ_clear_data ( msg ) == PKI_ERR ) return PKI_ERR;

	return ( PKI_MSG_REQ_add_data ( msg, data, size ));
}

/*! \brief Clears the data of the Message body */
int PKI_MSG_REQ_clear_data ( PKI_MSG_REQ *msg ) {

	if ( !msg ) return (PKI_ERR);

	if ( msg->data ) PKI_MEM_free ( msg->data );

	msg->data = NULL;

	return ( PKI_OK );
}

/*! \brief Sets the messaging protocol to be used */
int PKI_MSG_REQ_set_proto ( PKI_MSG_REQ *msg, PKI_MSG_PROTO proto ) {

	if ( !msg ) return ( PKI_ERR );

	switch ( proto ) {
		case PKI_MSG_PROTO_SCEP:
		case PKI_MSG_PROTO_CMC:
			msg->proto = proto;
			break;
		default:
			PKI_log_err ( "Protocol %d not supported, yet!", proto );
			return ( PKI_ERR );
	}

	return PKI_OK;
}

/*! \brief Returns the PKI_MSG_PROTO from a PKI_MSG_REQUEST object */
PKI_MSG_PROTO PKI_MSG_REQ_get_proto ( PKI_MSG_REQ *msg ) {

	if( !msg ) return ( PKI_MSG_PROTO_UNKNOWN );

	return ( msg->proto );
}

/*! \brief Sets the Certificate of the CA the request is intended for */
int PKI_MSG_REQ_set_cacert ( PKI_MSG_REQ *msg, PKI_X509_CERT *cacert ) {

	if( !msg || !cacert ) return ( PKI_ERR );

	if( msg->cacert ) PKI_X509_CERT_free ( msg->cacert );

	if((msg->cacert = PKI_X509_CERT_dup ( cacert )) == NULL ) {
		return ( PKI_ERR );
	}

	return ( PKI_OK );
}

/*! \brief Gets the Certificate of the CA the request is intended for */
PKI_X509_CERT *PKI_MSG_REQ_get_cacert ( PKI_MSG_REQ *msg ) {

	if( !msg || !msg->cacert ) return ( NULL );

	return ( msg->cacert );
}

/*! \brief Sets the Subject to be used in the certificate request */
int PKI_MSG_REQ_set_subject ( PKI_MSG_REQ *msg, char *subject ) {

	if( !msg || !subject ) return (PKI_ERR);

	if( msg->subject ) PKI_Free ( msg->subject);

	msg->subject = strdup( subject );

	return ( PKI_OK );
}

/*! \brief Gets the Subject to be used in the certificate request */
char * PKI_MSG_REQ_get_subject ( PKI_MSG_REQ *msg ) {

	if ( !msg || !msg->subject ) return ( NULL );

	return ( msg->subject );
}

/*! \brief Sets the basic action in a PKI_MSG_REQ message */
int PKI_MSG_REQ_set_action ( PKI_MSG_REQ *msg, PKI_MSG_REQ_ACTION action ) {

	if( !msg ) return ( PKI_ERR );

	msg->action = action;

	return ( PKI_OK );
}

/*! \brief Gets the basic action in a PKI_MSG_REQ message */
PKI_MSG_REQ_ACTION PKI_MSG_REQ_get_action ( PKI_MSG_REQ *msg ) {

	if( !msg ) return ( PKI_ERR );

	return ( msg->action );
}

/*! \brief Sets the Keypair to be used when generating the request */
int PKI_MSG_REQ_set_keypair ( PKI_MSG_REQ *msg, PKI_X509_KEYPAIR * pkey ) {

	if( !msg || !pkey || !pkey->value ) return ( PKI_ERR );

	if( msg->sign_key ) PKI_X509_KEYPAIR_free ( msg->sign_key );

	msg->sign_key = pkey;

	return ( PKI_OK );
}

/*! \brief Gets the Keypair to be used when generating the request */
PKI_X509_KEYPAIR * PKI_MSG_REQ_get_keypair ( PKI_MSG_REQ *msg ) {

	if( !msg ) return ( NULL );

	return ( msg->sign_key );
}

/*! \brief Sets the Signer Certificate */
int PKI_MSG_REQ_set_signer ( PKI_MSG_REQ *msg, PKI_X509_CERT *signer,
		PKI_DIGEST_ALG *md ) {

	if( !msg || !signer ) return ( PKI_ERR );

	if ( msg->sign_cert ) PKI_X509_CERT_free ( msg->sign_cert );

	if((msg->sign_cert = PKI_X509_CERT_dup ( signer )) == NULL ) {
		return PKI_ERR;
	}

	if ( md ) {
		msg->sign_md = md;
	};

	return ( PKI_OK );
}

/*! \brief Gets the Signer Certificate */
PKI_X509_CERT * PKI_MSG_REQ_get_signer ( PKI_MSG_REQ *msg ) {

	if( !msg || !msg->sign_cert ) return ( NULL );

	return ( msg->sign_cert );
}

/*! \brief Sets the requested certificate template */
int PKI_MSG_REQ_set_template ( PKI_MSG_REQ *msg, char *name ) {

	if( !msg || !name ) return ( PKI_ERR );

	if( msg->template_name ) PKI_Free ( msg->template_name );

	msg->template_name = strdup ( name );

	return ( PKI_OK );
}

/*! \brief Gets the requested certificate template */

char *PKI_MSG_REQ_get_template ( PKI_MSG_REQ *msg ) {

	if( !msg ) return ( NULL );

	return ( msg->template_name );
}

/*! \brief Sets the requested certificate level of assurance (LOA) */
int PKI_MSG_REQ_set_loa ( PKI_MSG_REQ *msg, char * loa ) {

	if( !msg || !loa ) return ( PKI_ERR );

	if( msg->loa ) PKI_Free ( msg->loa );
	msg->loa = strdup ( loa );

	return PKI_OK;
}

/*! \brief Gets the requested certificate template */

char * PKI_MSG_REQ_get_loa ( PKI_MSG_REQ *msg ) {

	if( !msg ) return PKI_ERR;

	return msg->loa;
}

/*! \brief Adds a certificate to the list of recipients */
int PKI_MSG_REQ_add_recipient ( PKI_MSG_REQ *msg, PKI_X509_CERT *x ) {

	PKI_X509_CERT *cert = NULL;

	if( !msg || !x ) return ( PKI_ERR );

	if( msg->recipients == NULL ) {
		if((msg->recipients = PKI_STACK_X509_CERT_new()) == NULL){
			PKI_log_debug("PKI_MSG_REQ_add_recipient():: Memory "
								"Error");
			return ( PKI_ERR );
		}
	}

	if(( cert = PKI_X509_CERT_dup ( x )) == NULL ) {
		return ( PKI_ERR );
	}

	return PKI_STACK_X509_CERT_push( msg->recipients, cert );
}

/*! \brief Clears the list of recipients in a PKI_MSG_REQ */
int PKI_MSG_REQ_clear_recipients( PKI_MSG_REQ *msg ) {

	if( !msg ) return ( PKI_ERR );

	if( !msg->recipients ) return ( PKI_OK );

	PKI_STACK_X509_CERT_free_all ( msg->recipients );

	return ( PKI_OK );
}

/*! \brief Gets the list of recipients in a PKI_MSG_REQ */
PKI_X509_CERT_STACK *PKI_MSG_REQ_get_recipients( PKI_MSG_REQ *msg ) {

	if( !msg || !msg->recipients ) return ( NULL );

	return ( msg->recipients );
}

/*! \brief Sets the list of recipients in a PKI_MSG_REQ */
int PKI_MSG_REQ_set_recipients ( PKI_MSG_REQ *msg, PKI_X509_CERT_STACK *x_sk) {

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

/*! \brief Gets the encoded version of the message */
void *PKI_MSG_REQ_get_encoded ( PKI_MSG_REQ *msg ) {

	PKI_X509 *obj = NULL;

	if( !msg || !msg->msg_data ) return ( NULL );

	obj = msg->msg_data;

	return obj->value;
}

/*! \brief Encodes the message according to the selected PKI_MSG_PROTO */
int PKI_MSG_REQ_encode ( PKI_MSG_REQ *msg, PKI_MSG_PROTO proto ) {

	int ret = PKI_OK;

	if( !msg ) return PKI_ERR;

	if( PKI_MSG_REQ_set_proto ( msg, proto ) == PKI_ERR ) {
		PKI_log_debug( "PKI_MSG_REQ_encode::Unknown proto %d", proto );
		return PKI_ERR;
	}

	switch ( proto ) {
		case PKI_MSG_PROTO_SCEP:
			ret = PKI_MSG_REQ_SCEP_new ( msg );
			break;
		case PKI_MSG_PROTO_CMC:
		case PKI_MSG_PROTO_XKMS:
		default:
			PKI_log_err("PKI_MSG_REQ_encode()::Protocol %d "
				"not supported", msg->proto );
	}

	return ret;
}

/*! Builds a new PKI message by using a PKI_TOKEN */
PKI_MSG_REQ *PKI_MSG_REQ_new_tk( PKI_MSG_REQ_ACTION action, char *subject,
	char *template_name, PKI_TOKEN *tk, PKI_DIGEST_ALG *md ) {

	return PKI_MSG_REQ_new ( action, subject, template_name, tk->keypair,
			tk->cert, tk->cacert, md );
}


/*! \brief Builds a new message */
PKI_MSG_REQ * PKI_MSG_REQ_new( PKI_MSG_REQ_ACTION action, char * subject, 
		char *template_name, PKI_X509_KEYPAIR *sign_key, 
		PKI_X509_CERT *signer, PKI_X509_CERT *cacert,
		PKI_DIGEST_ALG *md ) {

	PKI_MSG_REQ *ret = NULL;

	if((ret = PKI_MSG_REQ_new_null()) == NULL ) {
		PKI_log_debug("PKI_MSG_REQ_new()::Memory error");
		return NULL;
	}

	switch ( action ) {
		case PKI_MSG_REQ_ACTION_CERTREQ:
			if( !sign_key || !subject || !cacert ) goto err;
			break;
		default:
			goto err;
	}

	if ( PKI_MSG_REQ_set_action  (ret, action   ) == PKI_ERR ) goto err;
	if ( PKI_MSG_REQ_set_keypair (ret, sign_key ) == PKI_ERR ) goto err;
	if ( PKI_MSG_REQ_set_subject (ret, subject  ) == PKI_ERR ) goto err;
	if ( PKI_MSG_REQ_set_cacert  (ret, cacert   ) == PKI_ERR ) goto err;

	if ( template_name ) {
		/* Requested Profile Name */
		if(PKI_MSG_REQ_set_template (ret, template_name ) == PKI_ERR) 
			goto err;
	}

	if( signer ) {
		if( PKI_MSG_REQ_set_signer ( ret, signer, md ) == PKI_ERR )
			goto err;
	}

	/* Additional data to be encoded in the body (could be another msg) */
	ret->data = NULL;

	ret->recipients = NULL;

	/* The encoded message */
	ret->msg_data = NULL;

	return ( ret );

err:
	if( ret ) PKI_MSG_REQ_free ( ret );
	return ( NULL );
}

/*! \brief Sends a message and retrieves the response */

PKI_MSG_RESP * PKI_MSG_REQ_send (PKI_MSG_REQ *msg, 
					PKI_TOKEN *tk, char *url_s ) {

	PKI_STACK *sk = NULL;
	PKI_MSG_RESP *ret = NULL;

	char *srv_s = NULL;

	PKI_log_debug ("PKI_MSG_REQ_send()::Start.");

	if( !msg ) return ( NULL );

	switch ( msg->proto ) {
		case PKI_MSG_PROTO_SCEP:
			srv_s = "scepGateway";
			break;
		case PKI_MSG_PROTO_CMC:
			srv_s = "cmcGateway";
			break;
		case PKI_MSG_PROTO_XKMS:
			srv_s = "xkmsGateway";
			break;
		default:
			PKI_log_debug("MSG protocol not supported!");
			return ( NULL );
	}

	PKI_log_debug ("PKI_MSG_REQ_send()::srv_s = %s", srv_s );

	if( !url_s ) {
		sk = PKI_get_ca_service_sk ( msg->cacert, srv_s , NULL );
	} else {
		sk = PKI_STACK_new_null();
		PKI_STACK_push ( sk, strdup(url_s) );
	}

	if( PKI_STACK_elements(sk) < 1 ) {
		PKI_log_debug("ERROR, no %s available!", srv_s );
		PKI_STACK_free_all( sk );
	}

	/* In order to be able to send the certRequest we need to encrypt the
 	 * message for the recipient, therefore we need the RA certificate
 	 * (or CA) to encrypt the message with (2nd parameter of the
 	 * SCEP_MSG_new() */

	switch ( msg->proto ) {
		case PKI_MSG_PROTO_SCEP:
			ret = PKI_MSG_REQ_SCEP_send ( msg, sk, tk);
			break;
		case PKI_MSG_PROTO_CMC:
		case PKI_MSG_PROTO_XKMS:
		default:
			PKI_log_debug("MSG protocol not supported!");
			return ( NULL );
	}

	if ( sk ) PKI_STACK_free_all ( sk );

	return ( ret );

}

PKI_MSG_RESP *PKI_MSG_REQ_SCEP_send ( PKI_MSG_REQ *msg, 
					PKI_STACK *sk, PKI_TOKEN *tk ) {

	PKI_MEM *mem = NULL;
	PKI_MEM *resp_mem = NULL;

	PKI_MEM_STACK *mem_sk = NULL;
	PKI_X509_PKCS7 *p7 = NULL;

	PKI_MSG_RESP *ret = NULL;
	int cert_num = -1;

	char * url_s = NULL;
	int i = 0;

	char dest_url[1024];

	PKI_MEM *mem_url = NULL;

	PKI_log_debug ("PKI_MSG_REQ_SCEP_send()::Start");

	if( !msg || !sk ) return ( NULL );

	PKI_log_debug ("PKI_MSG_REQ_SCEP_send()::Addresses => %d", 
					PKI_STACK_elements ( sk ) );

	/* Grab the CA Chain */
	for( i = 0; i < PKI_STACK_elements( sk ); i++ ) {
		char cmd_url[2048];

		if ((url_s = PKI_STACK_get_num( sk, i )) == NULL)
			continue;

		snprintf( cmd_url, sizeof(cmd_url),
				"%s?operation=GetCACert&message=",
					url_s );

		PKI_log_debug("Sending GetCACert [%s]", cmd_url );

		if((mem_sk = URL_get_data ( cmd_url,  60, 
						64*1024, NULL)) == NULL ) {
			PKI_log_debug("Can not retrieve data from %s", cmd_url);
			continue;
		}

		if( PKI_STACK_MEM_elements ( mem_sk ) < 1 ) {
			PKI_log_debug("Returned elements %d from %s", 
				PKI_STACK_MEM_elements( mem_sk ), cmd_url);
			continue;
		}

		if((mem = PKI_STACK_MEM_pop ( mem_sk )) == NULL ) {
			PKI_log_debug("NULL content returned!");
			continue;
		}

		PKI_log_debug( "Got data (%d) from %s - Ok!", mem->size, 
							cmd_url );
		break;
	}

	if (!mem)
	{
		PKI_log_debug("ERROR::Can not retrieve CA/RA certs!");
		return NULL;
	}

	/* We want to add the RA certificate to the recipients
 	 * of the SCEP message */
	msg->recipients = NULL;

	p7 = PKI_X509_PKCS7_get_mem( mem, PKI_DATA_FORMAT_UNKNOWN, NULL);
	if (!p7)
	{
		PKI_log_debug("Can not load response (P7 with CA/RA "
			"certs!");
	}
	else
	{
		PKI_log_debug("Loaded P7 with CA/RA certs [OK]!");
	}

	if (mem_sk) PKI_STACK_MEM_free_all(mem_sk);

	// DEBUG
	// PKI_X509_PKCS7_put( p7, PKI_DATA_FORMAT_PEM, "ca-ra-p7.pem",
	//			NULL, NULL, NULL );

	if ((cert_num = PKI_X509_PKCS7_get_certs_num ( p7 )) <= 0 )
	{
		PKI_log_debug("No Certs in P7 with CA/RA Response!");
	}
	else
	{
		int j = 0;
		PKI_X509_CERT *x = NULL;

		for (j = 0; j < cert_num; j++)
		{
			if ((x = PKI_X509_PKCS7_get_cert ( p7, j )) == NULL)
				continue;
		
			if (PKI_MSG_REQ_add_recipient(msg, x) == PKI_ERR)
				PKI_log_debug("ERROR::Can not add recipients!");
		}
	}

	// Encode the message
	if (PKI_MSG_REQ_encode(msg, PKI_MSG_PROTO_SCEP) == PKI_ERR)
	{
		PKI_log_err ( "Can not encode message!");
		return ( NULL );
	}

	// TODO: Remove this debuggging info
	PKI_log_debug( "Creating MSG REQ message" );

	if ((mem = PKI_MSG_REQ_put_mem(msg, PKI_DATA_FORMAT_B64, 
						NULL, NULL, NULL )) == NULL)
	{
		PKI_log_debug( "Error in creating MSG REQ message" );
		return ( NULL );
	}
	
	// Strips \n \r from the B64 and encodes for safe URL
	if (PKI_MEM_encode(mem, PKI_DATA_FORMAT_URL, 1) != PKI_OK)
	{
		PKI_log_err ("Memory Error!");
		PKI_MEM_free ( mem );
		return ( NULL );
	}

	// TODO: Remove this debugging info
	PKI_log_debug( "Sending MSG REQ message" );

	// Build the URL for the GET
	mem_url = PKI_MEM_new_null();
	snprintf( dest_url, sizeof(dest_url), 
			"%s?operation=PKIOperation&message=", url_s );

	PKI_MEM_add(mem_url, dest_url, strlen(dest_url) );
	PKI_MEM_add(mem_url, (char *) mem->data, mem->size+1 );
	mem_url->data[mem_url->size-1] = '\x0';

	// Now we can free the mem buffer
	PKI_MEM_free(mem);
	mem = NULL; // Safety

	// Sends the GET request and retrieve the response
	if ((mem_sk = URL_get_data ( (char *) mem_url->data, 60, 
						64*1024, NULL )) != NULL)
	{
		resp_mem = PKI_STACK_MEM_pop ( mem_sk );
		PKI_STACK_MEM_free ( mem_sk );
	}

	// Free the URL data used for the GET request
	if( mem_url ) PKI_MEM_free ( mem_url );

	// If we have a response, let's parse it
	if (resp_mem)
	{
		PKI_X509_PKCS7 *p7 = NULL;

		if ((p7 = PKI_X509_PKCS7_get_mem ( resp_mem, 
							PKI_DATA_FORMAT_UNKNOWN, NULL )) == NULL) {
			PKI_log_debug("ERROR::Can not read response P7!");
			PKI_MEM_free ( resp_mem );
			return NULL;
		}

		// TODO: Remove this debug code
		// URL_put_data ("file://scep-resp.der", resp_mem, NULL, NULL, 0, 0, NULL);
		// PKI_X509_PKCS7_put ( p7, PKI_DATA_FORMAT_PEM, "scep-resp.pem",
		//	NULL, NULL, NULL );
		// PKI_X509_PKCS7_put ( p7, PKI_DATA_FORMAT_TXT, "scep-resp.txt",
		//	NULL, NULL, NULL );

	}
	else
	{
		PKI_log_debug( "ERROR::No Response received!" );
	}

	// Now we have to build the RESPONSE
	ret = PKI_MSG_RESP_new_null();

	// TODO: Finish building the response

	return ret;
}

/*! Returns a SCEP_MSG from the passed PKI_MSG_REQ */
int PKI_MSG_REQ_SCEP_new ( PKI_MSG_REQ *msg ) {

	PKI_X509_PKCS7 *ret = NULL;
	PKI_X509_REQ *req = NULL;

	if ( !msg ) return ( PKI_ERR );

	if( !msg->sign_key ) {
		PKI_log_debug("PKI_MSG_REQ_SCEP_new()::Missing Signing Key!"); 
		return ( PKI_ERR );
	}

	if( !msg->cacert ) {
		PKI_log_debug("PKI_MSG_REQ_SCEP_new()::Missing cacert!");
		return ( PKI_ERR );
	};

	if ( !msg->recipients ) {
		PKI_MSG_REQ_add_recipient ( msg, msg->cacert );
	}

	// if((ret = PKI_X509_new ( PKI_DATATYPE_SCEP_MSG, NULL )) == NULL ) {
	// 	return PKI_ERR;
	// }

	if ( msg->action == PKI_MSG_REQ_ACTION_CERTREQ )
	{
		PKI_X509_ATTRIBUTE *attr = NULL;
		char buf[64];

		if (!msg->sign_cert)
		{
			PKI_X509_PROFILE *prof = NULL;
			// PKI_CONFIG_ELEMENT *el = NULL;

			prof = PKI_X509_PROFILE_new("scep_req");
			// el = PKI_X509_PROFILE_add_child ( prof, "name", "scep" );
			// el = PKI_X509_PROFILE_add_child ( prof, "extensions", NULL );
	
			if (msg->template_name) 
			{
				PKI_X509_PROFILE_add_extension(prof, "certificateTemplate", msg->template_name, 
					"ASN1:BMPString", 0 );
			}

			if (msg->loa) 
			{
				PKI_X509_PROFILE_add_extension(prof, "loa", msg->loa, "ASN1:IA5String", 0 );
			}

			PKI_X509_PROFILE_put_file ( prof, "scep-pkcsreq-prof.xml");

			if((req = PKI_X509_REQ_new( msg->sign_key, msg->subject, prof, 
				NULL, NULL, NULL )) == NULL )
			{
				PKI_log_err( "Can not generate a new PKCS#10 request");
				return PKI_ERR;
			}

			PKI_X509_PROFILE_free ( prof );
		}

		if (msg->template_name)
		{
			if ((attr = PKI_X509_ATTRIBUTE_new_name("certificateTemplate", 
				PKI_STRING_PRINTABLE, msg->template_name, strlen(msg->template_name))) != NULL)
			{
				PKI_X509_REQ_add_attribute ( req, attr );
			}
		}

		snprintf( buf, sizeof(buf) - 1, "%s", msg->loa );

		if ((attr = PKI_X509_ATTRIBUTE_new_name( "loa", PKI_STRING_PRINTABLE, 
			buf, strlen(buf))) != NULL )
		{
			PKI_X509_REQ_add_attribute ( req, attr );
		}

		ret = PKI_X509_SCEP_MSG_new_certreq ( msg->sign_key,
			req, msg->sign_cert, msg->recipients, msg->sign_md );

		// DEBUG
		// PKI_X509_REQ_put ( req, PKI_DATA_FORMAT_PEM,
		// 		"scep-pkcsreq.pem", NULL, NULL, NULL );

		if (req) PKI_X509_REQ_free(req);

	}
	else
	{
		PKI_log_debug ( "MSG Action not supported by SCEP (%d)", msg->action );
		return PKI_ERR;
	}

	if (!ret || !ret->value)
	{
		PKI_log_debug("ERROR::Message generation failed!");
		if (ret) PKI_X509_free(ret);
		return PKI_ERR;
	}

	// DEBUG
	// PKI_X509_put ( ret, PKI_DATA_FORMAT_TXT, "scep-req.txt", NULL, NULL, NULL );
	// PKI_X509_put ( ret, PKI_DATA_FORMAT_PEM, "scep-req.pem", NULL, NULL, NULL );
	
	// Sets the message data
	msg->msg_data = ret;

	return PKI_OK;
}
