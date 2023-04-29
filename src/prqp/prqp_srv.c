/* PKI Resource Query Protocol Message implementation
 * (c) 2006 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 *
 * This software is released under the GPL2 License included
 * in the archive. You can not remove this copyright notice.
 */
                                                                                
#include <libpki/pki.h>

/*!
 * \brief Retireve a PKI_STACK of addresses from a PRQP server.
 *
 * Retrieve informations about services provided by a CA from a PRQP server.
 * The function returns a stack of strings containing URLs of the requested
 * services. If no URL (char *) is passed, then the library will search for
 * the default config file /etc/pki.conf for the configured Resource Query
 * Authority (PRQP Server).
 *
 */

PKI_STACK * PKI_get_ca_resources(PKI_X509_CERT *caCert, 
			PKI_X509_CERT *caIssuerCert, PKI_X509_CERT *issuedCert,
			PKI_STACK *sk_services, char *url_s ) {

	PKI_X509_PRQP_REQ *p = NULL;
	PKI_X509_PRQP_RESP *r = NULL;
	PKI_STACK *addr_sk = NULL;

	p = PKI_X509_PRQP_REQ_new_certs_res ( caCert, caIssuerCert, 
						issuedCert, sk_services );

	if( !p ) {
		PKI_log_debug ("PKI_get_ca_resources()::Can not generate PRQP REQ");
		return NULL;
	}

	if((r = PKI_DISCOVER_get_resp ( p, url_s )) == NULL ) {
		PKI_log_debug("PKI_get_ca_resources()::No response retrieved!");
		PKI_X509_PRQP_REQ_free ( p );
		return NULL;
	}

	// PKI_PRQP_RESP_print( r->value );

	if((addr_sk = PKI_X509_PRQP_RESP_url_sk ( r )) == NULL ) {
		PKI_log_debug ("PKI_get_ca_responses()::No list of address is returned!");
	}

	if ( p ) PKI_X509_PRQP_REQ_free ( p );
	if ( r ) PKI_X509_PRQP_RESP_free ( r );

	return addr_sk;
}

/*!
 * \brief Retireve a stack of configured URL for a PKI service from a PRQP
 *        server
 *
 * Retrieve information about a specific service provided by a CA.
 * The function returns a PKI_STACK containing the URLs of the requested
 * service (if available). 
 *
 * If no URL (char *) is passed, then the library will search for
 * the default config file /etc/pki.conf for the configured Resource Query
 * Authority (PRQP Server).
 *
 */

PKI_STACK * PKI_get_ca_service_sk( PKI_X509_CERT *caCert, 
					char *srv, char *url_s ) {

	PKI_STACK *services = NULL;
	PKI_STACK *ret_sk = NULL;

	if( !srv || !caCert ) return ( NULL );

	if((services = PKI_STACK_new_null()) == NULL ) {
		PKI_log_debug("Stack creation error in %s:%d",
						__FILE__, __LINE__ );
		return ( NULL );
	}

	PKI_STACK_push( services, strdup( srv ));

	ret_sk = PKI_get_ca_resources( caCert, NULL, NULL, services, url_s );

	PKI_STACK_free_all( services );

	return ( ret_sk );
}

PKI_STACK * PKI_get_cert_service_sk( PKI_X509_CERT *cert, 
					char *srv, char *url_s ) {

	PKI_STACK *services = NULL;
	PKI_STACK *ret_sk = NULL;

	if( !srv || !cert ) return ( NULL );

	if((services = PKI_STACK_new_null()) == NULL ) {
		PKI_log_debug("Stack creation error");
		return ( NULL );
	}

	PKI_STACK_push( services, strdup( srv ));

	ret_sk = PKI_get_ca_resources( NULL, NULL, cert, services, url_s );

	PKI_STACK_free_all( services );

	return ( ret_sk );
}

/*!
 * \brief Retireve the first configured URL for a PKI service from a PRQP
 *        server
 *
 * Retrieve informations about a specific service provided by a CA.
 * The function returns a string containing the URL of the requested
 * service (if available). 
 *
 * If no URL (char *) is passed, then the library will search for
 * the default config file /etc/pki.conf for the configured Resource Query
 * Authority (PRQP Server).
 *
 */

char * PKI_get_ca_service( PKI_X509_CERT *caCert, char *srv, char *url_s ) {

	PKI_STACK *services = NULL;
	PKI_STACK *ret_sk = NULL;

	char *ret_s = NULL;

	if( !srv || !caCert ) return ( NULL );

	if((services = PKI_STACK_new_null()) == NULL ) {
		PKI_log_debug("Stack creation error in %s:%d",
						__FILE__, __LINE__ );
		return ( NULL );
	}

	PKI_log_debug ("Getting Address for %s", srv );

	PKI_STACK_push( services, strdup(srv) );
	ret_sk = PKI_get_ca_resources( caCert, NULL, NULL, services, url_s );

	PKI_STACK_free_all( services );

	if( !ret_sk ) {
		PKI_log_debug("No address returned for %s", srv );
		return ( NULL );
	} else {
		ret_s = PKI_STACK_pop( ret_sk );
		PKI_STACK_free_all( ret_sk );
	}

	PKI_log_debug ( "Returned address %s", ret_s );

	return ( ret_s );
}

/*!
 * \brief Retireve a PRQP response from the passed url or from one of the
 *        configured RQAs in /etc/pki.conf
 */

PKI_X509_PRQP_RESP * PKI_DISCOVER_get_resp ( PKI_X509_PRQP_REQ *p, char *url_s ) {

	URL *url = NULL;

	if( p == NULL ) return (NULL);

	if( url_s != NULL ) {
		if((url = URL_new( url_s )) == NULL) {
			return(NULL);
		}
	}

	return( PKI_DISCOVER_get_resp_url( p, url ));
}

/*!
 * \brief Retrieve a PRQP Response from a server.
 *
 * The function returns a PKI_X509_PRQP_RESP if succesful or NULL if an error occurs
 * when contacting the PRQP server.
 */

PKI_X509_PRQP_RESP * PKI_DISCOVER_get_resp_url ( PKI_X509_PRQP_REQ *p, URL *url ) {

	PKI_X509_PRQP_RESP * ret = NULL;

	char line[1024], name[1024], addr[1024];

        FILE *file;

	if( !p || !p->value ) {
		PKI_log_debug( "WARNING, no PRQP request when trying to get"
				" the response!");
		return ( NULL );
	}

	if( url ) {
		if (( ret = PKI_X509_PRQP_RESP_get_http ( url, p, 0)) != NULL ) {
			return ret;
		} else {
			return NULL;
		}
	}

        file = fopen( PKI_PRQP_LIB_CONF_FILE, "r");
        if( !file ) {
		PKI_log_debug( "WARNING, PRQP config file %s not found!",
			PKI_PRQP_LIB_CONF_FILE );
		return ( NULL );
        }

       	while(!feof(file)) {
               	if( fgets(line, sizeof(line), file) ) {
                       	if((memcmp(line, ";", 1) == 0) || 
					(memcmp(line, "#", 1) == 0))
                                		continue;

			if(sscanf(line, "%1023s %1023s", name, addr ) > 1 ) {
				char *full_url_s = NULL;
				size_t full_len = 0;

				if((strcmp_nocase( name, 
					PKI_PRQP_LIB_CONF_ENTRY_LONG)==0) ||
						(strcmp_nocase ( name, 
						   PKI_PRQP_LIB_CONF_ENTRY_SHORT ) 
									== 0)) {

					URL *l_url = NULL;

					full_len = sizeof( addr ) + 12;
					full_url_s = PKI_Malloc ( full_len );
					snprintf( full_url_s, full_len, "http://%s", addr );
					if ( strchr ( addr, ':') == NULL ) {
						strncat ( full_url_s, ":830", full_len );
					}

					PKI_log_debug( "Trying PRQP RQA -> %s",
								full_url_s );

					if((l_url = URL_new( full_url_s )) == NULL) {
						PKI_log_debug("Can not parse address %s",
							full_url_s );
						PKI_Free ( full_url_s );
						continue;
					}

					if( l_url->port <= 0 ) 
						l_url->port = PKI_PRQP_DEFAULT_PORT;

					l_url->proto = URI_PROTO_HTTP;
					ret = PKI_X509_PRQP_RESP_get_http ( l_url, p, 0);

					PKI_Free ( full_url_s );

					if( ret == NULL ) {
						PKI_log( PKI_LOG_ERR,
							"Can not get response "
							"from server (%s:%d)!",
								l_url->addr, 
								l_url->port);
						URL_free ( l_url );
					} else {
						/* Exit the cycle */
						PKI_log_debug("Got PRQP response from server");
						URL_free ( l_url );
        					fclose(file);
						return ret;
					}
				}
                	}
        	}
	}

        fclose(file);

	return ret;
}

