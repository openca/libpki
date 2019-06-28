#include <libpki/pki.h>

void usage( void ) {
	printf("\nURL Tool - v1.0\n");
	printf("(c) 2007-2015 by Massimiliano Pala and OpenCA Labs\n");
	printf("OpenCA Licensed software\n");

	printf("\n  USAGE: url-tool [options] <URL>\n");

	printf("\nWhere options are:\n");
	printf("  -out <uri>           output target uri\n");
	printf("  -timeout <secs>      connection timeout (def. 0)\n");
	printf("  -trusted <file>      trusted certificates file\n");
	printf("  -no_selfsigned       don't allow self-signed certs\n");
	printf("  -dumpcert <file>     save server cert in <file>\n");
	printf("  -dumpchain <file>    save cert chain in <file>\n");
	printf("  -no_verify           do not verify cert chain\n");
	printf("  -debug               enables debugging info\n");
	printf("\n");

	return;
}

int main (int argc, char *argv[]) {

	PKI_MEM_STACK *sk = NULL;
	PKI_MEM *obj = NULL;
	PKI_SSL *ssl = NULL;
	// PKI_TOKEN *tk = NULL;
	PKI_SOCKET *sock = NULL;

	URL * url = NULL;

	char *url_s = NULL;
	char *outurl_s = "fd://1";
	char *trusted_certs = NULL;
	char *dump_cert = NULL;
	char *dump_chain = NULL;

	int debug = 0;
	int verify_chain = 1;
	int i = 0;
	int timeout = 0;
	int get_via_socket = 0;

	PKI_init_all();

	if( !argv[1] ) {
		usage();
		return(1);
	}

	for( i = 1; i <= argc; i++ ) {
		if( strcmp_nocase( argv[i], "-out" ) == 0 ) {
			outurl_s = argv[++i];
		} else if ( strcmp_nocase ( argv[i], "-trusted" ) == 0 ) {
			trusted_certs = argv[++i];
		} else if ( strcmp_nocase ( argv[i], "-dumpcert" ) == 0 ) {
			if((dump_cert = argv[++i]) == NULL ) {
				fprintf(stderr, "\nERROR: -dumpcert needs a file url!\n\n");
				exit(1);
			}
		} else if ( strcmp_nocase ( argv[i], "-dumpchain" ) == 0 ) {
			if((dump_chain = argv[++i]) == NULL ) {
				fprintf(stderr, "\nERROR: -dumpchain needs a file url!\n\n");
				exit(1);
			}
		} else if ( strcmp_nocase ( argv[i], "-timeout" ) == 0 ) {
			timeout = atoi( argv[++i] );
			if ( timeout < 0 ) timeout = 0;
		} else if ( strcmp_nocase ( argv[i], "-no_verify" ) == 0 ) {
			verify_chain = 0;
		} else if ( strcmp_nocase( argv[i], "-debug" ) == 0 ) {
			debug = 1;
		} else {
			url_s = argv[i];
			if ( i < argc - 1 ) {
				fprintf( stderr, "Args after URL ignored!(%s %d/%d)\n",
					url_s, i, argc );
			}
			break;
		}
	}

	if((url = URL_new( url_s )) == NULL ) {
		printf("\nERROR, %s is not a valid URL!\n\n", url_s );

		usage();
		return (1);
	}

	if( debug ) {
		if(( PKI_log_init (PKI_LOG_TYPE_STDERR, PKI_LOG_INFO, NULL,
        	              PKI_LOG_FLAGS_ENABLE_DEBUG, NULL )) == PKI_ERR) {
        	        exit(1);
        	}
	} else {
		if(( PKI_log_init (PKI_LOG_TYPE_STDERR, PKI_LOG_INFO, NULL,
        	              0, NULL )) == PKI_ERR) {
        	        exit(1);
        	}
	}

	// Check if we should use the socket approach or the simple URL
	// retrieval facility
	switch (url->proto) {
		case URI_PROTO_FD:
		case URI_PROTO_FILE:
		case URI_PROTO_HTTP:
		case URI_PROTO_HTTPS:
		case URI_PROTO_LDAP:
			get_via_socket = 1;
			break;
		default:
			get_via_socket = 0;
	}

	//
	// -------------------------- Setup the SSL Options ------------------------
	//
	if ((ssl = PKI_SSL_new(NULL)) == 0) {
		fprintf(stderr, "ERROR: Memory allocation error (PKI_SSL_new)\n");
		return ( 1 );
	}

	if ( trusted_certs ) {

		PKI_X509_CERT_STACK *sk = NULL;

		if ((sk = PKI_X509_CERT_STACK_get(trusted_certs, PKI_DATA_FORMAT_UNKNOWN,
																NULL, NULL)) == 0) {
			fprintf(stderr, "Can't load Trusted Certs from %s", trusted_certs);
			return 1;
		}		

		if (PKI_SSL_set_trusted(ssl, sk) != PKI_OK) {
			PKI_log_err("Can not set the stack of trusted certificates from %s",
	      trusted_certs);
			return 1;
		}

		PKI_log_debug("Added %d certificates to the trusted list (from %s)\n",
			PKI_STACK_X509_CERT_elements(sk), trusted_certs);
	}

	if (verify_chain != 0) {
		PKI_SSL_set_verify(ssl, PKI_SSL_VERIFY_PEER_REQUIRE);
	} else {
		PKI_SSL_set_verify(ssl, PKI_SSL_VERIFY_NONE );
		PKI_log_debug("WARNING: no verify set!");
	}

	if ((sock = PKI_SOCKET_new()) == 0) {
		fprintf(stderr, "ERROR, can not create a new Socket!\n\n");
		return 1;
	}

	if (PKI_SOCKET_set_ssl(sock, ssl) != PKI_OK) {
		fprintf(stderr, "ERROR, can not set the socket for SSL/TLS!\n\n");
		return 1;
	}

	//
	// ------------------------------ Retrieve Data -----------------------------
	//
	if (get_via_socket) {

		if( PKI_SOCKET_open( sock, url_s, timeout ) == PKI_ERR ) {
			fprintf(stderr, "ERROR, can not connect to %s!\n\n", url_s);
			exit(1);
		}

		ssl = PKI_SOCKET_get_ssl (sock);

		if (dump_cert) { 
			PKI_X509_CERT *x = NULL;

			if ( !ssl ) {
				fprintf( stderr, 
					"ERROR: Can not dump cert (no SSL)\n");
			}

			if((x = PKI_SSL_get_peer_cert ( ssl )) == NULL ) {
				fprintf( stderr,
					"ERROR: No Peer certificate is available\n");
			}

			if( PKI_X509_CERT_put ( x, PKI_DATA_FORMAT_PEM,
					dump_cert, NULL, NULL, NULL ) == PKI_ERR){
				fprintf(stderr, "ERROR: can not write Peer cert to "
					"%s\n", dump_cert );
			}
		}

		if (dump_chain) { 
			PKI_X509_CERT_STACK *x_sk = NULL;
	
			if ( !ssl ) {
				fprintf( stderr, 
					"ERROR: Can not dump cert (no SSL)\n");
			}

			if ((x_sk = PKI_SSL_get_peer_chain(ssl)) == NULL ) {
				fprintf( stderr,
					"ERROR: No certificate chain is available\n");
			}

			if (PKI_X509_CERT_STACK_put(x_sk, 
	                                PKI_DATA_FORMAT_PEM,
					                        dump_chain,
	                                NULL, NULL, NULL ) != PKI_OK) {
				fprintf(stderr, "ERROR: can not write Peer cert to "
					"%s\n", dump_cert );
			}
		}

		if ((sk = URL_get_data_socket(sock, timeout, 0)) == 0) {
			fprintf(stderr, "ERROR, can not retrieve data!\n\n");
			return(-1);
		}

		PKI_SOCKET_close ( sock );
		PKI_SOCKET_free ( sock );
	}
	else // Get Data via the usual URL socket-less approach
	{
		sk = URL_get_data_url(url, timeout, 0, ssl);
	}

	PKI_log_debug("URL: Number of retrieved entries is %d",
		PKI_STACK_MEM_elements(sk));

	while( (obj = PKI_STACK_MEM_pop ( sk )) != NULL ) {
		URL_put_data ( outurl_s, obj, NULL, NULL, 0, 0, NULL );
	}

	return 0;
}
