#include <libpki/pki.h>

#define BOLD     "\x1B[1m"
#define NORM     "\x1B[0m"
#define RED      "\x1B[31m"
#define GREEN    "\x1B[32m"
#define BLUE     "\x1B[34m"

#define BG       "\x1B[47m"
#define BG_BOLD  "\x1B[31;47m"
#define BG_NORM  "\x1B[30;47m"
#define BG_RED   "\x1B[31;47m"
#define BG_GREEN "\x1B[32;47m"
#define BG_BLUE  "\x1B[34;47m"

#define EE NORM "\r\n"

typedef enum {
	NEW_REQUEST = 1,
	GET_STATUS,
	GET_CERT
} REQ_CMDS;

char banner[] = 
	"\n   " BOLD "PKI Certificate Request Tool " EE
	"   (c) 2008-2009 by " BOLD "Massimiliano Pala" NORM
			" and " BOLD "Open" RED "CA" NORM BOLD " Labs" EE
	"       " BOLD BLUE "Open" RED "CA" NORM " Licensed software" EE "\n";

char usage_str[] =
	"     " BG "                                                          " EE 
	"     " BG_BOLD "  USAGE: " BG_NORM "pki-request "
		BG_GREEN "[new|status|import] " BG_BLUE "[options]        " EE
	"     " BG "                                                          " EE "\n";

void usage ( void ) {

	printf( "%s", banner );
	printf( "%s", usage_str );

	printf("   Where options are:\n");
	printf(BLUE "    -in " RED "<URI> " NORM "...........: URI for the PKCS#10 Request" EE );
	printf(BLUE "    -out " RED "<URI> " NORM "..........: Retrieved certificate out <URI>\n");
	printf(BLUE "    -cacert " RED "<file> " NORM "......:"
			" CA certificate (to request the cert from)\n");
	printf( BLUE "    -uri " RED "<URI>" NORM "...........:"
			" URI of the request service\n");
	printf( BLUE "    -proto " RED "<PROTO>" NORM ".......:"
			" Protocol to use (SCEP, EST, CMP)\n");
	printf( BLUE "    -nosend " NORM ".............:"
			" Don't send out the request to any server\n");
	printf( BLUE "    -reqout " NORM ".............:"
			" Prints ther request\n");
	// printf( BLUE "    -respout " NORM "............:"
	// 		" Prints the response\n");
	printf( BLUE "    -text " NORM "...............:"
			" Output in a human readable format\n");
	printf( BLUE "    -noout " NORM "..............:"
			" Do not output req/resp PEM format to stdout\n");
	printf( BLUE "    -help" NORM " ...............:"
			" Detailed usage info\n");
	printf( BLUE "    -verbose" NORM " ............:"
			" Be verbose during operations\n");
	printf( BLUE "    -debug" NORM " ..............:"
			" Print debug information\n");
	printf("\n");

	exit (1);
}

void help ( void ) {

	printf("\n");
	printf( "%s", banner );

	printf(
"   This tool receives a PKCS#10 request as input and sends it to a CA" EE
"   and retrieves the issued certificate." EE
EE
"   The pki-request tool is capable of using the message formats supported" EE
"   by libpki. Currently only SCEP is enabled." EE
EE
BOLD "    Examples:\n\n" NORM
BOLD "    1. " NORM "Requesting a certificate from a CA by using PRQP to" EE
     "       discover the SCEP gateway provided by the CA:" EE
EE
     "           " BG_NORM "                                                             " EE
     "           " BG_NORM "  $ pki-request send -cacert ca.pem      " EE
     "           " BG_NORM "                                                             " EE EE

BOLD RED"    NOTICE: " NORM "If no server is provided, the tool will " BOLD "try to use the default\n"
"            server" NORM " at http://prqp." BLUE "open" RED "ca" NORM ".org:830." EE EE
	);

	exit (1);
}

int main (int argc, char *argv[] ) {
	PKI_X509_PRQP_REQ *p = NULL;
	PKI_X509_PRQP_RESP *r = NULL;
	URL *url = NULL;
	int i, error;

	PKI_STACK *sk_services = NULL;

	char *cacertfile = NULL;
	// char *proto_s = NULL;

	URL *in_url = NULL;
	// URL *out_url = NULL;
	// char *outform_s = NULL;

	int debug = 0;
	int verbose = 0;
	int text = 0;
	int nosend = 0;
	int noout = 0;
	int reqout = 0;
	// int respout = 0;

	PKI_LOG_FLAGS log_debug = 0;
	int log_level = PKI_LOG_ERR;

	REQ_CMDS cmd = 0;

	PKI_init_all();
	sk_services = PKI_STACK_new_null();

	if( argc <= 2 ) {
		usage();
	}

	if( strcmp( argv[1], "new" ) == 0 ) {
		cmd = NEW_REQUEST;
	} else if ( strcmp( argv[1], "status" ) == 0 ) {
		cmd = GET_STATUS;
	} else if ( strcmp( argv[1], "get" ) == 0 ) {
		cmd = GET_CERT;
	} else {
		fprintf( stderr, "%s", banner );
		fprintf( stderr, BOLD RED "    ERROR: "
				NORM "Unreckognized command \'" BOLD BLUE
						"%s" NORM "\'\n\n",
				argv[1]);
		exit (1);
	}

	error = 0;
	for(i=2; i < argc; i++ ) {
		if ( strcmp ( argv[i], "-cacert" ) == 0) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			cacertfile=(argv[++i]);
		} else if ( strcmp ( argv[i], "-uri" ) == 0) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			if((url=getParsedUrl(argv[++i])) == NULL ) {
				fprintf(stderr, "%s", banner );
				fprintf(stderr, BOLD RED "    ERROR: " 
					NORM "url \"" BLUE "%s" NORM 
					"\" is not valid!\n\n", argv[i] );
				exit(1);
			};

		// } else if ( strcmp ( argv[i], "-out") == 0 ) {
		// 	if( argv[i+1] == NULL ) {
		// 		error=1;
		// 		break;
		// 	}
		// 	out_url=getParsedUrl(argv[++i]);
		
		} else if ( strcmp ( argv[i], "-in") == 0 ) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			in_url=getParsedUrl(argv[++i]);

		// } else if ( strcmp ( argv[i], "-outform") == 0 ) {
		// 	if( argv[i+1] == NULL ) {
		// 		error=1;
		// 		break;
		// 	}
		// 	outform_s=argv[++i];

		// } else if ( strcmp ( argv[i], "-proto") == 0 ) {
		// 	if( argv[i+1] == NULL ) {
		// 		error=1;
		// 		break;
		// 	}
		// 	proto_s=argv[++i];

		} else if ( strcmp ( argv[i], "-help") == 0 ) {
			help();
		} else if ( strcmp ( argv[i], "-reqout") == 0 ) {
			reqout=1;
		// } else if ( strcmp ( argv[i], "-respout") == 0 ) {
		// 	respout=1;
		} else if ( strcmp ( argv[i], "-text") == 0 ) {
			text=1;
		} else if ( strcmp ( argv[i], "-noout") == 0 ) {
			noout=1;
		} else if ( strcmp ( argv[i], "-nosend") == 0 ) {
			nosend=1;
		} else if ( strcmp ( argv[i], "-debug") == 0 ) {
			debug=1;
		} else if ( strcmp ( argv[i], "-verbose") == 0 ) {
			verbose=1;
		} else {
			fprintf( stderr, "%s", banner );
			fprintf( stderr, BOLD RED "    ERROR: "
				NORM "Unreckognized parameter \'" BOLD BLUE
						"%s" NORM "\'\n\n",
				argv[i]);
			exit (1);
		}
	}

	if( error == 1 ) {
		usage();
	}

	if( ( url ) && ( url->proto == URI_PROTO_FILE ) ) {
		fprintf(stderr, "%s", banner );
		fprintf(stderr, BOLD RED "    ERROR: " NORM "url \"" BLUE 
				"%s" NORM "\" is not valid!\n\n", url->url_s );
		exit(1);
	}

	if( verbose ) log_level = PKI_LOG_INFO;
	if( debug ) log_debug |= PKI_LOG_FLAGS_ENABLE_DEBUG;

	if(( PKI_log_init (PKI_LOG_TYPE_STDERR, log_level, NULL,
                        log_debug, NULL )) == PKI_ERR ) {
                exit(1);
        }

	if( !in_url ) {
		fprintf( stderr, "%s", banner );
		fprintf( stderr, RED BOLD "    ERROR:" NORM
			BLUE "-in <URL> " NORM "option is required!\n\n" );
		exit(1);
	}
 
	if(verbose) fprintf( stderr, "%s", banner );

	/*
	if(verbose) {
		fprintf( stderr, BOLD "\n    Initialization:" NORM "\n");
		fprintf( stderr, 
			"    * Parameters parsed ......" GREEN " Ok" 
								NORM "\n\n");
		fprintf(stderr, BOLD "    Generating PRQP request:" NORM "\n" );
	}
	*/

	if( cmd == NEW_REQUEST ) {
		if( verbose ) {
			fprintf( stderr, 
				 "    * Creating a " BOLD "new" NORM " PRQP request .... " );
		}
		p = PKI_X509_PRQP_REQ_new_url ( cacertfile, NULL, 
				NULL, NULL, NULL, NULL );

		if(!p ) {
			if ( verbose ) {
				fprintf( stderr, RED "ERROR!" NORM "\n\n");
			} else {
				fprintf( stderr, RED BOLD "    ERROR:" NORM
					" Can not generate PRQP request!\n\n");
			}
			exit(1);
		}
		if( verbose ) fprintf( stderr, GREEN "Ok" NORM "\n");

		for( i = 0; i < PKI_STACK_elements(sk_services); i++ ) {
			char *ss = NULL;
	
			ss = PKI_STACK_get_num( sk_services, i);
			if( verbose ) fprintf( stderr, 
				"    * Adding service " BOLD "%s" 
					NORM " to request ..... ", ss );
			if(PKI_X509_PRQP_REQ_add_service( p, ss ) == PKI_ERR ) {
				if( verbose ) fprintf( stderr, RED "ERROR!"
							NORM "\n");
				fprintf( stderr, "%s", banner );
				fprintf( stderr, BOLD RED "    ERROR: " 
					NORM "Unknown requested service name \'" 
					BLUE "%s" NORM "\'\n\n", ss);

				fprintf( stderr, "    Please Use " BLUE 
					"-help-services " NORM "for a list of"
					" valid service names\n\n");
				// help_services();
				exit(1);
			}
			if( verbose ) fprintf( stderr, GREEN "Ok" NORM "\n");
		}
	} else if ( in_url ) {
		if( verbose ) {
			fprintf( stderr, "    * Loading PRQP request ..... " );
		}
		p = PKI_X509_PRQP_REQ_get_url( in_url, PKI_DATA_FORMAT_UNKNOWN, NULL, NULL );
		if( !p ) {
			if ( verbose ) fprintf( stderr, RED "ERROR!" NORM "\n");
			fprintf( stderr, "%s", banner );
			fprintf( stderr, BOLD RED "    ERROR: " NORM 
					"Can not load PRQP request from \'" 
					BOLD BLUE "%s" NORM "\'\n\n", 
						in_url->url_s );
			exit(1);
		}
		if( verbose ) fprintf( stderr, GREEN "Ok" NORM "\n");
	}

	if( p && reqout ) {
		if ( text ) {
			PKI_X509_PRQP_REQ_print ( p->value );
			// PKI_X509_PRQP_REQ_put ( p, PKI_DATA_FORMAT_TXT, 
			// 		"fd://1", NULL, NULL, NULL );
		}

		if( !noout ) {
			PKI_X509_PRQP_REQ_put ( p, PKI_DATA_FORMAT_PEM, 
						"fd://1", NULL, NULL, NULL );
		}
	}

	if ( !nosend ) {

		if( verbose ) {
			fprintf( stderr, BOLD "\n    Contacting PRQP server:" 
				NORM "\n");
			if( url ) {
				fprintf( stderr, 
					"    * [" BLUE 
					"%s" NORM "] ..... ", url->url_s );
			} else {
				fprintf( stderr, 
					"    * [" BLUE "default server"
					NORM "] ..... " );
			}
		}

		/* Try the default request - uses the /etc/pki.conf file
 		 * to retrieve the list of PRQP servers passed via DHCP
 		 */
		r = PKI_DISCOVER_get_resp_url ( p, url );

		if( !r && !url ) {
			/* If not successful, let's try the default OpenCA
 			 * server */
			url = URL_new( "http://prqp.openca.org:830" );
			r = PKI_X509_PRQP_RESP_get_http ( url, p, 0 );
		}

		if( !r ) {
			if(!verbose) fprintf(stderr, "    ");

			fprintf( stderr, 
				BOLD RED "ERROR:" 
				NORM " Can not read the response!\n\n");
		} else {
			// BIO *st = NULL;

			if( verbose ) fprintf( stderr, GREEN "Ok" NORM "\n\n");

			if( text ) {
				PKI_X509_PRQP_RESP_print ( r->value );
				// PKI_X509_PRQP_RESP_put ( r, PKI_DATA_FORMAT_TXT,
				// 	"fd://1", NULL, NULL, NULL );

				// PKI_X509_PRQP_RESP_print ( r );
			}

			// PKI_X509_PRQP_RESP_print_fp ( stdout, r );

			if( !noout ) {
				PKI_X509_PRQP_RESP_put ( r, PKI_DATA_FORMAT_PEM,
					"fd://1", NULL, NULL, NULL );
			}
		}
	} else {
		PKI_X509_PRQP_REQ_put ( r, PKI_DATA_FORMAT_PEM,
			"fd://1", NULL, NULL, NULL );
	}

	PKI_X509_PRQP_REQ_free( p );

	return(0);

}


