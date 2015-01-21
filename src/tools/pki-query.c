#include <libpki/pki.h>

#define BOLD     "\x1B[1m"
#define NORM     "\x1B[0m"
#define BLACK    "\x1B[30m"
#define RED      "\x1B[31m"
#define GREEN    "\x1B[32m"
#define BLUE     "\x1B[34m"

#define BG       "\x1B[47m"
#define BG_BOLD  "\x1B[31;47m"
#define BG_NORM  "\x1B[30;47m"
#define BG_RED   "\x1B[31;47m"
#define BG_GREEN "\x1B[32;47m"
#define BG_BLUE  "\x1B[34;47m"

char banner[] = 
	"\n   " BOLD "PKI Resource Query Tool " NORM "(PRQP Client)\n"
	"   (c) 2008-2015 by " BOLD "Massimiliano Pala" NORM
			" and " BOLD "Open" RED "CA" NORM BOLD " Labs\n" NORM
	"       " BOLD BLUE "Open" RED "CA" NORM " Licensed software\n\n";

char usage_str[] =
	"     " BG "                                                          " NORM "\n"
	"     " BG_BOLD "  USAGE: " BG_NORM "pki-query "
		BG_GREEN "[options] " BG_BLUE "[-service <id> ...]          " NORM "\n"
	"     " BG "                                                          " NORM "\n\n";

void usage ( void ) {

	printf( "%s", banner );
	printf( "%s", usage_str );

	printf("   Where options are:\n");
	printf(BLUE "    -new " NORM "................: Generate a new PRQP request\n");
	printf(BLUE "    -in " RED "<URI> " NORM "...........: Loads the PRQP request from <URI>\n");
	printf(BLUE "    -out " RED "<URI> " NORM "..........: Output is sent to <URI>\n");
	/*
	   printf(" -casubject <dn>      - Issuer's of the CA certificate DN (optional if certfile\n");
	   printf("                        or cacertfile is provided)\n");
	   printf(" -serial <num>        - Serial Number of the CA certificate (optional)\n");
	   */
	printf(BLUE "    -cacert " RED "<file> " NORM "......:"
			" CA certificate\n");
	/*
	   printf(" -cacertissuer <file> - CA certificate to find serviced of (optional)\n");
	   printf(" -clientcert <file>   - A certificate issued by the CA you are requesting\n");
	   printf("                        information for\n");
	   */
	printf( BLUE "    -service " RED "id[:ver] " NORM "...:"
			" Service which URL is to be asked\n");
	printf( BLUE "    -uri " RED "<URI>" NORM "...........:"
			" URI of the PRQP server (http://...)\n");
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
	printf( BLUE "    -help-services" NORM " ......:"
			" Detailed services info\n");
	printf( BLUE "    -verbose" NORM " ............:"
			" Be verbose during operations\n");
	printf( BLUE "    -debug" NORM " ..............:"
			" Print debug information\n");
	printf("\n");

	exit (1);
}

void help ( void ) {
	// int c = 0;

	printf("\n");
	printf( "%s", banner );

	printf(
			"    This tool uses the " BOLD "PKI Resource Query Protocol (PRQP)" NORM " to query a\n"
			"    " BLUE "Resource Query Authority (RQA)" NORM " server about the services provided\n"
			"    by a Certification Authority.\n\n"
			"    If no " BOLD "'-service'" NORM " is specified, the response will include " BLUE "all the\n"
			"    provided services" NORM " by the specified CA. If the " BOLD "'-service <id>'" NORM " switch\n"
			"    is used, " BLUE "only the requested service URL" NORM " is reported. Notice that is\n"
			"    possible to specify multiple services by using multiple instances of\n"
			"    the " BOLD "-service <id>" NORM " switch in the same command.\n\n"
			"    For a " BOLD "list of supported service identifiers" NORM " use:\n\n"
			"           " BG_NORM "                                                             " NORM "\n"
			"           " BG_NORM "  $ pki-tool " BG_RED "-help-services                                  " NORM "\n"
			"           " BG_NORM "                                                             " NORM "\n\n" );

	printf("\n" BOLD "------ Press Enter to Continue ------" );
	getchar();
	printf("\n");

	printf(
			BOLD "    Examples:\n\n" NORM
			BOLD "    1. " NORM "Requesting the location of (a) the OCSP server, (b) the CA's cert\n"
			"       issuer (c) the certificate policy:\n\n");

	printf(
			"           " BG_NORM "                                                             " NORM "\n"
			"           " BG_NORM "  $ pki-query -cacert ca.pem -service ocspServer \\           " NORM "\n"
			"           " BG_NORM "             -service issuerCert -service certPolicy\\        " NORM "\n"
			"           " BG_NORM "                    -uri http://prqp.openca.org:830           " NORM "\n"
			"           " BG_NORM "                                                             " NORM "\n\n"
			BOLD "    2. " NORM "Requesting the location of all the services provided by a CA:\n\n"

			"           " BG_NORM "                                                             " NORM "\n"
			"           " BG_NORM "  $ pki-query -cacert ca.pem -uri http://server.org:830      " NORM "\n"
			"           " BG_NORM "                                                             " NORM "\n\n"

			BOLD RED"    NOTICE: " NORM "If no server is provided, the tool will " BOLD "try to use the default\n"
			"            server" NORM " at http://prqp." BLUE "open" RED "ca" NORM ".org:830.\n\n"
	      );

	exit (1);
}

void help_services ( void ) {

	// int c = 0;

	printf( "%s", banner );
	printf( "%s", usage_str );

	printf( "\nWhere service " RED "<id>" NORM " can be:\n\n" );
	printf(BOLD " * General Services\n" NORM);
	printf(BLUE "   rqa " NORM ".....................: PRQP server (Resource Query Authority)\n");
	printf(BLUE "   ocspServer " NORM "..............: OCSP Service\n");
	printf(BLUE "   timeStamping " NORM "............: TimeStamping Service\n");
	printf(BLUE "   scvp " NORM "....................: SCVP Service\n");
	printf(BLUE "   dvcs " NORM "....................: DVCS Service\n");

	printf(BOLD "\n * PKI Service Gateways:\n" NORM);
	printf(BLUE "   cmcGateway" NORM " ..............: CMC Gateway\n");
	printf(BLUE "   scepGateway" NORM " .............: SCEP Gateway\n");
	printf(BLUE "   xkmsGateway" NORM " .............: XKMS Gateway\n");

	printf("\n" BOLD "------ Press Enter to Continue ------" );
	getchar();
	printf("\n");

	printf(BOLD "\n * Repositories Location:\n" NORM);
	printf(BLUE "   issuerCert" NORM " ..............: Issuer's Certificate Retieval URI\n");
	printf(BLUE "   caRepository" NORM " ............: CA Certificate Repository\n");
	printf(BLUE "   caIssuers" NORM " ...............: CA Information\n");
	printf(BLUE "   crossCertRepository" NORM " .....: Cross Certificate Repository URI\n");
	printf(BLUE "   httpCertRepository" NORM " ......: HTTP Certificate Repository\n");
	printf(BLUE "   httpCrlRepository" NORM " .......: HTTP CRL Repository\n");
	printf(BLUE "   crlRepository" NORM " ...........: Other CRL Repository\n");
	printf(BLUE "   deltaCrl" NORM " ................: Delta CRL Base Address\n");
	printf(BLUE "   endorsedTA" NORM " ..............: List of Endorsed Trust Anchors (TA)\n");
	printf(BLUE "   apexTampUpdate" NORM " ..........: URI for the Apex Update Message (TAMP)\n");
	printf(BLUE "   tampUpdate" NORM " ..............: URI for the Update Message (TAMP)\n");

	printf(BOLD "\n * Policy Pointers:\n" NORM);
	printf(BLUE "   certPolicy" NORM " ..............: Certificate Policy (CP)\n");
	printf(BLUE "   certPracticesStatement" NORM " ..: Certificate CPS\n");
	printf(BLUE "   certLOAPolicy" NORM " ...........: Certificate LOA Policy\n");
	printf(BLUE "   certLOALevel" NORM " ............: Certificate LOA Modifier\n");

	printf("\n\n" BOLD "------ Press Enter to Continue ------" );
	getchar();
	printf("\n");

	printf(BOLD "\n * HTML (Browsers) Services:\n" NORM );
	printf(BLUE "   htmlRequest" NORM " .............: Certificate Request via HTML\n");
	printf(BLUE "   htmlRevoke" NORM " ..............: Certificate Revocation via HTML\n");
	printf(BLUE "   htmlRenew" NORM " ...............: Certificate Renewal via HTML\n");
	printf(BLUE "   htmlSuspend" NORM " .............: Certificate Suspension via HTML\n");

	printf(BOLD "\n * Grid Service Location:\n" NORM);
	printf(BLUE "   gridAccreditationBody" NORM " ...: n/a \n");
	printf(BLUE "   gridAccreditationPolicy" NORM " .: n/a\n");
	printf(BLUE "   gridAccreditationStatus" NORM " .: n/a\n");
	printf(BLUE "   gridDistributionUpdate" NORM " ..: n/a \n");
	printf(BLUE "   gridAccreditedCACerts" NORM " ...: n/a \n");

	printf(BOLD "\n * PKI Basic Services Location:\n" NORM );
	printf(BLUE "   revokeCertificate" NORM " .......: Certificate Revocation Service\n");
	printf(BLUE "   requestCertificate" NORM " ......: Certificate Revocation Service\n");
	printf(BLUE "   suspendCertificate" NORM " ......: Certificate Suspension Service\n");

	printf("\n");

	exit(1);
}

int main (int argc, char *argv[] ) {
	PKI_X509_PRQP_REQ *p = NULL;
	PKI_X509_PRQP_RESP *r = NULL;
	URL *url = NULL;
	int i, error;

	PKI_STACK *sk_services = NULL;

	char *cacertfile = NULL;
	char *cacertissuerfile = NULL;
	char *clientcertfile = NULL;
	char *subject_s = NULL;
	char *serial_s = NULL;

	URL *in_url = NULL;
	// URL *out_url = NULL;
	// char *outform_s = NULL;

	int debug = 0;
	int verbose = 0;
	int log_debug = 0;
	int log_level = PKI_LOG_ERR;
	int new = 0;
	int text = 0;
	int nosend = 0;
	int noout = 0;
	int reqout = 0;
	// int respout = 0;

	PKI_init_all();
	sk_services = PKI_STACK_new_null();

	if( argc <= 1 ) {
		usage();
	}

	error = 0;
	for(i=1; i < argc; i++ ) {
		if( strcmp( argv[i], "-clientcert" ) == 0 ) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			clientcertfile=(argv[++i]);
		} else if ( strcmp ( argv[i], "-cacertissuer" ) == 0) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			cacertissuerfile=(argv[++i]);
		} else if ( strcmp ( argv[i], "-cacert" ) == 0) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			cacertfile=(argv[++i]);
		} else if ( strcmp ( argv[i], "-serial") == 0 ) {
			if( argv[i+1] == NULL ) {
				error = 1;
				break;
			}
			serial_s = argv[++i];
		} else if ( strcmp ( argv[i], "-casubject") == 0 ) {
			if( argv[i+1] == NULL ) {
				error = 1;
				break;
			}
			subject_s = argv[++i];
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
		} else if ( strcmp ( argv[i], "-service" ) == 0) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			PKI_STACK_push( sk_services, argv[i+1] );
			i++;

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
		} else if ( strcmp ( argv[i], "-help-services") == 0 ) {
			help_services();
		} else if ( strcmp ( argv[i], "-help") == 0 ) {
			help();
		} else if ( strcmp ( argv[i], "-new") == 0 ) {
			new=1;
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

	if( !cacertfile && !subject_s && !clientcertfile ) {
		fprintf(stderr, "%s", banner );
		fprintf(stderr, BOLD RED "    ERROR: " NORM "parameter \"" BLUE 
					"-cacert" NORM "\" is required!\n\n" );
		exit(1);
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
		printf("ERROR, can not initialize logging facility!\n\n");
                exit(1);
        }

	if( !in_url && !new ) {
		fprintf( stderr, "%s", banner );
		fprintf( stderr, RED BOLD "    ERROR:" NORM
				" one of " BLUE "-new" NORM " or " BLUE 
				"-in <URL> " NORM "option is required!\n\n" );
		exit(1);
	}
 
	if(verbose) fprintf( stderr, "%s", banner );

	if(verbose) {
		fprintf( stderr, BOLD "\n    Initialization:" NORM "\n");
		fprintf( stderr, 
			"    * Parameters parsed ......" GREEN " Ok" 
								NORM "\n\n");
	}

	if( verbose ) {
		fprintf(stderr, BOLD "    Generating PRQP request:" NORM "\n" );
	}
	if( new ) {
		if( verbose ) {
			fprintf( stderr, 
				 "    * Creating a " BOLD "new" " PRQP request .... " );
		}
		p = PKI_X509_PRQP_REQ_new_url ( cacertfile, cacertissuerfile, 
				clientcertfile, subject_s, serial_s, NULL );

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
		p = PKI_X509_PRQP_REQ_get_url( in_url, NULL, NULL );
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
			PKI_X509_PRQP_REQ_print ( p );
			//
			// PKI_X509_PRQP_REQ_put ( p, PKI_DATA_FORMAT_TXT,
			//	"fd://1", NULL, NULL, NULL );
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
		r = PKI_DISCOVER_get_resp_url( p, url );

		if( !r && !url ) {
			/* If not successful, let's try the default OpenCA
 			 * server */
			url = URL_new( "http://prqp.openca.org:830" );
			r = PKI_X509_PRQP_RESP_get_http ( url, p, 0 );
			// r_val = PRQP_http_get_resp ( url, p->value, 0 );
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
				PKI_X509_PRQP_RESP_print ( r );
			}

			// PKI_X509_PRQP_RESP_print_fp ( stdout, r );

			if( !noout ) {
				PKI_X509_PRQP_RESP_put ( r, PKI_DATA_FORMAT_PEM,
					"fd://1", NULL, NULL, NULL );
				// st = BIO_new_fp ( stdout, BIO_NOCLOSE );
				// PEM_write_bio_PRQP_RESP( st, r );
				// BIO_free_all( st );
			}
		}
	} else {
		PKI_X509_PRQP_REQ_put ( p, PKI_DATA_FORMAT_PEM,
			"fd://1", NULL, NULL, NULL );
	}

	PKI_X509_PRQP_REQ_free( p );

	return(0);

}


