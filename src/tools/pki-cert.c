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
	"\n   " BOLD "PKI Certificate Display Tool " NORM "(pki-cert)\n"
	"   (c) 2008-2015 by " BOLD "Massimiliano Pala" NORM
			" and " BOLD "Open" RED "CA" NORM BOLD " Labs\n" NORM
	"       " BOLD BLUE "Open" RED "CA" NORM " Licensed software\n\n";

char usage_str[] =
	"     " BG "                                                " NORM "\n"
	"     " BG_BOLD "  USAGE: " BG_NORM "pki-cert "
		BG_GREEN "[options]                     " NORM "\n"
	"     " BG "                                                " NORM "\n\n";

void usage ( void ) {

	printf( "%s", banner );
	printf( "%s", usage_str );

	printf("   Where options are:\n");
	printf(BLUE "    -in " RED "<URI> " NORM "...........: Loads the certificate from <URI>\n");
	printf(BLUE "    -out " RED "<URI> " NORM "..........: Output is sent to <URI>\n");
	// printf(BLUE "    -token " RED "<URI>" NORM ".........: URI of the Token to load\n");
	printf(BLUE "    -outform " RED "<opt>" NORM ".......: Output format (PEM, DER, TXT, XML)\n");
	printf(BLUE "    -verbose"        NORM " ............: Be verbose during operations\n");
	printf(BLUE "    -verify " RED  NORM "...............: Verify Certificate's Signature\n");
	printf(BLUE "    -verifyChain " RED  NORM "..........: Verify Certificate's Chain\n");
	printf(BLUE "    -CACert " RED "<URI>" NORM "........: Issuer's Certificate (Required for verify)\n");
	printf(BLUE "    -debug"        NORM " ..............: Print debug information\n");
	printf(BLUE "    -help"        NORM " ...............: Print this message\n");
	printf("\n");

	exit (1);
}

int main (int argc, char *argv[] ) {
	PKI_X509_CERT *cert = NULL;
	PKI_X509_CERT *caCert = NULL;
	// PKI_TOKEN *tk = NULL;
	URL *inUrl = NULL;
	URL *outUrl = NULL;
	int i, error;

	int debug = 0;
	int verbose = 0;

	PKI_LOG_FLAGS log_debug = 0;
	int log_level = PKI_LOG_ERR;

	PKI_DATA_FORMAT outform = PKI_DATA_FORMAT_UNKNOWN;

	// char *token = NULL;
	char *infile = NULL;
	char *outfile = "stdout";
	char *outform_s = NULL;
	char *cacert_s = NULL;

	int verify = 0;
	int verify_chain = 0;

	PKI_init_all();

	error = 0;
	for(i=1; i < argc; i++ ) {
		if( strncmp_nocase( argv[i], "-in", 3 ) == 0 ) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			infile=(argv[++i]);

		// } else if ( strncmp_nocase ( argv[i], "-token", 6 ) == 0) {
		// 	if( argv[i+1] == NULL ) {
		// 		error=1;
		// 		break;
		// 	}
		// 	token=(argv[++i]);

		} else if(strncmp_nocase( argv[i], "-outform", 8) == 0 ) {
			if( argv[i+1] == NULL ) {
				error = 1;
				break;
			}
			outform_s=(argv[++i]);
		} else if ( strncmp_nocase ( argv[i], "-out", 4 ) == 0) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			outfile=(argv[++i]);
		} else if ( strcmp ( argv[i], "-outform") == 0 ) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			outform_s=argv[++i];
		} else if ( strncmp_nocase ( argv[i], "-CACert", 7 ) == 0) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			cacert_s=(argv[++i]);
		} else if(strncmp_nocase(argv[i], "-h", 2) == 0 ) {
			usage();
		} else if(strncmp_nocase(argv[i],"-verify", 7) == 0 ) {
			verify=1;
		} else if(strncmp_nocase(argv[i],"-verifyChain", 11) == 0 ) {
			verify_chain=1;
		} else if(strncmp_nocase(argv[i],"-debug", 6) == 0 ) {
			debug=1;
		} else if(strncmp_nocase(argv[i],"-verbose", 8) == 0 ) {
			verbose=1;
		} else {
			if(verbose) fprintf(stderr, "%s", banner );
			fprintf( stderr, BOLD RED "\n    ERROR: "
				NORM "Unreckognized parameter \'" BOLD BLUE
						"%s" NORM "\'\n\n",
				argv[i]);
			exit(1);
		}
	}

	if((outUrl=getParsedUrl(outfile)) == NULL ) {
		if(verbose) fprintf(stderr, "%s", banner );
		fprintf(stderr, BOLD RED "\n    ERROR: " 
			NORM "url \"" BLUE "%s" NORM 
			"\" is not valid!\n\n", outfile );
		exit(1);
	};

	if((inUrl=getParsedUrl(infile)) == NULL ) {
		if(verbose) fprintf(stderr, "%s", banner );
		fprintf(stderr, BOLD RED "\n    ERROR: " 
			NORM "url \"" BLUE "%s" NORM 
			"\" is not valid!\n\n", infile );
		exit(1);
	};

	if(outform_s) {
		if(strncmp_nocase(outform_s, "PEM", 3) == 0 ) {
			outform = PKI_DATA_FORMAT_PEM;
		} else if (strncmp_nocase(outform_s, "DER", 3) == 0 ) {
			outform = PKI_DATA_FORMAT_ASN1;
		} else if (strncmp_nocase(outform_s, "TXT", 3) == 0 ) {
			outform = PKI_DATA_FORMAT_TXT;
		} else if (strncmp_nocase(outform_s, "XML", 3) == 0 ) {
			outform = PKI_DATA_FORMAT_XML;
		} else if (strncmp_nocase(outform_s, "B64", 3) == 0 ) {
			outform = PKI_DATA_FORMAT_B64;
		} else if (strncmp_nocase(outform_s, "URL", 3) == 0 ) {
			outform = PKI_DATA_FORMAT_URL;
		} else {
			fprintf(stderr, "%s", banner );
			fprintf(stderr, BOLD RED "\n    ERROR: " 
				NORM "output format \"" BLUE "%s" NORM 
				"\" is not valid (use one of PEM, DER, TXT, XML)!\n\n", outform_s );
			exit(1);
		};	
	};

	if( verify ) {
		if ( !cacert_s ) {
			fprintf( stderr, BOLD RED "\n    ERROR," NORM " -CACert <URI> required"
				" for verify option!\n\n");
			exit(1);
		};

		if(( caCert = PKI_X509_CERT_get ( cacert_s, NULL, NULL)) == NULL ) {
			fprintf( stderr, BOLD RED "    ERROR, can not load CACert from %s\n\n",
				cacert_s );
			exit ( 1 );
		};
	};

	if( error == 1 ) {
		usage();
	}

	if( verbose ) log_level = PKI_LOG_INFO;
	if( debug ) log_debug |= PKI_LOG_FLAGS_ENABLE_DEBUG;

	if(( PKI_log_init (PKI_LOG_TYPE_STDERR, log_level, NULL,
                        log_debug, NULL )) == PKI_ERR ) {
		printf("ERROR, can not initialize logging facility!\n\n");
		exit(1);
	}

	if(verbose) fprintf( stderr, "%s", banner );

	if(verbose) {
		fprintf( stderr, BOLD "\n    Initialization:" NORM "\n");
		fprintf( stderr, 
			"    * Parameters parsed ......" GREEN " Ok" 
								NORM "\n");
		fprintf( stderr, 
			"    * Loading Certificate ...." );
	}

	if((cert = PKI_X509_CERT_get_url( inUrl, NULL, NULL )) == NULL) {
		if(!verbose) fprintf(stderr,"\n");
		fprintf( stderr, BOLD RED "    ERROR: " 
				NORM "Can not open certificate URL " BLUE "(%s)\n\n" NORM,
					inUrl->url_s );
		exit(1);
	};

	if( verbose ) {
		fprintf( stderr, GREEN " Ok" NORM "\n");
		fprintf( stderr, 
			"    * Saving Certificate ....." );
	};

	if( outform == PKI_DATA_FORMAT_UNKNOWN ) {
		if( PKI_X509_CERT_put(cert, PKI_DATA_FORMAT_TXT, outfile, 
					NULL, NULL, NULL) != PKI_OK ) {
			fprintf( stderr, BOLD RED "    ERROR: " 
				NORM "Can not store certificate to URL " BLUE "(%s)\n\n" NORM,
					inUrl->url_s );
			exit(1);
		}
		outform = PKI_DATA_FORMAT_PEM;
	};

	if ( verify ) {
		fprintf( stderr, "    Signature Verification: ");
		fflush ( stderr );
		if( PKI_X509_verify_cert ( cert, caCert ) == PKI_ERR ) {
			fprintf( stderr, BOLD RED " Error.\n" NORM);
		} else {
			fprintf (stderr, BOLD GREEN " Ok.\n" NORM );
		};
	};

	if( verify_chain ) {
		fprintf ( stderr, "    Chain Verify: " BOLD RED "Not Implemented\n" );
	}

	if( PKI_X509_CERT_put(cert, outform, outfile, 
			NULL, NULL, NULL) != PKI_OK ) {
		fprintf( stderr, BOLD RED "    ERROR: " 
				NORM "Can not store certificate to URL " BLUE "(%s)\n\n" NORM,
					inUrl->url_s );
		exit(1);
	};

	if( verbose ) {
		fprintf( stderr, GREEN " Ok" NORM "\n\n");
	};

	if( cert ) PKI_X509_CERT_free( cert );

	return(0);
}


