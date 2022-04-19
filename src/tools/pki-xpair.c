#include <libpki/pki.h>

void usage ( void ) {

	printf("\n\nPKI Cross Certificates Management Tool\n");
	printf("(c) 2006-2022 by Massimiliano Pala and OpenCA Labs\n");
	printf("    OpenCA Licensed Software\n\n");

	printf("  USAGE: pki-xpair [options]\n\n");

	printf("  Where options are:\n");
	printf("  -in <url>          - crossCertPair URI\n");
	printf("  -out <url>         - Output URI for the CrossCertPair\n");
//	printf("  -inform <format>   - Input format (PEM, DER, ...)\n");
	printf("  -outform <format>  - Output format (PEM, DER, ...)\n");
	printf("  -reverse <certUri> - Reverse Certificate URI\n");
	printf("  -forward <certUri> - Forward Certificate URI\n");
	printf("  -new               - Creates a new crossCertPair (use '-forward' and\n");
	printf("                       '-reverse' to specify the cross certs to use)\n");
	printf("  -text              - Outputs a text format\n");
	printf("  -certsonly         - Outputs only the certs (PEM)\n");
	printf("  -noout             - Does not output the crossCertPair\n");
	printf("  -verbose           - Writes additional info to stdout\n");
	printf("  -debug             - Enables Debugging info to stderr\n");
	printf("\n");

	exit(1);
}

void version ( void ) {
	printf("PKI Tool::Version=%s\n", PACKAGE_VERSION );

	exit(0);
}

int main (int argc, char *argv[] ) {

	PKI_X509_XPAIR_STACK *xp_sk = NULL;
	PKI_X509_XPAIR *xp = NULL;
	PKI_X509_CERT *x1 = NULL; 
	PKI_X509_CERT *x2 = NULL;

	char *inurl_s 	= NULL;
	char *outurl_s 	= NULL;
	char *outform_s	= NULL;
	char *reverse_s = NULL;
	char *forward_s = NULL;

	int new 	= 0;
	int text 	= 0;
	int certsonly 	= 0;
	int noout 	= 0;
	int verbose 	= 0;
	int debug 	= 0;
	int i 		= 0;

	PKI_DATA_FORMAT outform	= PKI_DATA_FORMAT_PEM;

	int log_level	= PKI_LOG_ERR;
	PKI_LOG_FLAGS log_debug	= 0;

	// char *url = "ldap://ldap.dartmouth.edu:389/cn=Dartmouth CertAuth1, o=Dartmouth College, C=US, dc=dartmouth, dc=edu?crossCertificatePair;binary";
	// char *url = "ldap://fpkia.gsa.gov:389/ou=Entrust, ou=FBCA, o=U.S. Government, c=US?crossCertificatePair;binary";

	if( argc < 1 ) {
		usage();
	}

	for ( i = 1; i < argc; i++ ) {
		if ( strncmp_nocase ("-new", argv[i], 4) == 0 ) {
			new = 1;
		} else if ( strcmp_nocase("-forward", argv[i] ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			forward_s = argv[i];
		} else if ( strcmp_nocase("-reverse", argv[i] ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			reverse_s = argv[i];
		} else if ( strcmp_nocase("-out", argv[i] ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			outurl_s = argv[i];
		} else if ( strcmp_nocase("-in", argv[i] ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			inurl_s = argv[i];
		} else if ( strcmp_nocase("-outform", argv[i] ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			outform_s = argv[i];
		} else if ( strcmp_nocase("-text", argv[i] ) == 0 ) {
			text = 1;
		} else if ( strcmp_nocase("-certsonly", argv[i] ) == 0 ) {
			certsonly = 1;
		} else if ( strcmp_nocase("-noout", argv[i] ) == 0 ) {
			noout = 1;
		} else if ( strcmp_nocase("-verbose", argv[i] ) == 0 ) {
			verbose = 1;
		} else if ( strcmp_nocase("-debug", argv[i] ) == 0 ) {
			debug = 1;
		} else {
			usage();
		}
	}

	if( verbose ) log_level = PKI_LOG_INFO;
	if( debug ) log_debug |= PKI_LOG_FLAGS_ENABLE_DEBUG;

	if( outform_s ) {
		if(strcmp_nocase(outform_s, "PEM" ) == 0 ) {
			outform = PKI_DATA_FORMAT_PEM;
		} else if (strcmp_nocase(outform_s, "DER" ) == 0 ) {
			outform = PKI_DATA_FORMAT_ASN1;
		} else {
			printf("ERROR, outfomat (%s) not supported (use PEM "
					"or DER)\n\n", outform_s );
			exit(1);
		}
	}

	if( !outurl_s ) outurl_s = "stdout";
	if( !inurl_s ) inurl_s = "stdin";

	if(( PKI_log_init (PKI_LOG_TYPE_STDERR, log_level, NULL,
			log_debug, NULL )) == PKI_ERR ) {
		exit(1);
	}


	if( new ) {
		if((xp = PKI_X509_XPAIR_new_null()) == NULL ) {
			printf("ERROR, memory allocation!\n");
			exit(1);
		}

		if( forward_s ) {
			if((x1 = PKI_X509_CERT_get ( forward_s, 
						PKI_DATA_FORMAT_UNKNOWN, NULL, NULL )) == NULL ) {
				PKI_log_err("Can not load forward "
					"certificate [%s]", forward_s );
				exit(1);
			}
			PKI_X509_XPAIR_set_forward ( xp, x1 );
		}

		if( reverse_s ) {
			if((x2 = PKI_X509_CERT_get ( reverse_s, 
						PKI_DATA_FORMAT_UNKNOWN, NULL, NULL )) == NULL ) {
				PKI_log_err("Can not load reverse "
					"certificate [%s]", reverse_s );
				exit(1);
			}
			PKI_X509_XPAIR_set_reverse ( xp, x2 );
		}


		xp_sk = PKI_STACK_X509_XPAIR_new();
		PKI_STACK_X509_XPAIR_push( xp_sk, xp );

	} else {
		if((xp_sk = PKI_X509_XPAIR_STACK_get ( inurl_s, 
						PKI_DATA_FORMAT_UNKNOWN, NULL, NULL )) == NULL ) {
			PKI_log_err("Can not load XPAIR from %s!", inurl_s );
			exit(1);
		}

		if( verbose ) {
			PKI_log(PKI_LOG_INFO, "Got %d Elements\n", 
				PKI_STACK_X509_XPAIR_elements (xp_sk ));
		}

	}

	for ( i=0; i < PKI_STACK_X509_XPAIR_elements( xp_sk ); i++ ) {
		xp = PKI_STACK_X509_XPAIR_get_num( xp_sk, i );

		if( text ) {
			PKI_X509_XPAIR_put ( xp, PKI_DATA_FORMAT_TXT, outurl_s, 
						NULL, NULL, NULL );
		} else if( certsonly ) {
			PKI_X509_CERT *x = NULL;

			if((x = PKI_X509_XPAIR_get_forward( xp )) != NULL ) {
				PKI_X509_put ( x, PKI_DATA_FORMAT_PEM, outurl_s,
						NULL, NULL, NULL );
				PKI_X509_free ( x );
			}

			if((x = PKI_X509_XPAIR_get_reverse( xp )) != NULL )  {
				PKI_X509_put ( x, PKI_DATA_FORMAT_PEM, outurl_s,
						 NULL, NULL, NULL );
				PKI_X509_free ( x );
			}
		}

		if( !noout ) {
			PKI_X509_XPAIR_put ( xp, outform, outurl_s, 
							NULL, NULL, NULL );
		}
	}
	return 0;
}
