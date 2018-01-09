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
	"\n   " BOLD "PKI CRL Management Tool " NORM "(pki-crl)\n"
	"   (c) 2008-2015 by " BOLD "Massimiliano Pala" NORM
			" and " BOLD "Open" RED "CA" NORM BOLD " Labs\n" NORM
	"       " BOLD BLUE "Open" RED "CA" NORM " Licensed software\n\n";

char usage_str[] =
	"     " BG "                                                " NORM "\n"
	"     " BG_BOLD "  USAGE: " BG_NORM "pki-crl "
		BG_GREEN "[options]                      " NORM "\n"
	"     " BG "                                                " NORM "\n\n";

void usage ( void ) {
	int i = 0;

	printf( "%s", banner );
	printf( "%s", usage_str );

	printf("   Where options are:\n");
	printf(BLUE "    -in " RED "<URI> " NORM "...........: Loads an existing CRL from <URI>\n");
	printf(BLUE "    -out " RED "<URI> " NORM "..........: Output is sent to <URI>\n");
	printf(BLUE "    -new " NORM "................: Generates a new CRL\n");
	printf(BLUE "    -cert " RED "<URI>" NORM "..........: Certificate for signing new CRLs\n");
	printf(BLUE "    -key " RED "<URI>" NORM "...........: Private Key to use for signing new CRLs\n");
	printf(BLUE "    -token " RED "<URI>" NORM ".........: URI of the Token to load\n");
	printf(BLUE "    -passin " RED "<opt>" NORM "........: Password method (stdin, env:var, file://.., none)\n");
	printf(BLUE "    -password " RED "<pwd>" NORM "......: URI of the Token to load\n");
	printf(BLUE "    -profile " RED "<opt>" NORM ".......: Name of the CRL profile to use\n");
	printf(BLUE "    -profileuri " RED "<URI>" NORM "....: URI of a CRL profile to be loaded\n");
	printf(BLUE "    -entry " RED "<ser:[code]>" NORM "..: Revoked Entry (with reason code)\n");
	printf(BLUE "    -crlNum " RED "<num>" NORM "........: CRL's serial number\n");
	printf(BLUE "    -validity " RED "<secs>" NORM ".....: CRL validity period (in secs)\n");
	printf(BLUE "    -outform " RED "<opt>" NORM ".......: Output format (PEM, DER, TXT, XML)\n");
	printf(BLUE "    -verbose"        NORM " ............: Be verbose during operations\n");
	printf(BLUE "    -debug"        NORM " ..............: Print debug information\n");
	printf(BLUE "    -help"        NORM " ...............: Print this message\n");
	printf("\n");
	printf("   Where revocation codes are:\n");
	for ( i = 0 ; i < PKI_X509_CRL_REASON_CODE_num(); i++ ) {
		printf("    * " BLUE "%s " NORM ": %s\n", 
			PKI_X509_CRL_REASON_CODE_get_parsed ( i ),
			PKI_X509_CRL_REASON_CODE_get_descr ( i ));
	} 
	printf("\n");

	exit (1);
}

PKI_X509_CRL_REASON get_rev_instruction( char *st ) {

	PKI_X509_CRL_REASON ret = PKI_CRL_REASON_UNSPECIFIED;

	if (!st || strlen(st) == 0) return ret;

	if( strcmp_nocase( st, "keyCompromise") == 0 ) {
	ret = PKI_CRL_REASON_KEY_COMPROMISE;
	} else if( strcmp_nocase( st, "caCompromise") == 0 ) {
    	ret = PKI_CRL_REASON_CA_COMPROMISE;
	} else if( strcmp_nocase( st, "affiliationChanged") == 0 ) {
    	ret = PKI_CRL_REASON_AFFILIATION_CHANGED;
	} else if( strcmp_nocase( st, "superseded") == 0 ) {
    	ret = PKI_CRL_REASON_SUPERSEDED;
	} else if( strcmp_nocase( st, "cessationOfOperation") == 0 ) {
    	ret = PKI_CRL_REASON_CESSATION_OF_OPERATION;
	} else if( strcmp_nocase( st, "certificateHold") == 0 ) {
    	ret = PKI_CRL_REASON_CERTIFICATE_HOLD;
	} else if( strcmp_nocase( st, "removeFromCRL") == 0 ) {
    	ret = PKI_CRL_REASON_REMOVE_FROM_CRL;
	} else if( strcmp_nocase( st, "privilegeWithdrawn") == 0 ) {
    	ret = PKI_CRL_REASON_PRIVILEGE_WITHDRAWN;
	} else if( strcmp_nocase( st, "aaCompromise") == 0 ) {
    	ret = PKI_CRL_REASON_AA_COMPROMISE;
	} else {
		fprintf(stderr, "ERROR, reason %s not recognized!\n\n", st);
		exit(1);
	}

	return ret;
};


int main (int argc, char *argv[] ) {
	PKI_X509_CRL *crl = NULL;
	PKI_TOKEN *tk = NULL;
	URL *inUrl = NULL;
	URL *outUrl = NULL;
	int i, error;

	int debug = 0;
	int verbose = 0;
	PKI_LOG_FLAGS log_debug = 0;
	int log_level = PKI_LOG_ERR;

	PKI_DATA_FORMAT outform = PKI_DATA_FORMAT_PEM;

	char *token = NULL;
	char *infile = "stdin";
	char *outfile = "stdout";
	char *outform_s = NULL;
	char *config = NULL;
	char *profile_s = NULL;
	char *profile_uri_s = NULL;
	char *crlNum_s = NULL;
	char *entry_s = NULL;
	char *cert_s = NULL;
	char *key_s = NULL;
	char *passin = NULL;
	char *password = NULL;

	long long validity = PKI_VALIDITY_ONE_WEEK;
	PKI_X509_CRL_ENTRY_STACK *entryStack = NULL;
	PKI_X509_CRL_ENTRY *crlEntry = NULL;

	int new = 0;

	PKI_init_all();

	if((entryStack = PKI_STACK_X509_CRL_ENTRY_new()) == NULL ) {
		fprintf(stderr, "ERROR, memory allocation!\n\n");
		exit(1);
	};

	error = 0;
	for(i=1; i < argc; i++ ) {
		if( strncmp_nocase( argv[i], "-in", 3 ) == 0 ) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			infile=(argv[++i]);
		} else if(strncmp_nocase(argv[i],"-new", 4) == 0 ) {
			new=1;
		} else if ( strncmp_nocase ( argv[i], "-config", 6 ) == 0) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			config=(argv[++i]);
		} else if ( strncmp_nocase ( argv[i], "-token", 6 ) == 0) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			token=(argv[++i]);
		} else if ( strncmp_nocase ( argv[i], "-profileuri", 11 ) == 0) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			profile_uri_s=(argv[++i]);
		} else if ( strncmp_nocase ( argv[i], "-profile", 8 ) == 0) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			profile_s=(argv[++i]);
		} else if ( strncmp_nocase ( argv[i], "-cert", 5 ) == 0) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			cert_s=(argv[++i]);
		} else if ( strncmp_nocase ( argv[i], "-key", 4 ) == 0) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			key_s=(argv[++i]);
		} else if ( strncmp_nocase ( argv[i], "-entry", 6 ) == 0) {
			PKI_X509_CRL_REASON instruction = PKI_CRL_REASON_UNSPECIFIED;
			char *idx = NULL;
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			entry_s=strdup(argv[++i]);

			if ((idx = strchr( entry_s, ':')) != NULL) {
				char *reason_s = NULL;
				*idx = '\x0';
				idx++;
				reason_s = idx;
				instruction = get_rev_instruction ( reason_s );
			} else {
				instruction = PKI_CRL_REASON_UNSPECIFIED;
			}

			if ((crlEntry = PKI_X509_CRL_ENTRY_new_serial(entry_s,
            						instruction, NULL, NULL )) == NULL ) {
        			fprintf(stderr, "ERROR, can not generate CRL entry from -entry %s!\n\n",
					entry_s);
        			exit(1);
    			}

			if( PKI_STACK_X509_CRL_ENTRY_push( entryStack, crlEntry ) == PKI_ERR ) {
				fprintf(stderr, "ERROR, can not add entry %s to CRL "
					"entries' stack!\n\n", entry_s);
				exit ( 1 );
			};
		} else if ( strncmp_nocase ( argv[i], "-passin", 7 ) == 0) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			passin=(argv[++i]);
		} else if ( strncmp_nocase ( argv[i], "-password", 7 ) == 0) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			password=(argv[++i]);
		} else if ( strncmp_nocase ( argv[i], "-crlNum", 7 ) == 0) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			crlNum_s=(argv[++i]);
		} else if ( strncmp_nocase ( argv[i], "-validity", 9 ) == 0) {
			if( argv[i+1] == NULL ) {
				error=1;
				break;
			}
			validity=atoll(argv[++i]);
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
		} else if(strncmp_nocase(argv[i], "-h", 2) == 0 ) {
			usage();
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
			usage();
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

	if ( !token && new ) {
		if((tk = PKI_TOKEN_new_null ()) == NULL ) {
			fprintf( stderr, "ERROR, memory allocation in Token Initialization!\n\n");
			exit ( 1 );
		};

		if( password ) {
			PKI_CRED *cred = NULL;

			if((cred = PKI_CRED_new_null()) == NULL ) {
				fprintf( stderr, "ERROR, memory allocation\n\n");
				exit(1);
			};
			cred->username = NULL;
			cred->password = strdup(password);

			PKI_TOKEN_set_cred( tk, cred );
			PKI_TOKEN_cred_set_cb(tk, NULL, NULL);

		} else if( passin ) {
			if( strncmp_nocase( passin, "env:", 4) == 0) {
                PKI_TOKEN_cred_set_cb ( tk, PKI_TOKEN_cred_cb_env, passin+4);
            } else if (strncmp_nocase( passin, "stdin", 5) == 0 ) {
                PKI_TOKEN_cred_set_cb ( tk,
                    PKI_TOKEN_cred_cb_stdin, NULL);
            } else if (strncmp_nocase( passin, "none", 4) == 0 ) {
                PKI_TOKEN_cred_set_cb ( tk, NULL, NULL);
            } else if (strlen(passin) < 1) {
                PKI_TOKEN_cred_set_cb ( tk, NULL, NULL );
            }
		} else {
			PKI_TOKEN_cred_set_cb(tk, PKI_TOKEN_cred_cb_stdin, NULL);
		}

		if ( !cert_s || !key_s )
		{
			fprintf( stderr, "\n    " RED BOLD "ERROR:" NORM " -token "
				BLUE "<name>" NORM " or -cert " BLUE "<uri>" NORM " and -key "
				BLUE "<uri>" NORM " required!\n\n");

			exit(1);
		}

		if( PKI_TOKEN_load_cert( tk, cert_s ) == PKI_ERR ) {
			fprintf( stderr, "ERROR, can not load certificate %s\n\n", cert_s );
			exit(1);
		};

		if ( PKI_TOKEN_load_keypair( tk, key_s ) == PKI_ERR ) {
			fprintf( stderr, "ERROR, can not load KeyPair %s\n\n", key_s );
			exit(1);
		};

	} else {
		if((tk = PKI_TOKEN_new ( config, token )) == NULL ) {
			fprintf(stderr, "ERROR, can not load token %s\n\n", token);
			exit ( 1 );
		};
	};

	if( profile_uri_s ) {
		PKI_X509_PROFILE *prof = NULL;
		if((prof = PKI_X509_PROFILE_load( profile_uri_s )) == NULL ) {
			fprintf( stderr, "ERROR, can not load profile uri %s", profile_uri_s );
			exit(1);
		}
		if( PKI_TOKEN_add_profile( tk, prof ) == PKI_ERR ) {
			fprintf( stderr, "ERROR, can not add profile %s!\n\n", profile_uri_s);
			exit(1);
		};
	};

	if( new ) {
		// fprintf( stderr, "REASON CODES = > %d\n",
		// 	PKI_X509_CRL_REASON_CODE_get ( "" ) );

		if ((crl = PKI_TOKEN_issue_crl(tk, crlNum_s, (long unsigned int) validity, entryStack, profile_s )) == NULL ) {
			fprintf( stderr, "ERROR, can not issue new CRL!\n\n");
			exit(1);
		};
	} else {
		if((crl = PKI_X509_CRL_get_url( inUrl, NULL, NULL )) == NULL) {
			if(!verbose) fprintf(stderr,"\n");
			fprintf( stderr, BOLD RED "    ERROR: " 
					NORM "Can not open certificate URL " BLUE "(%s)\n\n" NORM,
						inUrl->url_s );
			exit(1);
		};
	};

	if( outfile ) {
		if( verbose ) {
			fprintf( stderr, GREEN " Ok" NORM "\n");
			fprintf( stderr, 
				"    * Saving CRL ....." );
		};

		if( PKI_X509_CERT_put(crl, outform, outfile, 
				NULL, NULL, NULL) != PKI_OK ) {
			fprintf( stderr, BOLD RED "    ERROR: " 
					NORM "Can not store CRL to URL " BLUE "(%s)\n\n" NORM,
						inUrl->url_s );
			exit(1);
		};

		if( verbose ) {
			fprintf( stderr, GREEN " Ok" NORM "\n\n");
		};
	};

	if( crl ) PKI_X509_CRL_free( crl );

	return(0);
}


