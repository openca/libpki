
#include <libpki/pki.h>

/* Global Variables - not a good coding practice, but for a small
   tool is not a problem (and it saves in complexity for signatures
   of the functions */

int verbose = 0;
int debug = 0;


/*------------------------------ Functions -----------------------------*/

char * prompt_str( char * pt ) {
	char buf[1024];
	char *ret = NULL;
	int i;
	char c;

	fprintf(stderr, "%s", pt);
	memset(buf, 0, sizeof(buf));

	for(i = 0 ; i < sizeof(buf); i++ )
	{
		if (scanf("%c", &c) > 0)
		{
			buf[i] = c;
			if( c == '\n' || c == '\r' )
			{
				buf[i] = '\x0';
				break;
			}
		}
	}

	ret = (char *) PKI_Malloc ((size_t) i+1);
	memcpy(ret, buf, (size_t) i+1);
	return ret;
}

void usage ( void ) {

	fprintf(stderr, "\n\nPKI Token Tool - Massimiliano Pala <madwolf@openca.org>\n");
	fprintf(stderr, "(c) 2006-2015 by Massimiliano Pala and OpenCA Labs\n");
	fprintf(stderr, "OpenCA Licensed Software\n\n");

	fprintf(stderr, "  USAGE: pki-tool cmd [options]\n\n");
	fprintf(stderr, "  Where cmd is:\n");
	fprintf(stderr, "  info            - Prints out information about the token\n");
	fprintf(stderr, "  list            - List the names of available tokens\n");
	fprintf(stderr, "  clear           - Deletes all the data on the token\n");
	fprintf(stderr, "  delete          - Deletes objects (use -uri)\n");
	fprintf(stderr, "  genkey          - Generates a new Keypair (def. RSA-SHA1)\n");
	fprintf(stderr, "  genreq          - Generates a new X.509 PKCS#10 request\n");
	fprintf(stderr, "  gencert         - Generates a new X.509 certificate\n");
	fprintf(stderr, "  import          - Import an item in the token\n");
	fprintf(stderr, "\n");

	fprintf(stderr, "  Where Options are:\n");
	fprintf(stderr, "  -token          - Name of the token to be used\n");
	fprintf(stderr, "  -config <dir>   - Token config dir (HOME/.libpki/token.d)\n");
	fprintf(stderr, "  -hsm <name>     - HSM name (HOME/.libpki/hsm.d)\n");
	fprintf(stderr, "  -in <url>       - Input Data URI\n");
	fprintf(stderr, "  -out <url>      - Output Data URI\n");
	fprintf(stderr, "  -bits <num>     - Number of Bits\n");
	fprintf(stderr, "  -type <objtype> - Type of Object\n");
	fprintf(stderr, "  -algor <name>   - Algorithm to be used\n");
	fprintf(stderr, "  -newkey         - Generate new keypair when using genreq\n");
	fprintf(stderr, "  -outkey <URI>   - URI where to store the new key\n");
	fprintf(stderr, "  -uri <uri>      - URI of the item (key/cert/..) in the "
				    "token\n");
	fprintf(stderr, "  -signkey <uri>  - URI of the cert-signing key\n");
	fprintf(stderr, "  -signcert <uri> - URI of the cert-signing cert (CA)\n");
	fprintf(stderr, "  -subject <dn>   - Distinguished Name (Subject)\n");
	fprintf(stderr, "  -serial <num>   - Serial Number to use (gencert)\n");
	fprintf(stderr, "  -profile <name> - Profile to use (gencert/genreq)\n");
	fprintf(stderr, "  -profileuri <uri>  - Profile URI to load (gencert/genreq)\n");
	fprintf(stderr, "  -profilesdir <dir> - Directory to scan for profile configs\n");
	fprintf(stderr, "  -oidsuri <uri>  - OID files to load (gencert/genreq)\n");
	fprintf(stderr, "  -days <num>     - Validity period (days)\n");
	fprintf(stderr, "  -hours <num>    - Validity period (hours)\n");
	fprintf(stderr, "  -mins <num>     - Validity period (mins)\n");
	fprintf(stderr, "  -secs <num>     - Validity period (secs)\n");
	fprintf(stderr, "  -selfsign       - Generate a self signed X.509 cert\n");
	fprintf(stderr, "  -outform <OPT>  - Output format (i.e., PEM, DER, TXT, XML)\n");
	fprintf(stderr, "  -batch          - Batch mode (no prompt - assumes yes)\n");
	fprintf(stderr, "  -verbose        - Writes additional info to stdout\n");
	fprintf(stderr, "  -debug          - Enables Debugging info to stderr\n");
	fprintf(stderr, "  -param <par>    - KeyGen param (eg., curve:curvename for EC)\n");
	fprintf(stderr, "  -curves         - Prints out available curve names\n");

	fprintf(stderr, "\n  Where Type of Object can be:\n");
	fprintf(stderr, "   any            - Unknown type\n");
	fprintf(stderr, "   key            - Keypair (Pub and Priv Keys)\n");
	fprintf(stderr, "   pubkey         - Public Key\n");
	fprintf(stderr, "   privkey        - Private Key\n");
	fprintf(stderr, "   user           - User Certificates\n");
	fprintf(stderr, "   ca             - CA Certificates\n");
	fprintf(stderr, "   trusted        - Trusted Certificates (TA)\n");
	fprintf(stderr, "   other          - Other Certificates\n");
	fprintf(stderr, "   crl            - CRL\n");

	fprintf(stderr, "\n");

	exit(1);
}

void usage_curves (char *curr_name) {
	fprintf(stderr, "\n\nPKI Token Tool - Massimiliano Pala <madwolf@openca.org>\n");
	fprintf(stderr, "(c) 2006-2011 by Massimiliano Pala and OpenCA Labs\n");
	fprintf(stderr, "OpenCA Licensed Software\n\n");

	if (curr_name) fprintf(stderr, "    ERROR: unknown curve %s\n\n", curr_name );

	fprintf(stderr, "  Available EC Curves:\n" );

#ifdef ENABLE_ECDSA
	EC_builtin_curve *curves = NULL;
	size_t num_curves = 0;
	int i;

	/* Get the number of availabe ECDSA curves in OpenSSL */
	if((num_curves = EC_get_builtin_curves(NULL, 0)) < 1 ) {
		/* No curves available! */
		goto err;
	}

	/* Alloc the needed memory */
	curves = OPENSSL_malloc(sizeof(EC_builtin_curve) * (int) num_curves);

	if (curves == NULL) goto err;

	/* Get the builtin curves */
	if (!EC_get_builtin_curves(curves, num_curves)) {
		if( curves ) free (curves);
		goto err;
	}

	/* Cycle through the curves and display the names */
	for( i = 0; i < num_curves; i++ ) {
		int nid;
		PKI_OID *oid = NULL;

		nid = curves[i].nid;
		if((oid = PKI_OID_new_id(nid)) != NULL) {
			fprintf(stderr, "  - [%2.2d] %25s : %s\n", i, PKI_OID_get_descr(oid), 
				curves[i].comment);
	 		PKI_OID_free ( oid );
		};
	};
	fprintf(stderr, "\n");

	if( curves ) free ( curves );

	exit(0);

err:
	exit(1);

#endif

}

void version ( void ) {
	fprintf(stderr,"PKI Tool::Version=%s\n", PACKAGE_VERSION );

	exit(0);
}

int gen_keypair ( PKI_TOKEN *tk, int bits, char *param_s,
		char *url_s, char *algor_opt, char *profile_s, char *outform, int batch ) {

	int algor_id = 0;

	char *prompt = NULL;
	int outFormVal = PKI_DATA_FORMAT_PEM;

	URL *keyurl = NULL;

	PKI_KEYPARAMS *kp = NULL;
	PKI_X509_PROFILE *prof = NULL;

	int scheme = -1;

	if((url_s==NULL) || (strcmp_nocase("stdin", url_s) == 0)) {
		if((url_s = tk->key_id) == NULL ) {
			if(tk->config) {
				if((url_s = PKI_CONFIG_get_value(tk->config, 
						"/tokenConfig/keypair")) == NULL) {
					url_s = "stdout";
				};
			};
		};
	};

	if ( outform ) {
		if (strcmp_nocase( outform, "pem") == 0 ) {
			outFormVal = PKI_DATA_FORMAT_PEM;
		} else if ( strcmp_nocase( outform, "der") == 0 ) {
			outFormVal = PKI_DATA_FORMAT_ASN1;
	  } else if ( strcmp_nocase( outform, "txt") == 0 ) {
		  outFormVal = PKI_DATA_FORMAT_TXT;
		} else if ( strcmp_nocase( outform, "xml") == 0 ) {
			outFormVal = PKI_DATA_FORMAT_XML;
		} else {
			fprintf(stderr, "ERROR, out format %s not supported!\n\n", outform);
			exit(1);
		};
	};

	// Output can not write to stdin, so, if that was specified, 
	// let's re-route to stdout instead
	if (!url_s || strcmp_nocase(url_s, "stdin") == 0) url_s = "stdout";
	PKI_log_debug("Output URL: %s", url_s);

	keyurl = URL_new( url_s );

	if (keyurl == NULL)
	{
		fprintf(stderr, "\nERROR: can not parse URL [%s]\n\n", url_s );
		exit(1);
	}

	// Let's get the algor options from the ENV if not set
	if( !algor_opt ) algor_opt = PKI_get_env ( "PKI_TOKEN_ALGORITHM" );

	if( algor_opt != NULL )
	{
		PKI_ALGOR *algor = NULL;

		/* Get the Algor Id from the cmd line option */
		algor = PKI_ALGOR_get_by_name ( algor_opt );
		if (!algor)
		{
			fprintf(stderr, "\nERROR: Algorithm %s is not recognized!\n\n", algor_opt);
			exit(1);
		}

		algor_id = PKI_ALGOR_get_id ( algor );
		scheme   = PKI_ALGOR_get_scheme ( algor );

		if (verbose && !batch) 
		{
			fprintf(stderr, "\nSetting Token Algorithm to %s ... ", 
					PKI_ALGOR_ID_txt ( algor_id ) );
		}

		if ((PKI_TOKEN_set_algor ( tk, algor_id )) == PKI_ERR)
		{
			fprintf(stderr, "ERROR, can not set the crypto scheme!\n\n");
			exit(1);
		}

		if( verbose && !batch ) fprintf(stderr, "Ok.\n");
	}

	// If specified, search the profile among the ones already loaded
	if (profile_s) prof = PKI_TOKEN_search_profile( tk, profile_s );

	// Let's now generate the new key parameters
	if ((kp = PKI_KEYPARAMS_new ( scheme, prof )) == NULL )
	{
		fprintf(stderr, "ERROR, can not create KEYPARAMS object (scheme %d)!\n\n", scheme);
		exit(1);
	}

	// Checks that the bits value is not negative (at least!)
	if( bits > 0 ) kp->bits = bits;

	// Checks for Paramters for Key Generation
	if( param_s )
	{
		switch ( kp->scheme )
		{
			case PKI_SCHEME_RSA:
			case PKI_SCHEME_DSA:
				// Nothing to do Here - no params support
				break;

#ifdef ENABLE_ECDSA
			case PKI_SCHEME_ECDSA:
				// ECDSA Scheme - allow for curve:<name> param
				if( strncmp_nocase( param_s, "curve:", 6) == 0 ) {
					char *curveName;
					PKI_OID *oid = NULL;

					// Get the Name of the Curve
					curveName = &param_s[6];

					// If the name of the Curve generates a valid id, let's use it
					if((oid = PKI_OID_get(curveName)) != NULL) {
						if(( kp->ec.curve = PKI_OID_get_id(oid)) != PKI_ID_UNKNOWN) {
							PKI_OID_free(oid);
						} else {
							PKI_OID_free ( oid );
							usage_curves( curveName );
						};
					} else {
						usage_curves( curveName );
					};
				};
				break;
#endif
		};

	}

	if (!batch)
	{
		fprintf(stderr, "\nThis will generate a new keypair on the "
							"Token.\n");
		fprintf(stderr, "\nDetails:\n");
		fprintf(stderr, "  - Algorithm ......: %s\n", 
					PKI_SCHEME_ID_get_parsed( kp->scheme ));
		fprintf(stderr, "  - Bits ...........: %d\n", kp->bits );
#ifdef ENABLE_ECDSA
		fprintf(stderr, "  - Point Type......: %d\n", kp->ec.form );
#endif
		fprintf(stderr, "  - Output .........: %s\n", keyurl->url_s );

		prompt = prompt_str ("\nAre you sure [y/N] ? ");
	}

	if( batch || (strncmp_nocase(prompt, "y", 1 ) == 0))
	{
		int ret = PKI_OK;
		char *tmp_s = NULL;

		if(verbose) {
			fprintf(stderr, "Generating new KeyPair ... ");
			fflush(stderr);
		}

		if((PKI_TOKEN_new_keypair_url_ex ( tk, kp, keyurl, profile_s )) == PKI_ERR)
		{
			if(verbose) fprintf(stderr, "Error.\n");
			return (PKI_ERR);
		}
		else if( verbose ) fprintf(stderr, "Ok.\n");

		if (verbose)
		{
			fprintf(stderr, "Saving KeyPair to ");
			fflush(stderr);
		}

		if (tk->type != HSM_TYPE_PKCS11)
		{
			if (keyurl)
			{
				if (verbose)
				{
					fprintf( stderr, "%s ... ", keyurl->url_s );
					fflush(stderr);
				}

				tmp_s = keyurl->url_s;
				ret = PKI_TOKEN_export_keypair( tk, tmp_s, outFormVal );
			}
			else
			{
				if((tmp_s = tk->key_id ) == NULL) tmp_s = "stdout";

				if (verbose)
				{
					fprintf( stderr, "%s ... ", tmp_s );
					fflush(stderr);
				}

				ret = PKI_TOKEN_export_keypair( tk, tmp_s, PKI_DATA_FORMAT_PEM);
			}

			if ( ret == PKI_ERR )
			{
				if(verbose) fprintf(stderr, "Error!\n");
				return ( PKI_ERR );
			} 
			else if( verbose ) fprintf(stderr, "Ok!\n");
		}
	} 
	else
	{
		fprintf(stderr, "\nOperation Cancelled.\n\n");
		exit(1);
	}

	if (kp) PKI_KEYPARAMS_free ( kp );

	return ( PKI_OK );
}

int main (int argc, char *argv[] ) {

	PKI_TOKEN *tk = NULL;
	PKI_X509_PROFILE *prof =  NULL;

	unsigned long i = 0;
	unsigned long start = 2;
	char * prompt = NULL;

	char * cmd = NULL;
	char * token_name = NULL;
	char * infile = NULL;
	char * outfile = NULL;
	char * config = NULL;

	int log_level = PKI_LOG_ERR;
	int log_debug = 0;
	int batch = 0;

	int bits = 0;
	int token_slot = 0;
	int selfsign = 0;
	int newkey = 0;

	char * algor_opt = NULL;
	char * hsm_name = NULL;
	char * uri = NULL;
	char * signkey = NULL;
	char * signcert = NULL;
	char * subject = NULL;
	char * profile = NULL;
	char * profileuri = NULL;
	char * profiles_dir = NULL;
	char * oidsuri = NULL;
	char * serial = NULL;
	char * type = NULL;
	char * param_s = NULL;
	char * outkey_s = NULL;
	char * outform = NULL;

	char * outpubkey_s = NULL;
	char * outprivkey_s = NULL;

	int days  = 0;
	int hours = 0;
	int mins  = 0;
	int secs  = 0;

	unsigned long validity = 0;
	int datatype = 0;

	if( argc < 2 ) {
		usage();
	}

	cmd = argv[1];

	for ( i = start; i < argc; i++ ) {
		if ( strncmp_nocase ("-token", argv[i], 5) == 0 ) {
			if( argv[i++] == NULL ) usage();
			token_name = argv[i];
		} else if ( strncmp_nocase("-config", argv[i], 7 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			config = argv[i];
		} else if ( strncmp_nocase("-type", argv[i], 5 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			type = argv[i];
		} else if ( strncmp_nocase("-hsm", argv[i], 4 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			hsm_name = argv[i];
		} else if ( strncmp_nocase("-in", argv[i], 3 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			infile = argv[i];
		} else if ( strncmp_nocase("-outform", argv[i], 8 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			outform = argv[i];
		} else if ( strncmp_nocase("-outkey", argv[i], 7 ) == 0 ) {
			if( argv[i++] == NULL) usage();
			outkey_s = argv[i];
		} else if ( strncmp_nocase("-outpubkey", argv[i], 10) == 0 ) {
			if( argv[i++] == NULL) usage();
			outpubkey_s = argv[i];
		} else if ( strncmp_nocase("-outprivkey", argv[i], 11) == 0 ) {
			if( argv[i++] == NULL) usage();
			outprivkey_s = argv[i];
		} else if ( strncmp_nocase("-out", argv[i], 4 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			outfile = argv[i];
		} else if ( strncmp_nocase("-algor", argv[i], 6 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			algor_opt = argv[i];
		} else if ( strncmp_nocase("-signkey", argv[i], 8 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			signkey = argv[i];
			uri = signkey;
		} else if ( strncmp_nocase("-signcert", argv[i], 9 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			signcert = argv[i];
		} else if ( strncmp_nocase("-uri", argv[i], 4 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			uri = argv[i];
			signkey = uri;
			outkey_s = uri;
		} else if ( strncmp_nocase("-param", argv[i], 6 ) == 0 ) {
			if( argv[i++] == NULL) usage();
			param_s = argv[i];
		} else if ( strncmp_nocase("-subject", argv[i], 8 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			subject = argv[i];
		} else if ( strncmp_nocase("-serial", argv[i], 7 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			serial = argv[i];
		} else if ( strncmp_nocase("-profilesdir", argv[i], 11 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			profiles_dir = argv[i];
		} else if ( strncmp_nocase("-profileuri", argv[i], 11 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			profileuri = argv[i];
		} else if ( strncmp_nocase("-profile", argv[i], 8 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			profile = argv[i];
		} else if ( strncmp_nocase("-oidsuri", argv[i], 8 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			oidsuri = argv[i];
		} else if ( strncmp_nocase("-days", argv[i], 5 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			days = atoi( argv[i] );
		} else if ( strncmp_nocase("-hours", argv[i], 6 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			hours = atoi( argv[i] );
		} else if ( strncmp_nocase("-mins", argv[i], 5 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			mins = atoi( argv[i] );
		} else if ( strncmp_nocase("-secs", argv[i], 5 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			secs = atoi( argv[i] );
		} else if ( strncmp_nocase("-bits", argv[i], 5 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			bits = atoi(argv[i]);
		} else if ( strncmp_nocase("-slot", argv[i], 5 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			token_slot = atoi(argv[i]);
		} else if ( strncmp_nocase("-newkey", argv[i], 7 ) == 0 ) {
			newkey = 1;
		} else if ( strncmp_nocase("-batch", argv[i], 6 ) == 0 ) {
			batch = 1;
		} else if ( strncmp_nocase("-selfsign", argv[i], 9 ) == 0 ) {
			selfsign = 1;
		} else if ( strncmp_nocase("-verbose", argv[i], 8 ) == 0 ) {
			verbose = 1;
		} else if ( strncmp_nocase("-debug", argv[i], 6 ) == 0 ) {
			debug = 1;
		} else if ( strncmp_nocase("-curves", argv[i], 7 ) == 0 ) {
			usage_curves( NULL );
		} else {
			usage();
		}
	}

	if( verbose ) log_level = PKI_LOG_INFO;
	if( debug ) log_debug |= PKI_LOG_FLAGS_ENABLE_DEBUG;

	validity = (unsigned long)(secs + mins * 60 + hours * 3600 + 
					days * 86400);

	if(( PKI_log_init (PKI_LOG_TYPE_STDERR, log_level, NULL,
                        log_debug, NULL )) == PKI_ERR ) {
		exit(1);
	}

	if( !infile ) infile = "stdin";

	if((tk = PKI_TOKEN_new_null()) == NULL ) {
		printf("ERROR, can not allocate token!\n\n");
		exit(1);
	}

	if( verbose ) {
		printf("Loading Token .. ");
		fflush( stdout );
	}
	if(( PKI_TOKEN_init( tk, config, token_name )) == PKI_ERR) {
		printf("ERROR, can not load token (enable debug for "
							"details)!\n\n");
		exit(1);
	}
	if( verbose ) printf("Ok.\n");

	if( batch ) {
		PKI_TOKEN_cred_set_cb ( tk, NULL, NULL );
	};

	if( token_name == NULL ) {
		if( hsm_name ) {
			if( verbose ) {
				printf("Loading HSM (%s) .. ", hsm_name );
				fflush( stdout );
			}
			if((tk->hsm = HSM_new ( config, hsm_name )) == NULL ) {
				printf("ERROR, can not load HSM (enable debug"
						" for details)!\n\n");
				exit(1);
			};
			if( verbose ) printf ( "Ok.\n");

			tk->type = tk->hsm->type;
		}

		if ( signkey && !newkey) {
			if( verbose ) printf("Loading KeyPair...");
			fflush( stdout );

			if((PKI_TOKEN_load_keypair( tk, uri )) == PKI_ERR){
					printf("\nERROR, can not load key [%s]\n\n", signkey );
					exit(1);
			}
		}

		if ( signcert ) {
			if( verbose ) printf("Loading SignCert...");
			fflush( stdout );

			if((PKI_TOKEN_load_cert( tk, signcert )) == PKI_ERR) {
					fprintf(stderr, "ERROR: Can not load signcert (%s)\n\n",
						signcert );
					exit(1);
			}
		}

		if (profiles_dir)
		{
			if (verbose) printf("Loading Profiles from %s... ", profiles_dir);
			if (PKI_TOKEN_load_profiles(tk, profiles_dir) != PKI_OK)
			{
				fprintf(stderr, "ERROR: Can not load profiles dir (%s)", profiles_dir);
				exit(1);
			}
		}
	}

	if((PKI_TOKEN_use_slot( tk, token_slot )) == PKI_ERR ) {
		printf("ERROR, can not use selected slot (%d/%s)\n", 
						token_slot, token_name );
		exit (1);
	}

	if( !batch ) {
		printf("\n\nUsing Token (%s::%d)\n", 
					token_name ? token_name : "none", 
						token_slot );
		if( verbose )
			printf("  - Config Dir .. : %s\n\n", 
				PKI_TOKEN_get_config_dir ( tk ) ?
				PKI_TOKEN_get_config_dir ( tk ) : "none" );

	}

	if ( oidsuri ) {
		if ( tk->oids != NULL ) {
			PKI_CONFIG_free ( tk->oids );
		};

		if((tk->oids = PKI_CONFIG_OID_load( oidsuri )) == NULL ) {
        	PKI_log_debug("ERROR, can not load oids uri (%s)!\n", oidsuri);
    	};
	};

	if ( profileuri ) {
		PKI_X509_PROFILE *p = NULL;
		if(( p = PKI_X509_PROFILE_load ( profileuri )) == NULL ) {
			// Can not load the specified profile
			fprintf( stderr, "Can not load profile (%s)\n",
				profileuri );
			exit(1);
		};

		PKI_log_debug("Loaded profile: %s (%s)", profileuri,
			PKI_X509_PROFILE_get_name ( p ));

		if( PKI_TOKEN_add_profile( tk, p ) == PKI_ERR ) {
			fprintf( stderr, "ERROR, can not add profile to the Token!\n");
			exit(1);
		};

		PKI_log_debug("Profile Added to Token: Ok.");
	};

	/*
	if( tk ) {
		PKI_TOKEN_login ( tk );
	};
	*/

	if ( strncmp_nocase("version", cmd, 3) == 0 ) {
		version();
	} else if( strncmp( cmd, "clear", 5) == 0 ) {
		printf("\nThis will delete all the contents of the Token.\n");
		if( !batch ) {
			prompt = prompt_str ("Are you sure [y/N] ? ");
		}
		if( batch || (strncmp_nocase(prompt, "y", 1 ) == 0)) {
			printf("\nClearing up the Token Slot .. ");
			fflush( stdout );
			if((HSM_SLOT_clear ( (unsigned long) tk->slot_id, tk->cred, 
							tk->hsm )) == PKI_OK ) {
				printf("Ok.\n\n");
				exit(0);
			} else {
				printf("Error.\n\n");
				exit(1);
			}
		} else {
			printf("\nOperation Cancelled.\n\n");
		}
	} else if( strncmp( cmd, "delete", 6) == 0 ) {
		if( uri == NULL ) {
			printf("ERROR: please use '-uri' to identify what to "
								"delete.\n\n");
			usage();
		}

		if( type == NULL ) {
			/*
			printf("ERROR: please use '-type' to identify the "
					"type of object to delete.\n\n");
			usage();
			*/
			type = "any";
		}

		if( strncmp_nocase( type, "any", 3 ) == 0 ) {
			datatype = PKI_DATATYPE_ANY;
		} else if ( strncmp_nocase(type, "key", 3 ) == 0 ) {
			datatype = PKI_DATATYPE_X509_KEYPAIR;
		} else if ( strncmp_nocase(type, "pubkey", 6 ) == 0 ) {
			datatype = PKI_DATATYPE_PUBKEY;
		} else if ( strncmp_nocase(type, "privkey", 7 ) == 0 ) {
			datatype = PKI_DATATYPE_PRIVKEY;
		} else if ( strncmp_nocase(type, "other", 5 ) == 0 ) {
			datatype = PKI_DATATYPE_X509_OTHER;
		} else if ( strncmp_nocase(type, "trusted", 7 ) == 0 ) {
			datatype = PKI_DATATYPE_X509_TRUSTED;
		} else if ( strncmp_nocase(type, "cacert", 6 ) == 0 ) {
			datatype = PKI_DATATYPE_X509_CA;
		} else if ( strncmp_nocase(type, "cert", 4 ) == 0 ) {
			datatype = PKI_DATATYPE_X509_CERT;
		} else if ( strncmp_nocase(type, "req", 3 ) == 0 ) {
			datatype = PKI_DATATYPE_X509_REQ;
		} else if ( strncmp_nocase(type, "crl", 3 ) == 0 ) {
			datatype = PKI_DATATYPE_X509_CERT;
		} else {
			printf("ERROR: type is not of a recognized type. "
			    "please use one of any, pubkey, privkey, cert, "
				"req, or crl.\n\n");
			exit(1);
		}
		
		printf("\nThis will delete object %s (%s) in Token %s.\n",
						uri, type, token_name );
		if( !batch ) {
			prompt = prompt_str ("Are you sure [y/N] ? ");
		}
		if( batch || (strncmp_nocase(prompt, "y", 1 ) == 0)) {
			URL *url = NULL;

			if((url = URL_new(uri)) == NULL ) {
				printf("ERROR, %s is not a valid "
						"URI.\n\n", uri );
				exit(1);
			}

			printf("\nDeleting Object .. ");
			fflush( stdout );
			if ( datatype == PKI_DATATYPE_X509_KEYPAIR ) {
				int rv, rv2;

				rv = PKI_TOKEN_del_url(tk, url,
						PKI_DATATYPE_PUBKEY );

				rv2 = PKI_TOKEN_del_url( tk, url,
						PKI_DATATYPE_PRIVKEY );

				if( (rv == PKI_OK) && (rv2 == PKI_OK)) {
					printf("Ok.\n\n");
					exit(0);
				} else {
					printf("Error.\n\n");
					exit(1);
				}
			} else {
				if((PKI_TOKEN_del_url(tk, url, 
						datatype)) == PKI_OK ) {
					printf("Ok.\n\n");
					exit(0);
				} else {
					printf("Error.\n\n");
					exit(1);
				}
			}
		} else {
			printf("\nOperation Cancelled.\n\n");
		}
	} else if ( strncmp_nocase(cmd, "info", 4) == 0 ) {
		printf("\nPrinting Token information (%s):\n\n", 
			token_name ? token_name : "default" );
		PKI_TOKEN_print_info ( tk );

	} else if ( strncmp_nocase(cmd, "list", 4) == 0 ) {
		PKI_TOKEN_STACK *sk = NULL;
		PKI_TOKEN *tk = NULL;

		printf("\nAvailable (configured) Tokens:\n");
		if((sk = PKI_get_all_tokens( config )) == NULL ) {
			printf("- None.\n\n");
			exit(0);
		}

		printf("\nFound %d Tokens:\n", PKI_STACK_elements (sk));

		while( (tk = PKI_STACK_TOKEN_pop ( sk )) != NULL ) {
			printf("- %s (in %s)\n", PKI_TOKEN_get_name ( tk ), 
				PKI_TOKEN_get_config_dir ( tk ) );
			if( tk ) PKI_TOKEN_free ( tk );
		}
		printf("\n");

		if( sk ) PKI_STACK_TOKEN_free ( sk );

	} else if ( strncmp_nocase(cmd, "genkey", 6) == 0 ) {
		PKI_TOKEN_login( tk );
		if((gen_keypair ( tk, bits, param_s, outfile, algor_opt, 
				profile, outform, batch )) == PKI_ERR ) {
			printf("\nERROR, can not create keypair!\n\n");
			exit(1);
		}
	} else if ( strncmp_nocase(cmd, "genreq", 6) == 0 ) {
		/* We need to generate a new keypair first - if the '-newkey'
		   switch is used */

		PKI_TOKEN_login( tk );

		if( newkey ) 
		{
			if (verbose) fprintf(stderr, "Generating KeyPair %s ...", outkey_s);

			if ((gen_keypair(tk, bits, param_s, outkey_s, algor_opt, 
					profile, outform, batch)) == PKI_ERR ) 
			{
				fprintf(stderr, "\nERROR, can not create keypair!\n\n");
				exit(1);
			}
			if ( verbose && batch ) fprintf( stderr, "Ok.\n");

			// Let's assign the new key to the token
			if (PKI_TOKEN_load_keypair(tk, outkey_s) == PKI_ERR)
			{
				fprintf(stderr, "\nERROR, can not load the newly generated keypair!\n\n");
				exit(1);
			}
		}

		if ( algor_opt ) 
		{
			int algor_id;
			PKI_ALGOR *algor = NULL;

			if((algor = PKI_ALGOR_get_by_name ( algor_opt )) == NULL ) {
				PKI_log_err ("Can not set algor to %s", algor_opt);
				return(1);
			}

			algor_id = PKI_ALGOR_get_id (algor);
			if( PKI_TOKEN_set_algor ( tk, algor_id ) == PKI_ERR ) {
				PKI_log_err( "Can not set algor in Token (%d)", algor_id);
				return(1);
			}
		}

		if( !outfile || (strcmp_nocase(outfile, "stdin") == 0)) outfile = "stdout";

		if( !batch ) {
			fprintf(stderr, "\nThis will generate a new request on the "
							"Token.\n");
			fprintf(stderr, "\nDetails:\n");
			fprintf(stderr, "  - Subject ........: %s\n", subject ? 
				subject : "n/a" );
			fprintf(stderr, "  - Algorithm ......: %s\n", 
						PKI_ALGOR_get_parsed( tk->algor ));
			fprintf(stderr, "  - key size .......: %d\n",
				PKI_X509_KEYPAIR_get_size ( tk->keypair ));
			// fprintf(stderr, "  - key URI ........: %s\n", 
			// 	URL_get_parsed( tk->keypair->ref ) ?
			// 	URL_get_parsed( tk->keypair->ref ) : outkey_s );
			fprintf(stderr, "  - Output .........: %s\n", outfile );
			fflush(stderr);

			prompt = prompt_str ("\nAre you sure [y/N] ? ");
		}

		if (batch || (strncmp_nocase(prompt, "y", 1 ) == 0))
		{
			if( verbose ) fprintf(stderr, "Generating new request (%s) ... ", 
					subject ? subject : "no subject" );
			fflush(stderr);

			if((PKI_TOKEN_new_req (tk, subject, profile)) == PKI_ERR)
			{
				fprintf(stderr, "ERROR, can not generate a new Request!\n");
				exit(1);
			}

			if( verbose ) fprintf(stderr, "Ok.\n");

			if( outfile ) 
			{
				if (verbose )
				{
					fprintf(stderr, "Writing request to %s ... ", outfile);
					fflush(stderr);
				}

				if((PKI_TOKEN_export_req( tk, outfile,
							PKI_DATA_FORMAT_PEM )) == PKI_ERR )
				{
					fprintf(stderr, "ERROR, can not save req!\n");
					exit(1);
				}

				if (verbose) fprintf(stderr, "Ok.\n");
			}
		}

	} else if ( strncmp_nocase(cmd, "gencert", 7) == 0 ) {

		PKI_TOKEN_login( tk );

		if (signkey)
		{
			if (verbose)
			{
				printf("Loading Keypair (%s) ... ", signkey);
				fflush(stdout);
			}

			if (PKI_TOKEN_load_keypair(tk, signkey) == PKI_ERR)
			{
				printf("\nERROR, can not load key [%s]\n\n", signkey );
				exit(1);
			}
			else
			{
				if( !tk->keypair ) {
					printf("\nERROR, can not load keypair from token config!\n\n");
					exit(1);
				}
				if( verbose ) printf("Ok.\n");
			}
		} 
		else if ( tk->keypair == NULL ) 
		{
			printf("\nERROR, no keypair loaded - check token config!\n\n");
			exit(1);
		}

		if ( signcert ) 
		{
			if (verbose)
			{
				printf("Loading Signing Cert (%s) ... ", signcert);
				fflush(stdout);
			}

			if ((PKI_TOKEN_load_cert( tk, signcert )) == PKI_ERR)
			{
				printf("\nERROR, can not load signing cert "
						"[%s]\n\n", signcert );
				exit(1);
			}
		}
		else if ((tk->cert == NULL) && (!selfsign))
		{
				fprintf(stderr, "ERROR, no signing cert provided!\n");
				exit ( 1 );
		}

		if (verbose) printf("* Generating a new Certificate:\n");

		if ( !infile ) 
		{
			printf("\nERROR, '-in <req>' is required!\n\n");
			exit(1);
		}

		if( PKI_TOKEN_load_req ( tk, infile ) == PKI_ERR )
		{
			printf("\nERROR, can not load request %s!\n\n", infile);
			return ( 1 );
		}

		if ( algor_opt ) 
		{
			int algor_id;
			PKI_ALGOR *algor = NULL;

			if((algor = PKI_ALGOR_get_by_name ( algor_opt )) == NULL ) {
				PKI_log_err ("Can not set algor to %s", algor_opt);
				return(1);
			}

			algor_id = PKI_ALGOR_get_id (algor);
			if( PKI_TOKEN_set_algor ( tk, algor_id ) == PKI_ERR ) {
				PKI_log_err( "Can not set algor in Token (%d)", algor_id);
				return(1);
			}
		}

		if ( selfsign == 1 ) {
			if ( verbose ) printf ("  - Self Signing "
							"certificate .... ");
			if((PKI_TOKEN_self_sign( tk, subject, serial, 
					validity, profile )) == PKI_ERR ) {
				printf("ERROR, can not self sign certificate!\n");
				return(1);
			}
			if ( verbose ) printf("Ok.\n");

			if(verbose) {
				printf("  - Writing Certificate to (%s)... ",
								outfile );
				fflush(stdout);
			};

			if ( outfile == NULL ) {
				if((outfile = tk->cert_id) == NULL ) {
					if(tk->config) {
						if((outfile = PKI_CONFIG_get_value(tk->config, 
						"/tokenConfig/cert")) == NULL) {
							outfile = "stdout";
						};
					};
				};
			};

			if((PKI_TOKEN_export_cert( tk, outfile,
					PKI_DATA_FORMAT_PEM )) == PKI_ERR ) {
				printf("ERROR,can not save cert in "
							"certificate.pem!\n");
				return(1);
			}
			if ( verbose ) printf("Ok.\n");
		} else {
			PKI_X509_CERT * x = NULL;

			if(verbose ) printf("  - Issuing new certificate ... ");
			fflush(stdout);

			if( tk->cert == NULL ) {
				printf("ERROR, the token has no usable "
						"(signing) certificate!\n");
				if( tk ) PKI_TOKEN_free (tk);
				return ( 1 );
			}

			if((x = PKI_TOKEN_issue_cert( tk, subject, serial, 
					validity, tk->req, profile)) == NULL ) {
				printf("ERROR, can not issue certificate!\n\n");
				fflush(stdout);
				if ( tk ) PKI_TOKEN_free ( tk );
				return (1);
			}
			if(verbose) printf("Ok.\n");

			if ( !outfile ) outfile = "stdout";

			if(verbose) {
				printf("  - Writing Certificate to (%s)... ", outfile );
				fflush(stdout);
			};

			if((PKI_X509_CERT_put ( x, PKI_DATA_FORMAT_PEM, 
				outfile, NULL, tk->cred, tk->hsm)) == PKI_ERR) {
				printf("ERROR, can not save cert in "
						"%s\n", outfile );
				return(1);
			}
			if ( verbose ) printf("Ok.\n");
		}
	} else if ( strncmp_nocase(cmd, "gencrl", 6) == 0 ) {
		PKI_X509_CRL *crl = NULL;
		int ret = PKI_OK;

		if( !tk->keypair ) {
			fprintf(stderr, "ERROR: no SignKey loaded\n\n");
			exit(1);
		}

		if( !tk->cert ) {
			fprintf(stderr, "ERROR: no SignCert loaded\n\n");
			exit(1);
		}

		if ( !outfile ) outfile = "stdout";

		if( verbose ) fprintf(stderr, "Generating new CRL (%s) ... ", outfile );
		fflush(stdout);

		if((crl = PKI_TOKEN_issue_crl( tk, serial, validity, NULL,
				profile )) == NULL) {
			fprintf(stderr, "ERROR: can not generate a new CRL!\n\n");
			exit(1);
		};
		if((ret = PKI_X509_CRL_put ( crl, PKI_DATA_FORMAT_PEM, 
					outfile, NULL, NULL )) != PKI_OK ) {
			fprintf(stderr, "ERROR: can not save crl!\n\n");
			exit(1);
		}
		if( verbose ) printf("Ok.\n");

	} else if ( strncmp_nocase(cmd, "delete", 6) == 0 ) {
		if( uri == NULL ) {
			printf("\nERROR, no '-uri' provided!");
			usage();
		}
	} else if ( strncmp_nocase(cmd, "import", 6) == 0 ) {
		if ( type == NULL ) {
			printf("\nERROR, no <type> provided!");
			usage();
		}

		if( !uri ) {
			printf("ERROR, no '-uri' provided!\n\n");
			return ( 1 );
		}

		if(strncmp_nocase(type, "user", 4) == 0 ) {
			PKI_X509_CERT_STACK * sk = NULL;

			if(verbose) {
				printf("Importing User certificate(s) %s ... ",
						infile );
				fflush ( stdout );
			}


			if((sk = PKI_X509_CERT_STACK_get ( infile, 
						tk->cred, NULL )) == NULL ) {
				printf("ERROR, can not load cert (%s)!\n\n",
						infile );
				return ( 1 );
			}

			if(PKI_TOKEN_import_cert_stack(tk, sk, 
					PKI_DATATYPE_X509_CERT, uri) 
								== PKI_ERR) {
				printf("ERROR!\n\n");
				exit(1);
			};

			if( verbose ) {
				printf("Ok.\n");
			}
		} else if(strncmp_nocase(type, "key", 3) == 0 ) {

			PKI_X509_KEYPAIR *x = NULL;

			if(verbose) {
				printf("Importing key %s ... ",
						infile );
				fflush ( stdout );
			}

			if((x = PKI_X509_KEYPAIR_get ( infile, 
						tk->cred, NULL)) == NULL ) {
				printf("ERROR, can not load keyfile (%s)\n\n",
					infile);
				return ( 1 );
			}

			if(PKI_TOKEN_import_keypair(tk, x, uri) ==PKI_ERR) {
				printf("ERROR!\n\n");
				exit(1);
			};

			printf("Not implemented Yet!\n");

			if( verbose ) {
				printf("Ok.\n");
			}
		} else if(strncmp_nocase(type, "ca", 2) == 0 ) {
			PKI_X509_CERT_STACK *sk = NULL;

			if(verbose) {
				printf("Importing CA certificate(s) %s ... ",
						infile );
				fflush ( stdout );
			}


			if((sk = PKI_X509_CERT_STACK_get ( infile, 
						tk->cred, NULL )) == NULL ) {
				printf("ERROR, can not load cert (%s)!\n\n",
						infile );
				return ( 1 );
			}

			if(PKI_TOKEN_import_cert_stack ( tk, sk, 
					PKI_DATATYPE_X509_CA, uri) 
								== PKI_ERR) {
				printf("ERROR!\n\n");
				exit(1);
			};

			if( verbose ) {
				printf("Ok.\n");
			}
		} else if(strncmp_nocase(type, "trusted", 7) == 0 ) {
			PKI_X509_CERT_STACK *sk = NULL;

			if(verbose) {
				printf("Importing Trusted (TA) certificate(s) "
						"%s ... ", infile );
				fflush ( stdout );
			}


			if((sk = PKI_X509_CERT_STACK_get ( infile, tk->cred, 
							NULL )) == NULL ) {
				printf("ERROR, can not load cert (%s)!\n\n",
						infile );
				return ( 1 );
			}

			if(PKI_TOKEN_import_cert_stack(tk, sk, 
					PKI_DATATYPE_X509_TRUSTED, uri) 
								== PKI_ERR) {
				printf("ERROR!\n\n");
				exit(1);
			};

			if( verbose ) {
				printf("Ok.\n");
			}
		} else if(strncmp_nocase(type, "other", 5) == 0 ) {
			PKI_X509_CERT_STACK *sk = NULL;

			if(verbose) {
				printf("Importing Other certificate(s) "
						"%s ... ", infile );
				fflush ( stdout );
			}


			if((sk = PKI_X509_CERT_STACK_get ( infile, tk->cred, 
							NULL )) == NULL ) {
				printf("ERROR, can not load cert (%s)!\n\n",
						infile );
				return ( 1 );
			}

			if(PKI_TOKEN_import_cert_stack ( tk, sk, 
					PKI_DATATYPE_X509_OTHER, uri) 
								== PKI_ERR) {
				printf("ERROR!\n\n");
				exit(1);
			};

			if( verbose ) {
				printf("Ok.\n");
			}
		} else {
			printf("\nERROR: type '%s' not recognized!\n\n", type);
			usage();
		}
	} else {
		printf("\n  ERROR: command not recognized (%s)\n", cmd );
		usage();
	}

	if(outpubkey_s){
		PKI_MEM *mem = NULL;

		if((mem = PKI_X509_KEYPAIR_get_pubkey(PKI_TOKEN_get_keypair(tk)))==NULL) {
			printf("\n  ERROR: can not get pubkey from Token!\n");
		};

		URL_put_data(outpubkey_s, mem, NULL, NULL, 0, 0, NULL);
	};

	if( outprivkey_s ) {
		PKI_MEM *mem = NULL;

		if((mem = PKI_X509_KEYPAIR_get_privkey(PKI_TOKEN_get_keypair(tk)))==NULL) {
			printf("\n  ERROR: can not get privkey from Token!\n");
		};

		URL_put_data(outprivkey_s, mem, NULL, NULL, 0, 0, NULL);
	};

	if( verbose ) printf("Freeing Token Object ... ");
	fflush(stdout);

	if( prof ) PKI_X509_PROFILE_free ( prof );
	if( tk ) PKI_TOKEN_free ( tk );

	if(verbose) printf("Done.\n\n");

	return (0);

	/*
	printf("Setting Token Algorithm to DSA-SHA1 ... ");
	if((PKI_TOKEN_set_algor ( tk, PKI_ALGOR_DSA_SHA1 )) == PKI_ERR ) {
		printf("ERROR, can not set the DSA-SHA1 crypto scheme!\n");
	}
	printf("Ok.\n");
	*/

	/*
	printf("Setting Token Algorithm to DSA-SHA256 ... ");
	if((PKI_TOKEN_set_algor ( tk, PKI_ALGOR_DSA_SHA256 )) == PKI_ERR ) {
		printf("ERROR, can not set the RSA crypto scheme!\n");
	}
	printf("Ok.\n");

	printf("Setting Token Algorithm to RSA-MD5 ... ");
	if((PKI_TOKEN_set_algor ( tk, PKI_ALGOR_RSA_MD5 )) == PKI_ERR ) {
		printf("ERROR, can not set the RSA crypto scheme!\n");
	}
	printf("Ok.\n");
	*/

	/*
	if((PKI_TOKEN_new_req( tk, "CN=Test4, O=OpenCA", "test" )) == PKI_ERR) {
		printf("ERROR, can not generate a new Request!\n");
		return(0);
	}
	printf("Ok.\n");

	printf("* Writing request to request.pem .... ");
	if((PKI_TOKEN_export_req( tk, "request.pem",
			PKI_DATA_FORMAT_PEM )) == PKI_ERR ) {
		printf("ERROR, can not save req pkcs11_request.pem!\n");
		return(0);
	}
	printf("Ok.\n");
	*/


	/*
	if((PKI_TOKEN_set_scheme ( tk, PKI_SCHEME_RSA )) == PKI_ERR ) {
		printf("ERROR, can not set the RSA crypto scheme!\n");
		return (0);
	}

	if((PKI_TOKEN_set_algor ( tk, PKI_ALGOR_RSA_SHA1 )) == PKI_ERR ) {
		printf("ERROR, can not set the RSA crypto scheme!\n");
		return (0);
	}

	if((PKI_TOKEN_new_keypair ( tk, 1024, NULL )) == PKI_ERR) {
		printf("ERROR, can not generate new keypair!\n");
		return (0);
	}

	printf("* Generating new Request ... ");
	if((PKI_TOKEN_new_req( tk, "CN=Test4, O=OpenCA", "test" )) == PKI_ERR) {
		printf("ERROR, can not generate a new Request!\n");
		return(0);
	}
	printf("Ok.\n");

	printf("* Writing request to results/test4_req1.pem .... ");
	if((PKI_TOKEN_write_req( tk, "results/test4_req1.pem",
			PKI_DATA_FORMAT_PEM )) == PKI_ERR ) {
		printf("ERROR, can not save req results/test4_req1.pem!\n");
		return(0);
	}
	printf("Ok.\n");

	printf("* Self Signing certificate .... ");
	if((PKI_TOKEN_self_sign( tk, NULL, NULL, "Test" )) == PKI_ERR ) {
		printf("ERROR, can not self sign certificate!\n");
		return(0);
	}
	printf("Ok.\n");

	if((PKI_KEYPAIR_export( tk->keypair, NULL, PKI_DATA_FORMAT_PEM, NULL, 
			keyfile,  NULL )) == PKI_ERR ) {
                printf("ERROR::Can not export key (%s)!\n", buf );
                return(0);
        };

	printf("Writing Certificate to file... \n");
	if((PKI_TOKEN_write_cert( tk, "results/test4_cert1.pem",
			PKI_DATA_FORMAT_PEM )) == PKI_ERR ) {
		printf("ERROR,can not save cert in results/test4_cert1.pem!\n");
		return(0);
	}
	*/

}

