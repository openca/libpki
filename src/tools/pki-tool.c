
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
	fprintf(stderr, "(c) 2006-2022 by Massimiliano Pala and OpenCA Labs\n");
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
	fprintf(stderr, "  format          - Converts the format of the input data type\n");
	fprintf(stderr, "  import          - Import an item in the token\n");
	fprintf(stderr, "\n");

	fprintf(stderr, "  Where Options are:\n");
	fprintf(stderr, "  -token          - Name of the token to be used\n");
	fprintf(stderr, "  -config <dir>   - Token config dir (HOME/.libpki/token.d)\n");
	fprintf(stderr, "  -hsm <name>     - HSM name (HOME/.libpki/hsm.d)\n");
	fprintf(stderr, "  -in <url>       - Input Data URI\n");
	fprintf(stderr, "  -out <url>      - Output Data URI\n");
	fprintf(stderr, "  -outform <OPT>  - Output Format (i.e., PEM, DER, TXT, XML)\n");
	fprintf(stderr, "  -bits <num>     - Number of Bits\n");
	fprintf(stderr, "  -type <objtype> - Type of Object\n");
	fprintf(stderr, "  -algor <name>   - Algorithm to be used (e.g., RSA, Falcon, etc.)\n");
	fprintf(stderr, "  -digest <name>  - Digest Algorithm to be used (e.g., sha256, shake128, null, etc.)\n");
#ifdef ENABLE_COMPOSITE
	fprintf(stderr, "  -addkey <file>  - Key to be added to a composite key\n");
#endif
	fprintf(stderr, "  -newkey         - Generate new keypair when using genreq\n");
	fprintf(stderr, "  -outkey <URI>   - URI where to store the new key\n");
	fprintf(stderr, "  -uri <uri>      - URI of the item (key/cert/..) in the token\n");
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
#if OPENSSL_VERSION_NUMBER >= 0x1010000f
	curves = OPENSSL_malloc(sizeof(EC_builtin_curve) * num_curves);
#else
	curves = OPENSSL_malloc(sizeof(EC_builtin_curve) * (int)num_curves);
#endif

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

int add_comp_stack(PKI_KEYPARAMS * kp, char * url, PKI_CRED * cred, HSM * hsm) {

#ifdef ENABLE_COMPOSITE

	PKI_X509_KEYPAIR_STACK * tmp_stack = NULL;
	PKI_X509_KEYPAIR * tmp_key = NULL;

	if (!kp || !url) {
		PKI_DEBUG("ERROR: Missing Key Parameter (%p) or URL (%p)", kp, url);
		return 0;
	}

	if (!PKI_SCHEME_ID_supports_multiple_components(kp->scheme)

// 	if (kp->scheme != PKI_SCHEME_COMPOSITE
// 	    && kp->scheme != PKI_SCHEME_COMPOSITE_DILITHIUM3_RSA
// 	    && kp->scheme != PKI_SCHEME_COMPOSITE_DILITHIUM3_P256
// 	    && kp->scheme != PKI_SCHEME_COMPOSITE_DILITHIUM3_BRAINPOOL256
// 	    && kp->scheme != PKI_SCHEME_COMPOSITE_DILITHIUM3_ED25519
// 	    && kp->scheme != PKI_SCHEME_COMPOSITE_DILITHIUM5_P384
// 	    && kp->scheme != PKI_SCHEME_COMPOSITE_DILITHIUM5_BRAINPOOL384
// 	    && kp->scheme != PKI_SCHEME_COMPOSITE_DILITHIUM5_ED448
// 	    && kp->scheme != PKI_SCHEME_COMPOSITE_FALCON512_P256
// 	    && kp->scheme != PKI_SCHEME_COMPOSITE_FALCON512_BRAINPOOL256
// 	    && kp->scheme != PKI_SCHEME_COMPOSITE_FALCON512_ED25519
// 	    && kp->scheme != PKI_SCHEME_COMPOSITE_SPHINCS256_P256
// 	    && kp->scheme != PKI_SCHEME_COMPOSITE_SPHINCS256_BRAINPOOL256
// 	    && kp->scheme != PKI_SCHEME_COMPOSITE_SPHINCS256_ED25519
// 	    && kp->scheme != PKI_SCHEME_COMPOSITE_FALCON512_RSA
// 	    && kp->scheme != PKI_SCHEME_COMPOSITE_DILITHIUM5_FALCON1024_P521
// 	    && kp->scheme != PKI_SCHEME_COMPOSITE_DILITHIUM5_FALCON1024_RSA
// #ifdef ENABLE_COMBINED
// 		&& kp->scheme != PKI_SCHEME_COMBINED
// #endif
		) {
		PKI_DEBUG("ERROR while adding a component key to a non-composite algorithm (%d)", kp->scheme);
		return 0;
	}

	// Debugging Info
	PKI_DEBUG("Loading Key from %s", url);

	if ((tmp_stack = PKI_X509_KEYPAIR_STACK_get(url, 
						PKI_DATA_FORMAT_UNKNOWN, cred, hsm)) == NULL) {
		// Nothing was loaded
		PKI_DEBUG("Cannot load or retrieve the key (URL: %s)", url);
		return 0;
	}

	while ((tmp_key = PKI_STACK_X509_KEYPAIR_pop(tmp_stack)) != NULL) {
		if (PKI_KEYPARAMS_add_key(kp, tmp_key) != PKI_OK) {
			PKI_STACK_X509_KEYPAIR_free_all(tmp_stack);
			PKI_log_err("ERROR: Cannot add keys from %s", url);
			return 0;
		}
	}

	PKI_STACK_X509_KEYPAIR_free(tmp_stack);

	// All Done
	return 1;

#else

	// Not Supported
	return 0;

#endif

}

int gen_keypair ( PKI_TOKEN *tk, int bits, char *param_s,
		char *url_s, char *algor_opt, char *profile_s, PKI_DATA_FORMAT outFormVal, 
		char *comp_keys[], int comp_keys_num, int batch ) {

	char *prompt = NULL;
	// int outFormVal = PKI_DATA_FORMAT_PEM;

	URL *keyurl = NULL;

	PKI_KEYPARAMS *kp = NULL;
	PKI_X509_PROFILE *prof = NULL;

	PKI_SCHEME_ID scheme = PKI_SCHEME_UNKNOWN;

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

	// Output can not write to stdin, so, if that was specified, 
	// let's re-route to stdout instead
	if (!url_s || strcmp_nocase(url_s, "stdin") == 0) url_s = "stdout";
	// PKI_log_debug("Output URL: %s", url_s);

	keyurl = URL_new( url_s );

	if (keyurl == NULL)
	{
		fprintf(stderr, "\nERROR: can not parse URL [%s]\n\n", url_s );
		exit(1);
	}

	// Let's get the algor options from the ENV if not set
	if (!algor_opt) algor_opt = PKI_get_env("PKI_TOKEN_ALGORITHM");

	// Checks for the supported schemes
	if (algor_opt) {
		if ((scheme = PKI_X509_ALGOR_VALUE_get_scheme_by_txt(algor_opt)) == PKI_SCHEME_UNKNOWN) {
			fprintf(stderr, "\nERROR: Scheme not supported for key generation (%s)\n\n",
				algor_opt);
			exit(1);
		}
	}

	// If specified, search the profile among the ones already loaded
	if (profile_s) prof = PKI_TOKEN_search_profile( tk, profile_s );

	// Sanity Check
	if (profile_s && !prof) {
		PKI_log_debug("Detected Issue: profile %s was selected, but could not be found!");
		exit(1);
	}

	// Let's now generate the new key parameters
	if ((kp = PKI_KEYPARAMS_new(scheme, prof)) == NULL)
	{
		fprintf(stderr, "\n    ERROR, can not create KEYPARAMS object (scheme %d)!\n\n", scheme);
		exit(1);
	}

	// Updates the bits
	if (bits <= 0 && kp->bits > 0) bits = kp->bits;

	// Checks that the bits value is not negative (at least!)
	if (PKI_KEYPARAMS_set_bits(kp, bits) != PKI_OK) {
		fprintf(stderr, "\n    ERROR, requested security bits (%d) are higher than provided in this scheme (scheme: %s, bits: %d)\n\n",
			bits, PKI_SCHEME_ID_get_parsed(scheme), kp->bits);
		exit(1);
	}

#ifdef ENABLE_OQS
	PKI_DEBUG("Key Parameters Generated: scheme %d (bits: %d)", scheme, bits);
#endif

	// Checks for Parameters for Key Generation
	if (param_s != NULL) {

		switch ( kp->scheme )
		{
			// case PKI_SCHEME_RSA:
			// case PKI_SCHEME_DSA:
			// 	// No parameters to set
			// 	break;

			// case PKI_SCHEME_RSAPSS: {
			// 	// Shall we set the parameters?
			// } break;

			// case PKI_SCHEME_DH: {
			// 	// No parameters to set
			// } break;

#ifdef ENABLE_ECDSA
			case PKI_SCHEME_ECDSA:
				// ECDSA Scheme - allow for curve:<name> param
				if (strncmp_nocase( param_s, "curve:", 6) == 0 ) {
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
						}
					} else {
						usage_curves( curveName );
					}
				}
				break;
#endif

// #ifdef ENABLE_OQS
// 			// Post Quantum Digital Signature Switches
// 			case PKI_SCHEME_FALCON:
// 			case PKI_SCHEME_PICNIC:
// 			case PKI_SCHEME_SPHINCS:
// 			case PKI_SCHEME_DILITHIUM: {
// 				// No parameters to set
// 			} break;

// 			// Experimental
// 			case PKI_SCHEME_DILITHIUMX3:{
// 				// No parameters to set
// 			} break;

// #ifdef ENABLE_COMPOSITE
// 			// Generic Composite Crypto Combinations
// 			case PKI_SCHEME_COMPOSITE:

// 			// Explicit Composite Crypto Combinations
// 			case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_RSA:
// 			case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_P256:
// 			case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_BRAINPOOL256:
// 			case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_ED25519:
// 			case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSA:
// 			case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSAPSS:
// 			case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_P256:
// 			case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_BRAINPOOL256:
// 			case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_ED25519:
// 			case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_P384:
// 			case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_BRAINPOOL384:
// 			case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_ED448:
// 			case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_P521:
// 			case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_RSA: {
// 				// No parameters to set
// 			} break;
// #endif

// #ifdef ENABLE_COMBINED
// 			case PKI_SCHEME_COMBINED:{
// 				// No parameters to set
// 			} break;
// #endif

// 			// KEMs
// 			case PKI_SCHEME_NTRU_PRIME:
// 			case PKI_SCHEME_BIKE:
// 			case PKI_SCHEME_FRODOKEM:
// 			case PKI_SCHEME_CLASSIC_MCELIECE:
// 			case PKI_SCHEME_KYBER: {
// 				// No parameters to set
// 			} break;

// 			case PKI_SCHEME_UNKNOWN: {
// 				PKI_ERROR(PKI_ERR_ALGOR_UNKNOWN, NULL);
// 				return PKI_ERR;
// 			} break;
// #endif

			default: {
				fprintf(stderr, "ERROR: Scheme not supported (%d)\n\n", kp->scheme);
				return PKI_ERR;
			}
		}
	}

	if (PKI_SCHEME_ID_supports_multiple_components(kp->scheme)

// #ifdef ENABLE_COMPOSITE

// 	if (kp->scheme == PKI_SCHEME_COMPOSITE
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSA
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSAPSS
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_P256
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_BRAINPOOL256
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_ED25519
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_P384
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_BRAINPOOL384
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_ED448
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_P256
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_BRAINPOOL256
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_ED25519
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_EXPLICIT_SPHINCS256_P256
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_EXPLICIT_SPHINCS256_BRAINPOOL256
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_EXPLICIT_SPHINCS256_ED25519
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_P521
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_RSA
// #ifdef ENABLE_COMBINED
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_OR
// #endif
											) {

		char * url = NULL;
		int i = 0;

		PKI_DEBUG("Multiple Key Components Scheme Detected");

		while ((url = comp_keys[i]) != NULL) {

			if (verbose) {
				PKI_DEBUG("Loading key component [%s]", url);
			}
					
			if (0 == add_comp_stack(kp, url, tk->cred, tk->hsm)) {
				PKI_DEBUG("ERROR: Cannot add key component (%s)", url);
				return PKI_ERR;
			}

			// Move the Index
			if (i < comp_keys_num) {
				 i++;
			} else { 
				break; 
			}
		}
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
		if (kp->scheme == PKI_SCHEME_ECDSA) {
			fprintf(stderr, "  - Point Type .....: %d\n", kp->ec.form );
		}
#endif

#ifdef ENABLE_COMPOSITE
	if (PKI_SCHEME_ID_supports_multiple_components(kp->scheme)
// 	if (   kp->scheme == PKI_SCHEME_COMPOSITE
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_DILITHIUM3_RSA
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_DILITHIUM3_P256
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_DILITHIUM3_BRAINPOOL256
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_DILITHIUM3_ED25519
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_DILITHIUM5_P384
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_DILITHIUM5_BRAINPOOL384
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_DILITHIUM5_ED448
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_SPHINCS256_P256
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_SPHINCS256_BRAINPOOL256
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_SPHINCS256_ED25519
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_FALCON512_P256
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_FALCON512_BRAINPOOL256
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_FALCON512_ED25519
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_DILITHIUM5_FALCON1024_P521
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_DILITHIUM5_FALCON1024_RSA
// #ifdef ENABLE_COMBINED
// 		|| kp->scheme == PKI_SCHEME_COMPOSITE_OR
// #endif
	 ) {
		fprintf(stderr, "  - Number of Keys..: %d\n", 
			PKI_STACK_X509_KEYPAIR_elements(kp->comp.k_stack) );
	}
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

		if((PKI_TOKEN_new_keypair_url_ex (tk, kp, keyurl, profile_s)) == PKI_ERR)
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
				ret = PKI_TOKEN_export_keypair( tk, tmp_s, (PKI_DATA_FORMAT)outFormVal );
			}
			else
			{
				if((tmp_s = tk->key_id ) == NULL) tmp_s = "stdout";

				if (verbose)
				{
					fprintf( stderr, "%s ... ", tmp_s );
					fflush(stderr);
				}

				ret = PKI_TOKEN_export_keypair( tk, tmp_s, (PKI_DATA_FORMAT)outFormVal);
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

int set_token_algorithm(PKI_TOKEN * tk, const char * algor_opt, const char * digest_opt) {

	PKI_DIGEST_ALG * digest = NULL;
		// Requested Digest Algorithm

	int sig_alg = -1;
		// Signature Algorithm ID

	if ( algor_opt ) {
		
		int algor_id = PKI_ID_UNKNOWN;
		PKI_X509_ALGOR_VALUE *algor = NULL;

		// Retrieves the Algorithm By Name
		algor = PKI_X509_ALGOR_VALUE_get_by_name(algor_opt);
		if (algor == NULL) {
			PKI_log_err("Cannot parse the algorithm for the token");
			return PKI_ERR;
		}
		// Retrieves the ID of the algorithm
		algor_id = PKI_X509_ALGOR_VALUE_get_id (algor);
		if (algor_id == PKI_ID_UNKNOWN) {
			PKI_ERROR(PKI_ERR_ALGOR_UNKNOWN, NULL);
			return PKI_ERR;
		}
		// Sets the Token's Algorithm
		if (PKI_TOKEN_set_algor(tk, algor_id) == PKI_ERR) {
			PKI_log_err( "Can not set algor in Token (%d)", algor_id);
			return PKI_ERR;
		}

	}
	
	if (digest_opt) {

		// Checks for the NO-HASH (null) digest option
		if (strncasecmp(digest_opt, "null", 4) == 0 ||
		    strncasecmp(digest_opt, "no", 2) == 0) {
			// Uses the NULL digest method to indicate we
			// do not need the digest. NULL is used to
			// indicated there is no preference, use the
			// default hash algorithm instead.
			digest = PKI_DIGEST_ALG_NULL;
		} else {
			// Retrieves the Digest from the provided name
			digest = (PKI_DIGEST_ALG *) PKI_DIGEST_ALG_get_by_name(digest_opt);
		}

		if (digest == NULL) {
			PKI_log_err("Cannot parse digest %s", digest_opt);
			return PKI_ERR;
		}

	} else {

		// Use the default algorithm if NULL was used
		digest = PKI_DIGEST_ALG_DEFAULT;
	}

	// Assigns the digest algorithm to the token
	tk->digest = digest;

	// Updates the algorithm
	if (tk->keypair != NULL && algor_opt == NULL) {

		PKI_X509_KEYPAIR_VALUE * p_val = PKI_X509_get_value(tk->keypair);
			// Internal Value

		if (digest != EVP_md_null()) {
			// Gest the Signature ID for the digest/pkey combination
			if (!OBJ_find_sigid_by_algs(&sig_alg, EVP_MD_nid(digest), EVP_PKEY_id(p_val))) {
				PKI_log_err("No available combined digest/pkey algorithm for (%d/%d)",
					EVP_MD_nid(digest), EVP_PKEY_id(p_val));
				return PKI_ERR;
			}
			// Let's update the token's algorithm, if any
			if (sig_alg != PKI_ID_UNKNOWN) {
				PKI_TOKEN_set_algor(tk, sig_alg);
			}
		} else if (digest == EVP_md_null()) {
			// If we do not have a defined one, let's use 
			PKI_TOKEN_set_algor(tk, EVP_PKEY_id(p_val));
		} else {
			// Error Condition
			fprintf(stderr, "\n    ERROR: Cannot set the token algorithm\n\n");
			exit(1);
		}
	}

	// All Done
	return PKI_OK;
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
	PKI_LOG_FLAGS log_debug = 0;
	int batch = 0;

	int bits = 0;
	int token_slot = 0;
	int selfsign = 0;
	int newkey = 0;

	char * algor_opt = NULL;
	char * digest_opt = NULL;
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
	PKI_DATA_FORMAT outFormVal = PKI_DATA_FORMAT_PEM;

	char * outpubkey_s = NULL;
	char * outprivkey_s = NULL;

	int days  = 0;
	int hours = 0;
	int mins  = 0;
	int secs  = 0;

#ifdef ENABLE_COMPOSITE

	char * comp_keys[50] = { 0x0 };
	int comp_keys_num = 0;

#endif

	PKI_init_all();

	unsigned long validity = 0;
	PKI_DATATYPE datatype = PKI_DATATYPE_UNKNOWN;

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
		} else if ( strncmp_nocase("-digest", argv[i], 7 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			digest_opt = argv[i];
#ifdef ENABLE_COMPOSITE
		} else if ( strncmp_nocase("-addkey", argv[i], 6 ) == 0 ) {
			if (argv[i++] == NULL) usage();
			if (comp_keys_num >= sizeof(comp_keys)/sizeof(*comp_keys)) {
				fprintf(stderr, "ERROR: Number of Keys not supported (max %ld)\n\n",
					sizeof(comp_keys)/sizeof(*comp_keys));
				usage();
			}
			comp_keys[comp_keys_num++] = argv[i];
#endif
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
			fprintf(stderr, "\n   ERROR: unknown option '%s', abort.\n\n", argv[i]);
			usage();
		}
	}

	if( verbose ) log_level = PKI_LOG_INFO;
	if( debug ) log_debug |= PKI_LOG_FLAGS_ENABLE_DEBUG;

	validity = (unsigned long) (secs + mins * 60 + 
							hours * 3600 + days * 86400);

	if(( PKI_log_init (PKI_LOG_TYPE_STDERR, log_level, NULL,
                        log_debug, NULL )) == PKI_ERR ) {
		exit(1);
	}

	if (!infile) infile = "stdin";

	if((tk = PKI_TOKEN_new_null()) == NULL ) {
		printf("ERROR, can not allocate token!\n\n");
		exit(1);
	}

	if (verbose) {
		printf("Loading Token .. ");
		fflush( stdout );
	}

	if ((PKI_TOKEN_init(tk, config, token_name)) == PKI_ERR) {
		printf("ERROR, can not load token (enable debug for "
							"details)!\n\n");
		exit(1);
	}

	if (verbose) printf("Ok.\n");

	if (batch) {
		PKI_TOKEN_cred_set_cb ( tk, NULL, NULL );
	}

	if (outform) {
		if (strcmp_nocase( outform, "pem") == 0 ) {
			outFormVal = PKI_DATA_FORMAT_PEM;
		} else if ( strcmp_nocase( outform, "der") == 0 ) {
			outFormVal = PKI_DATA_FORMAT_ASN1;
	  } else if ( strcmp_nocase( outform, "txt") == 0 ) {
		  outFormVal = PKI_DATA_FORMAT_TXT;
		} else if ( strcmp_nocase( outform, "xml") == 0 ) {
			outFormVal = PKI_DATA_FORMAT_XML;
		} else {
			fprintf(stderr, "\n    ERROR: out format %s not supported!\n\n", outform);
			exit(1);
		}
	}

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

			tk->type = (int) tk->hsm->type;
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

			// If we are generating a REQ, we can use the
			// signcert as the CA cert to provide the needed
			// info for, for example, the authorityKeyIdentifier

			if ( strncmp_nocase("genreq", cmd, 6) == 0 ) {
				// Loads the CA certificate via the signing cert
				// to calculate the value of certain extensions
				if ((PKI_TOKEN_load_cacert(tk, signcert)) == PKI_ERR) {
					fprintf(stderr, "ERROR, cannot add the signcert as the CA cert (%s)", signcert);
					exit(1);
				}

			} else {
				
				// Loads the Certificate as the user certificate
				// for generic signing operations
				if((PKI_TOKEN_load_cert( tk, signcert )) == PKI_ERR) {
						fprintf(stderr, "ERROR: Can not load signcert (%s)\n\n",
							signcert );
						exit(1);
				}
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

	if (!batch) {
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

		PKI_DEBUG("Profile Added to Token: Ok.");
	};

	if ( strncmp_nocase("version", cmd, 3) == 0 ) {
					
					// ------------
					// CMD: version
					// ------------
					
		version();

	} else if( strncmp( cmd, "clear", 5) == 0 ) {

					// ----------
					// CMD: clear
					// ----------

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

					// -----------
					// CMD: delete
					// -----------
					
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

					// ---------
					// CMD: info
					// ---------

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

					// -----------
					// CMD: genkey
					// -----------

		// Logs into the token
		PKI_TOKEN_login( tk );

		// Algor Option (default)
		if (!algor_opt) {
			algor_opt = "RSA";
			if (bits < 128) bits = 128;
		// RSA Option
		} else if (strncmp_nocase(algor_opt, "RSA", 3) == 0) {
			algor_opt = "RSA";
			if (bits < 128) bits = 128;
		// EC Option
		} else if (strncmp_nocase(algor_opt, "EC", 2) == 0) {
			algor_opt = "EC";
			if (bits < 128) bits = 128;
		// DSA
		} else if (strncmp_nocase(algor_opt, "DSA", 3) == 0) {
			algor_opt = "DSA";
			if (bits < 128) bits = 128;
		} else if (strncmp_nocase(algor_opt, "DILITHIUMX3", 11) == 0
				   && strlen(algor_opt) == strlen("DILITHIUMX3")) {
			algor_opt = "DILITHIUMX3";
			if (bits < 192) bits = 192;
		} else if (strncmp_nocase(algor_opt, "DILITHIUM2", 10) == 0
				   && strlen(algor_opt) == strlen("DILITHIUM2")) {
			algor_opt = "Dilithium2";
			if (bits < 128) bits = 128;
		} else if (strncmp_nocase(algor_opt, "DILITHIUM3", 10) == 0
				   && strlen(algor_opt) == strlen("DILITHIUM3")) {
			algor_opt = "Dilithium3";
			if (bits < 192) bits = 192;
		} else if (strncmp_nocase(algor_opt, "DILITHIUM5", 10) == 0
				   && strlen(algor_opt) == strlen("DILITHIUM5")) {
			algor_opt = "Dilithium5";
			if (bits < 256) bits = 256;
		} else if (strncmp_nocase(algor_opt, "DILITHIUM", 10) == 0
				   && strlen(algor_opt) == strlen("DILITHIUM")) {
			// Default option for Dilithium
			algor_opt = "Dilithium2";
			if (bits < 128) bits = 128;
		} else if (strncmp_nocase(algor_opt, "FALCON512", 9) == 0
				   && strlen(algor_opt) == strlen("FALCON512")) {
			algor_opt = "FALCON512";
			if (bits < 128) bits = 128;
		} else if (strncmp_nocase(algor_opt, "FALCON1024", 10) == 0
				   && strlen(algor_opt) == strlen("FALCON1024")) {
			algor_opt = "FALCON1024";
			if (bits < 256) bits = 256;
		} else if (strncmp_nocase(algor_opt, "FALCON", 7) == 0
				   && strlen(algor_opt) == strlen("FALCON")) {
			// Default option for Falcon
			algor_opt = "FALCON512";
			if (bits < 128) bits = 128;
		// Explicit Composite - DILITHIUM3-P256
		} else if (strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_P256_SHA256_OID, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_P256_SHA256_OID)) == 0 ||
 				   strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_P256_SHA256_NAME, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_P256_SHA256_NAME)) == 0 ||
				   strncmp_nocase(algor_opt, "DILITHIUM3-ECDSA", 16) == 0 ||
				   strncmp_nocase(algor_opt, "DILITHIUM3-EC", 13) == 0 ||
				   strncmp_nocase(algor_opt, "DILITHIUM-P256", 14) == 0) {
			algor_opt = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_P256_SHA256_NAME;
		// Explicit Composite - DILITHIUM3-RSA
		} else if (strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_SHA256_OID, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_SHA256_OID)) == 0 ||
				   strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_SHA256_NAME, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_SHA256_NAME)) == 0 ||
				   strncmp_nocase(algor_opt, "DILITHIUM3-RSA", 14) == 0) {
			algor_opt = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_SHA256_NAME;
			if (!digest_opt) digest_opt = "null";
		// Explicit Composite - DILITHIUM3-BRAINPOOL256
		} else if (strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_BRAINPOOL256_SHA256_OID, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_BRAINPOOL256_SHA256_OID)) == 0 || 
				   strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_BRAINPOOL256_SHA256_NAME, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_BRAINPOOL256_SHA256_NAME)) == 0 || 
				   strncmp_nocase(algor_opt, "DILITHIUM3-BRAINPOOL", 20) == 0 ||
				   strncmp_nocase(algor_opt, "DILITHIUM3-B256", 15) == 0) {
			algor_opt = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_BRAINPOOL256_SHA256_NAME;
			if (!digest_opt) digest_opt = "null";
		} else if (strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ED25519_OID, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ED25519_OID)) == 0 || 
				   strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ED25519_NAME, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ED25519_NAME)) == 0 || 
				   strncmp_nocase(algor_opt, "DILITHIUM3-ED25519", 18) == 0 ||
				   strncmp_nocase(algor_opt, "DILITHIUM3-25519", 16) == 0 ||
				   strncmp_nocase(algor_opt, "DILITHIUM3-25519", 16) == 0) {
			algor_opt = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ED25519_NAME;
			if (!digest_opt) digest_opt = "null";
		} else if (strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_P384_SHA384_OID, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_P384_SHA384_OID)) == 0 || 
				   strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_P384_SHA384_NAME, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_P384_SHA384_NAME)) == 0 || 
				   strncmp_nocase(algor_opt, "DILITHIUM5-ECDSA", 16) == 0 ||
				   strncmp_nocase(algor_opt, "DILITHIUM5-EC", 13) == 0 ||
				   strncmp_nocase(algor_opt, "DILITHIUM5-P384", 15) == 0) {
			algor_opt = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_P384_SHA384_NAME;
			if (!digest_opt) digest_opt = "null";
		} else if (strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_BRAINPOOL384_SHA384_OID, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_BRAINPOOL384_SHA384_OID)) == 0 || 
				   strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_BRAINPOOL384_SHA384_NAME, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_BRAINPOOL384_SHA384_NAME)) == 0 || 
				   strncmp_nocase(algor_opt, "DILITHIUM5-BRAINPOOL", 20) == 0 ||
				   strncmp_nocase(algor_opt, "DILITHIUM5-B384", 15) == 0) {
			algor_opt = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_BRAINPOOL384_SHA384_NAME;
			if (!digest_opt) digest_opt = "null";
		} else if (strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_ED448_OID, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_ED448_OID)) == 0 || 
				   strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_ED448_NAME, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_ED448_NAME)) == 0 || 
				   strncmp_nocase(algor_opt, "DILITHIUM5-448", 14) == 0 ||
				   strncmp_nocase(algor_opt, "DILITHIUM-ED448", 15) == 0 ||
				   strncmp_nocase(algor_opt, "DILITHIUM-448", 13) == 0) {
			algor_opt = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_ED448_NAME;
			if (!digest_opt) digest_opt = "null";
		} else if (strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_P256_SHA256_OID, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_P256_SHA256_OID)) == 0 || 
				   strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_P256_SHA256_NAME, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_P256_SHA256_NAME)) == 0 || 
				   strncmp_nocase(algor_opt, "FALCON512-P256", 14) == 0 || 
				   strncmp_nocase(algor_opt, "FALCON-ECDSA", 12) == 0 || 
				   strncmp_nocase(algor_opt, "FALCON-P256", 12) == 0) {
			algor_opt = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_P256_SHA256_NAME;
			if (!digest_opt) digest_opt = "null";
		} else if (strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_BRAINPOOL256_SHA256_OID, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_BRAINPOOL256_SHA256_OID)) == 0 || 
				   strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_BRAINPOOL256_SHA256_NAME, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_BRAINPOOL256_SHA256_NAME)) == 0 || 
				   strncmp_nocase(algor_opt, "FALCON512-BRAINPOOL", 19) == 0 || 
				   strncmp_nocase(algor_opt, "FALCON-BRAINPOOL256", 19) == 0 || 
				   strncmp_nocase(algor_opt, "FALCON-BRAINPOOL", 16) == 0) {
			algor_opt = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_BRAINPOOL256_SHA256_NAME;
			if (!digest_opt) digest_opt = "null";
		} else if (strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_OID, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_OID)) == 0 ||
				   strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_NAME, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_NAME)) == 0 || 
				   strncmp_nocase(algor_opt, "FALCON512-25519", 15) == 0 || 
				   strncmp_nocase(algor_opt, "FALCON-ED25519", 14) == 0 || 
				   strncmp_nocase(algor_opt, "FALCON-25519", 12) == 0) {
			algor_opt = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_NAME;
			if (!digest_opt) digest_opt = "null";
		} else if (strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_P256_SHA256_OID, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_P256_SHA256_OID)) == 0 || 
				   strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_P256_SHA256_NAME, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_P256_SHA256_NAME)) == 0 || 
				   strncmp_nocase(algor_opt, "SPHINCS256-ECDSA", 16) == 0 || 
				   strncmp_nocase(algor_opt, "SPHINCS-ECDSA", 13) == 0 || 
				   strncmp_nocase(algor_opt, "SPHINCS-P256", 12) == 0) {
			algor_opt = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_P256_SHA256_NAME;
			if (!digest_opt) digest_opt = "null";
		} else if (strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_BRAINPOOL256_SHA256_OID, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_BRAINPOOL256_SHA256_OID)) == 0 || 
				   strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_BRAINPOOL256_SHA256_NAME, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_BRAINPOOL256_SHA256_NAME)) == 0 || 
				   strncmp_nocase(algor_opt, "SPHINCS256-BRAINPOOL", 20) == 0 || 
				   strncmp_nocase(algor_opt, "SPHINCS-BRAINPOOL", 17) == 0 || 
				   strncmp_nocase(algor_opt, "SPHINCS-B256", 12) == 0) {
			algor_opt = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_BRAINPOOL256_SHA256_NAME;
			if (!digest_opt) digest_opt = "null";
		} else if (strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_ED25519_OID, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_ED25519_OID)) == 0 || 
				   strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_ED25519_NAME, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_ED25519_NAME)) == 0 || 
				   strncmp_nocase(algor_opt, "SPHINCS256-25519", 16) == 0 || 
				   strncmp_nocase(algor_opt, "SPHINCS-ED25519", 15) == 0 || 
				   strncmp_nocase(algor_opt, "SPHINCS-25519", 13) == 0) {
			algor_opt = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_SPHINCS256_ED25519_NAME;
			if (!digest_opt) digest_opt = "null";
		} else if (strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSAPSS_SHA256_OID, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSAPSS_SHA256_OID)) == 0 || 
				   strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSAPSS_SHA256_NAME, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSAPSS_SHA256_NAME)) == 0 || 
				   strncmp_nocase(algor_opt, "DILITHIUM3-RSAPSS", 17) == 0 || 
				   strncmp_nocase(algor_opt, "DILITHIUM-RSAPSS", 16) == 0) {
			algor_opt = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSAPSS_SHA256_NAME;
			if (!digest_opt) digest_opt = "null";
		} else if (strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_RSA_SHA256_OID, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_RSA_SHA256_OID)) == 0 || 
				   strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_RSA_SHA256_NAME, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_RSA_SHA256_NAME)) == 0 || 
				   strncmp_nocase(algor_opt, "FALCON-RSA", 10) == 0 ||
				   strncmp_nocase(algor_opt, "FALCON512-RSA", 10) == 0) {
			algor_opt = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_RSA_SHA256_NAME;
			if (!digest_opt) digest_opt = "null";
		// Explicit Composite - DILITHIUM5-FALCON1024-ECDSA-P521
		} else if (strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_P521_SHA512_OID, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_P521_SHA512_OID)) == 0 ||
				   strncmp_nocase(algor_opt, OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_P521_SHA512_NAME, sizeof(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_P521_SHA512_NAME)) == 0 ||
				   strncmp_nocase(algor_opt, "DILITHIUM-FALCON-EC", 19) == 0 ||
				   strncmp_nocase(algor_opt, "DILITHIUM-FALCON-P521", 21) == 0) {
			algor_opt = OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_P521_SHA512_NAME;
			if (!digest_opt) digest_opt = "null";
		} else {
			// This should be a catch all for new algos
			if (debug) fprintf(stderr, "\nUsing Non-Standard Algorithm: %s\n", algor_opt);
		}

		PKI_DEBUG("\nSelected Algorithm: %s\n", algor_opt);

		if ((gen_keypair(tk, 
				 bits,
				 param_s,
				 outfile,
				 algor_opt, 
				 profile,
				 outFormVal,
#ifdef ENABLE_COMPOSITE
				 comp_keys,
				 comp_keys_num,
#else
				 NULL,
				 0,
#endif
				 batch )) == PKI_ERR ) {
			printf("\nERROR, can not create keypair!\n\n");
			exit(1);
		}
	} else if ( strncmp_nocase(cmd, "genreq", 6) == 0 ) {

					// -----------
					// CMD: genreq
					// -----------
					
		/* We need to generate a new keypair first - if the '-newkey'
		   switch is used */

		if (!PKI_TOKEN_login( tk )) {
			fprintf(stderr, "\nERROR, cannot login into the Token!");
			exit(1);
		};

		if (newkey) {

			if (verbose) fprintf(stderr, "Generating KeyPair %s ...", outkey_s);

#ifdef ENABLE_COMPOSITE
			if ((gen_keypair(tk, bits, param_s, outkey_s, algor_opt, 
					profile, outFormVal, comp_keys, comp_keys_num, batch)) == PKI_ERR ) 
			{
				fprintf(stderr, "\nERROR, can not create keypair!\n\n");
				exit(1);
			}
#else
			if ((gen_keypair(tk, bits, param_s, outkey_s, algor_opt, 
					profile, outFormVal, NULL, 0, batch)) == PKI_ERR ) 
			{
				fprintf(stderr, "\nERROR, can not create keypair!\n\n");
				exit(1);
			}
#endif
			if ( verbose && batch ) fprintf( stderr, "Ok.\n");

			// Let's assign the new key to the token
			if (PKI_TOKEN_load_keypair(tk, outkey_s) == PKI_ERR)
			{
				fprintf(stderr, "\nERROR, can not load the newly generated keypair!\n\n");
				exit(1);
			}
		}

		// fprintf(stderr, "DEBUG: algor_opt = %s, digest_opt = %s\n", algor_opt, digest_opt);

		if (PKI_OK != set_token_algorithm(tk, algor_opt, digest_opt)) {
			fprintf(stderr, "\n    ERROR: Cannot set the token's algorithm\n\n");
			exit(1);
		}

		// Sets the Outfile
		if( !outfile || (strcmp_nocase(outfile, "stdin") == 0)) outfile = "stdout";

		if( !batch ) {
			fprintf(stderr, "\nThis will generate a new request on the "
							"Token.\n");
			fprintf(stderr, "\nDetails:\n");
			fprintf(stderr, "  - Subject ........: %s\n", subject ? 
				subject : "n/a" );
			fprintf(stderr, "  - Algorithm ......: %s\n", 
						PKI_X509_ALGOR_VALUE_get_parsed( tk->algor ));
			fprintf(stderr, "  - Digest .........: %s\n", 
						(tk->digest && tk->digest != EVP_md_null() ? PKI_DIGEST_ALG_get_parsed(tk->digest) : "none" ));
			fprintf(stderr, "  - key size .......: %d\n",
				PKI_X509_KEYPAIR_get_size ( tk->keypair ));
			fprintf(stderr, "  - Output .........: %s\n", outfile );
			fflush(stderr);

			prompt = prompt_str ("\nAre you sure [y/N] ? ");
		}

		if (batch || (strncmp_nocase(prompt, "y", 1 ) == 0))
		{
			if (verbose) fprintf(stderr, "Generating new request (%s) ... ", 
					subject ? subject : "no subject" );
			fflush(stderr);

			if ((PKI_TOKEN_new_req(tk, subject, profile)) == PKI_ERR)
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
							(PKI_DATA_FORMAT)outFormVal )) == PKI_ERR )
				{
					fprintf(stderr, "ERROR, can not save req!\n");
					exit(1);
				}

				if (verbose) fprintf(stderr, "Ok.\n");
			}
		}

	} else if ( strncmp_nocase(cmd, "gencert", 7) == 0 ) {

					// ------------
					// CMD: version
					// ------------
					
		// PKI_TOKEN_login( tk );

		if (!PKI_TOKEN_login( tk )) {
			fprintf(stderr, "\nERROR, cannot login into the Token!");
			exit(1);
		}

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

		if (!infile) 
		{
			printf("\nERROR, '-in <req>' is required!\n\n");
			exit(1);
		}

		if (PKI_TOKEN_load_req ( tk, infile ) == PKI_ERR)
		{
			printf("\nERROR, can not load request %s!\n\n", infile);
			return ( 1 );
		}

		if (PKI_OK != set_token_algorithm(tk, algor_opt, digest_opt)) {
			fprintf(stderr, "\n    ERROR: Cannot set the token's algorithm\n\n");
			exit(1);
		}

		if ( selfsign == 1 ) {
			if (verbose) printf("  - Self Signing "
							"certificate .... ");
			if ((PKI_TOKEN_self_sign(tk, subject, serial, 
						validity, profile )) == PKI_ERR ) {
				printf("ERROR, can not self sign certificate!\n");
				return(1);
			}

			if (verbose) printf("Ok.\n");

			if(verbose) {
				printf("  - Writing Certificate to (%s)... ",
								outfile );
				fflush(stdout);
			}

			if (outfile == NULL) {
				if ((outfile = tk->cert_id) == NULL ) {
					if (tk->config) {
						if ((outfile = PKI_CONFIG_get_value(tk->config, 
								"/tokenConfig/cert")) == NULL) {
							outfile = "stdout";
						}
					} else {
						outfile = "stdout";
					}
				}
			}

			if ((PKI_TOKEN_export_cert( tk, outfile, outFormVal )) == PKI_ERR ) {
				printf("ERROR,can not save cert in '%s'\n", outfile);
				return(1);
			}

			if (verbose) printf("Ok.\n");

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

			if ((PKI_X509_CERT_put(x, outFormVal, outfile, NULL, tk->cred, tk->hsm)) == PKI_ERR) {
				printf("ERROR, can not save cert in %s\n", outfile );
				return(1);
			}

			if ( verbose ) printf("Ok.\n");

		}

	} else if ( strncmp_nocase(cmd, "gencrl", 6) == 0 ) {

					// -----------
					// CMD: gencrl
					// -----------
					
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

		long long thisUpdate = 0;
		long long nextUpdate = (long long) validity;
		if ((crl = PKI_TOKEN_issue_crl(tk,
									   serial,
									   thisUpdate,
									   nextUpdate,
									   NULL,
									   NULL,
									   profile )) == NULL) {
			fprintf(stderr, "\n    ERROR: can not generate a new CRL!\n\n");
			exit(1);
		}

		if((ret = PKI_X509_CRL_put(crl, 
								   outFormVal, 
								   outfile,
								   NULL,
								   NULL)) != PKI_OK ) {
			fprintf(stderr, "\n    ERROR: can not save crl!\n\n");
			exit(1);
		}

		if (verbose) printf("Ok.\n");


	} else if ( strncmp_nocase(cmd, "delete", 6) == 0 ) {

					// -----------
					// CMD: delete
					// -----------

		if( uri == NULL ) {
			printf("\nERROR, no '-uri' provided!");
			usage();
		}

	} else if ( strncmp_nocase(cmd, "import", 6) == 0 ) {

					// -----------
					// CMD: import
					// -----------

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
						PKI_DATA_FORMAT_UNKNOWN, tk->cred, NULL )) == NULL ) {
				printf("ERROR, can not load cert (%s)!\n\n",
						infile );
				return ( 1 );
			}

			if(PKI_TOKEN_import_cert_stack(tk, sk, 
				PKI_DATATYPE_X509_CERT, uri) == PKI_ERR) {
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
						PKI_DATA_FORMAT_UNKNOWN, tk->cred, NULL)) == NULL ) {
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
						PKI_DATA_FORMAT_UNKNOWN, tk->cred, NULL )) == NULL ) {
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


			if((sk = PKI_X509_CERT_STACK_get ( infile, PKI_DATA_FORMAT_UNKNOWN,
							tk->cred, NULL )) == NULL ) {
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


			if((sk = PKI_X509_CERT_STACK_get ( infile, PKI_DATA_FORMAT_UNKNOWN,
							tk->cred, NULL )) == NULL ) {
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

	} else if ( strncmp_nocase(cmd, "convert", 7) == 0 ) {

					// ------------
					// CMD: convert
					// ------------

		PKI_X509 * obj = NULL;

		if (!infile) {
			fprintf(stderr, "\nERROR, '-in <x509_data>' is required!\n\n");
			usage();
		}

		// Verbose
		if (verbose) printf("* Converting X509 data to %s:\n", outform);

		// Verbose
		if (verbose) printf("  - Loading input file (%s) ... : ", infile);

		// Tries to load the generic object
		obj = PKI_X509_get(infile, PKI_DATATYPE_ANY, PKI_DATA_FORMAT_UNKNOWN, NULL, NULL);
		if (obj == NULL) {
			if (verbose) printf("ERROR!\n");
			fprintf(stderr, "\n    ERROR: cannot open the input file, aborting.\n\n");
			exit(1);
		}

		// Verbose
		if (verbose) printf("Ok\n");

		// Verbose
		if (verbose) printf ("  - Converting to %s ... : ", outform);
		if (!outfile) outfile = "stdout";

		// Let's generate the output version
		if (PKI_X509_put(obj, outFormVal, outfile, NULL, NULL, NULL) == PKI_ERR) {
			printf("ERROR!\n");
			fprintf(stderr, "\n    ERROR: cannot convert to %s, aborting.\n\n", outform);
			exit(1);
		}

		// Verbose
		if (verbose) printf ("Ok\n\n");

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

}

