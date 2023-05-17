
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
	fprintf(stderr, "  info             - Prints out information about the token\n");
	fprintf(stderr, "  list             - List the names of available tokens\n");
	fprintf(stderr, "  clear            - Deletes all the data on the token\n");
	fprintf(stderr, "  delete           - Deletes objects (use -uri)\n");
	fprintf(stderr, "  genkey           - Generates a new Keypair (def. RSA-SHA1)\n");
	fprintf(stderr, "  genreq           - Generates a new X.509 PKCS#10 request\n");
	fprintf(stderr, "  gencert          - Generates a new X.509 certificate\n");
	fprintf(stderr, "  convert          - Converts the format of the input data type\n");
	fprintf(stderr, "  import           - Import an item in the token\n");
	fprintf(stderr, "\n");

	fprintf(stderr, "  Where Options are:\n");
	fprintf(stderr, "  -token           - Name of the token to be used\n");
	fprintf(stderr, "  -config <dir>    - Token config dir (HOME/.libpki/token.d)\n");
	fprintf(stderr, "  -hsm <name>      - HSM name (HOME/.libpki/hsm.d)\n");
	fprintf(stderr, "  -in <url>        - Input Data URI\n");
	fprintf(stderr, "  -out <url>       - Output Data URI\n");
	fprintf(stderr, "  -pubout <url>    - Saves the SubjectPublicKeyInfo of a cert\n");
	fprintf(stderr, "  -outform <OPT>   - Output Format (i.e., PEM, DER, TXT, XML)\n");
	fprintf(stderr, "  -bits <num>      - Number of Bits\n");
	fprintf(stderr, "  -type <objtype>  - Type of Object\n");
	fprintf(stderr, "  -algor <name>    - Algorithm to be used (e.g., RSA, Falcon, etc.)\n");
	fprintf(stderr, "  -digest <name>   - Digest Algorithm to be used (e.g., sha256, shake128, null, etc.)\n");
#ifdef ENABLE_COMPOSITE
	fprintf(stderr, "  -addkey <file>   - Key to be added to a composite key\n");
	fprintf(stderr, "  -kofn <num>      - Minimum number of required valid component signatures (def. all)\n");
#endif
	fprintf(stderr, "  -newkey          - Generate new keypair when using genreq\n");
	fprintf(stderr, "  -outkey <URI>    - URI where to store the new key\n");
	fprintf(stderr, "  -keyalg <uri>    - Extracts the key AlgorithmIdentifier into URI\n");
	fprintf(stderr, "  -uri <uri>       - URI of the item (key/cert/..) in the token\n");
	fprintf(stderr, "  -signkey <uri>   - URI of the cert-signing key\n");
	fprintf(stderr, "  -signcert <uri>  - URI of the cert-signing cert (CA)\n");
	fprintf(stderr, "  -sigout <uri>    - Extracts the signature bitstream into URI\n");
	fprintf(stderr, "  -sigalg <uri>    - Extracts the signature AlgorithmIdentifier into URI\n");
	fprintf(stderr, "  -subject <dn>    - Distinguished Name (Subject)\n");
	fprintf(stderr, "  -serial <num>    - Serial Number to use (gencert)\n");
	fprintf(stderr, "  -profile <name>  - Profile to use (gencert/genreq)\n");
	fprintf(stderr, "  -profileuri <uri>  - Profile URI to load (gencert/genreq)\n");
	fprintf(stderr, "  -profilesdir <dir> - Directory to scan for profile configs\n");
	fprintf(stderr, "  -oidsuri <uri>   - OID files to load (gencert/genreq)\n");
	fprintf(stderr, "  -days <num>      - Validity period (days)\n");
	fprintf(stderr, "  -hours <num>     - Validity period (hours)\n");
	fprintf(stderr, "  -mins <num>      - Validity period (mins)\n");
	fprintf(stderr, "  -secs <num>      - Validity period (secs)\n");
	fprintf(stderr, "  -selfsign        - Generate a self signed X.509 cert\n");
	fprintf(stderr, "  -batch           - Batch mode (no prompt - assumes yes)\n");
	fprintf(stderr, "  -verbose         - Writes additional info to stdout\n");
	fprintf(stderr, "  -debug           - Enables Debugging info to stderr\n");
	fprintf(stderr, "  -param <par>     - KeyGen param (eg., curve:curvename for EC)\n");
	fprintf(stderr, "  -curves          - Prints out available curve names\n");

	fprintf(stderr, "\n  Where Type of Object can be:\n");
	fprintf(stderr, "   any             - Unknown type\n");
	fprintf(stderr, "   key             - Keypair (Pub and Priv Keys)\n");
	fprintf(stderr, "   pubkey          - Public Key\n");
	fprintf(stderr, "   privkey         - Private Key\n");
	fprintf(stderr, "   user            - User Certificates\n");
	fprintf(stderr, "   ca              - CA Certificates\n");
	fprintf(stderr, "   trusted         - Trusted Certificates (TA)\n");
	fprintf(stderr, "   other           - Other Certificates\n");
	fprintf(stderr, "   crl             - CRL\n");

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
		char *url_s, PKI_SCHEME_ID scheme_id, char *profile_s, PKI_DATA_FORMAT outFormVal, 
#ifdef ENABLE_COMPOSITE
		char *comp_keys[], int comp_keys_num, int comp_kofn,
#endif
		int batch ) {

	char *prompt = NULL;
	// int outFormVal = PKI_DATA_FORMAT_PEM;

	URL *keyurl = NULL;

	PKI_KEYPARAMS *kp = NULL;
	PKI_X509_PROFILE *prof = NULL;

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

	// If specified, search the profile among the ones already loaded
	if (profile_s) prof = PKI_TOKEN_search_profile( tk, profile_s );

	// Sanity Check
	if (profile_s && !prof) {
		PKI_log_debug("Detected Issue: profile %s was selected, but could not be found!");
		exit(1);
	}

	// Let's now generate the new key parameters
	if ((kp = PKI_KEYPARAMS_new(scheme_id, prof)) == NULL) {
		fprintf(stderr, "\n    ERROR, can not create KEYPARAMS object (scheme %d)!\n\n", scheme_id);
		exit(1);
	}

	// Updates the bits (use defaults, if not specified)
	if (bits <= 0 && kp->bits > 0) bits = kp->bits;

	// Checks that the bits value is not negative (at least!)
	if (PKI_KEYPARAMS_bits_set(kp, bits) != PKI_OK) {
		fprintf(stderr, "\n    WARNING, requested bits (%d) are higher than provided in this scheme (scheme: %s, bits: %d)\n\n",
			bits, PKI_SCHEME_ID_get_parsed(scheme_id), kp->bits);
	}

#ifdef ENABLE_COMPOSITE
	PKI_DEBUG("Key Parameters Generated: scheme %d (bits: %d)", scheme_id, bits);
	PKI_DEBUG("Key to be generated is PQC? %s", PKI_SCHEME_ID_is_post_quantum(scheme_id) ? "YES" : "NO");
	PKI_DEBUG("Key to be generated is composite? %s", PKI_SCHEME_ID_is_composite(scheme_id) ? "YES" : "NO");
	PKI_DEBUG("Key to be generated is explicit composite? %s", PKI_SCHEME_ID_is_explicit_composite(scheme_id) ? "YES" : "NO");
	PKI_DEBUG("Parsed Scheme ID is => %s", PKI_SCHEME_ID_get_parsed(scheme_id));
#endif

	// Checks for Parameters for Key Generation
	if (param_s != NULL) {

		switch ( kp->scheme )
		{

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

#ifdef ENABLE_COMPOSITE

			case PKI_SCHEME_COMPOSITE: {

				// Processes the K-of-N parameter option
				if (strncmp_nocase( param_s, "kofn:", 5) == 0 ) {
						// Get the Name of the Curve
						if (sscanf(param_s + 5, "%d", &comp_kofn) < 1) {
								PKI_DEBUG("ERROR: Cannot get kofn from the key param, please use 'kofn:<int>' (%s)", param_s);
								return PKI_ERR;
						}
				}

				// If the parameter is set, then set it in the keyparams
				if (comp_kofn > 0) {
						if (PKI_ERR == PKI_KEYPARAMS_set_kofn(kp, comp_kofn)) {
								PKI_DEBUG("ERROR: Cannot set kofn (%d)", comp_kofn);
								return PKI_ERR;
						}
				}

			} break;

# ifdef ENABLE_OQS

               // Post Quantum Cryptography - Composite Crypto
               case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_P256:
               case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_BRAINPOOL256:
               case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_ED25519:
               case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSA:
               case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_P256:
               case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_ED25519:
               case PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_RSA: 
               case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_P521:
               case PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_RSA: {
                       // Explicit Composite Combinations, nothing to do
                       PKI_DEBUG("Generating components for explicit composite scheme %d", kp->scheme);
                       fprintf(stderr, "\n    ERROR, explicit composite schemes not supported yet!\n\n");
                       return PKI_ERR;
               } break;
# endif
#endif

			default: {
				// Nothing to do here
			}
		}
	}

	// This processes the key components
    if (PKI_SCHEME_ID_is_composite(kp->scheme) || PKI_SCHEME_ID_is_explicit_composite(kp->scheme)) {
        // Adds the components keys

		char * url = NULL;
		int i = 0;

		if (PKI_SCHEME_ID_is_explicit_composite(kp->scheme)) {
			PKI_DEBUG("WARNING: Adding separate components to an explicit composite scheme %d, please make sure the composition is correct.", kp->scheme);
		}

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

	} else if (PKI_SCHEME_ID_is_explicit_composite(kp->scheme)) {
		// anything to do here (?)
	}

	if (!batch)	{

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
	if (PKI_SCHEME_ID_supports_multiple_components(kp->scheme)) {
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
		if (str_cmp_ex(digest_opt, "null", 0, 1) == 0 ||
		    str_cmp_ex(digest_opt, "no", 0, 1) == 0) {
			// Uses the NULL digest method to indicate we
			// do not need the digest. NULL is used to
			// indicated there is no preference, use the
			// default hash algorithm instead.
			digest = PKI_DIGEST_ALG_NULL;
			PKI_DEBUG("Using NULL digest");
		} else {
			// Retrieves the Digest from the provided name
			digest = (PKI_DIGEST_ALG *) PKI_DIGEST_ALG_get_by_name(digest_opt);
			if (!digest) {
				PKI_log_err("Cannot parse digest %s", digest_opt);
				return PKI_ERR;
			}
		}

	} else {

		PKI_X509_KEYPAIR_VALUE * p_val = PKI_X509_get_value(tk->keypair);
			// Internal Value

		int pkey_type = EVP_PKEY_type(EVP_PKEY_id(p_val));
			// Key Type

		// Explicit does not allow for hash-n-sign
		if (PKI_ID_requires_digest(pkey_type) == PKI_OK) {
			// Use the default algorithm if NULL was used
			digest = PKI_DIGEST_ALG_DEFAULT;
		} else {
			// Use the NULL digest method
			digest = PKI_DIGEST_ALG_NULL;
		}
	}

	// Assigns the digest algorithm to the token
	tk->digest = digest;

	// Updates the algorithm
	if (tk->keypair != NULL) {

		PKI_X509_KEYPAIR_VALUE * p_val = PKI_X509_get_value(tk->keypair);
			// Internal Value

		int pkey_type = PKI_X509_KEYPAIR_VALUE_get_id(p_val);
			// Key Type

		// Gets the Signature ID for the digest/pkey combination
		if (!OBJ_find_sigid_by_algs(&sig_alg, EVP_MD_nid(digest), pkey_type)) {

			// Checks for possible fixes
			if (digest == NULL || digest == PKI_DIGEST_ALG_NULL) {
				// If we have a PQC or an explicit composite key, we
				// can use the pkey_type as the signature algorithm
				// if the digest is NULL
				if (PKI_ID_is_pqc(pkey_type, NULL) ||
					PKI_ID_is_composite(pkey_type, NULL) ||
					PKI_ID_is_explicit_composite(pkey_type, NULL)) {
					// If we do not have a defined one, let's use
					// the pkey_type as the signature algorithm
					sig_alg = pkey_type;
				} else {
					// No available algorithm for pkey without digest
					PKI_DEBUG("No available combined digest/pkey algorithm for (digest: %d, pkey_type: %d)",
						EVP_MD_nid(digest), pkey_type);
					return PKI_ERR;
				}
			} else {
				// No available algorithm for pkey/digest combination
				PKI_DEBUG("No available algorithm (%d) for combined digest/pkey algorithm for (digest: %d, pkey_type: %d)",
					sig_alg, EVP_MD_nid(digest), pkey_type);
				return PKI_ERR;
			}
		}

		// Let's update the token's algorithm, if any
		if (sig_alg != PKI_ID_UNKNOWN) {
			// Sets the Token's Algorithm
			PKI_TOKEN_set_algor(tk, sig_alg);

		} else if ((digest == EVP_md_null() || digest == NULL) &&
		           (PKI_ID_is_explicit_composite(pkey_type, NULL) ||
				    PKI_ID_is_pqc(pkey_type, NULL))) {
			// If we do not have a defined one, let's use 
			PKI_TOKEN_set_algor(tk, pkey_type);
		} else {
			// Error Condition
			fprintf(stderr, "\n    ERROR: Cannot set the token algorithm (pkey: %d, md: %d)\n\n",
				pkey_type, EVP_MD_nid(digest));
			exit(1);
		}
	}

	// All Done
	return PKI_OK;
}

int pki_tool_save_object_data(PKI_X509 * obj, const char * uri, PKI_X509_DATA type) {

	PKI_MEM * out_mem = NULL;
		// Output Buffer

	PKI_X509_ALGOR_VALUE * val = NULL;
		// Internal Value

	ASN1_BIT_STRING * data = NULL;
		// Pointer to the Signature ASN1_BIT_STRING type

	PKI_DATATYPE obj_type = PKI_DATATYPE_UNKNOWN;
		// Type of object that was passed

	// Input Checks
	if (!obj) return PKI_ERR;

	// Gets the Value
	val = PKI_X509_get_value(obj);
	if (!val) return PKI_ERR;

	// Gets the type of object
	obj_type = PKI_X509_get_type(obj);
	if (obj_type == PKI_DATATYPE_UNKNOWN) {
		fprintf(stderr, "\n    ERROR: Unknown data type.\n\n");
		exit(1);
	}

	// Process the different types
	switch (obj_type) {

		// KeyPair
		case PKI_DATATYPE_X509_KEYPAIR: {

			// Checks for the type
			if (type != PKI_X509_DATA_PUBKEY_BITSTRING) {
				fprintf(stderr, "\nERROR: Keypair do not support signature extraction, aborting.\n\n");
				exit(1);
			}

			// Retrieves the ASN1_BITSTRING for the public key
			if (PKI_X509_KEYPAIR_get_public_bitstring(obj, &out_mem) == NULL) {
				fprintf(stderr, "\nERROR: Cannot extract the key bitstring from the keypair\n\n");
				exit(1);
			}
			
		} break;

		// Certificate
		case PKI_DATATYPE_X509_REQ: {

			data = PKI_X509_get_data(obj, type);
			if (!data) {
				fprintf(stderr, "\nERROR: Cannot extract the key bitstring from the request.\n\n");
				exit(1);
			}
		} break;

		// Certificate
		case PKI_DATATYPE_X509_CERT: {

			// Retrieves the public key from the certificate
			data = PKI_X509_get_data(obj, type);
			if (!data) {
				fprintf(stderr, "\nERROR: Cannot extract the key bitstring from the certificate.\n\n");
				exit(1);
			}

		} break;

		default:
			fprintf(stderr, "\n    ERROR: signature extraction is not supported for %s type\n\n",
				PKI_X509_get_type_parsed(obj));
			exit(1);
	}

	// If we do not already have the data, we use the ASN1_BIT_STRING (data)
	// pointer to save it into the out_mem
	if (!out_mem) {
		// Status Check
		if (!data || !data->data || data->length <= 0) {
			fprintf(stderr, "\n    ERROR: Cannot extract the signature, aborting.\n\n");
			exit(1);
		}
		// Copies the data from the certificate
		out_mem = PKI_MEM_new_data((size_t)data->length, data->data);
		if (!out_mem) {
			fprintf(stderr, "\n    ERROR: memory allocation error, aborting.\n\n");
			exit(1);
		}
	}
	
	// Saves the extracted data to the URI
	if (PKI_OK != URL_put_data(uri, out_mem, NULL, NULL, 0, 0, NULL)) {
		fprintf(stderr, "\n    ERROR: Cannot save to destination file (%s).\n\n", uri);
		exit(1);
	}

	// Free allocated memory
	if (out_mem) PKI_MEM_free(out_mem);
	out_mem = NULL;
	
	// All done
	return PKI_OK;

	// All done
	return PKI_OK;
}

int pki_tool_save_params(PKI_X509 * obj, const char * uri, int key_params) {

	PKI_MEM * out_mem = NULL;
		// Output Buffer

	PKI_X509_ALGOR_VALUE * val = NULL;
		// Internal Value

	PKI_X509_ALGOR_VALUE * algor = NULL;
		// Pointer to the Signature ASN1_BIT_STRING type

	PKI_DATATYPE obj_type = PKI_DATATYPE_UNKNOWN;
		// Type of object that was passed

	// Input Checks
	if (!obj) return PKI_ERR;

	// Gets the Value
	val = PKI_X509_get_value(obj);
	if (!val) return PKI_ERR;

	// Gets the type of object
	obj_type = PKI_X509_get_type(obj);
	if (obj_type == PKI_DATATYPE_UNKNOWN) {
		fprintf(stderr, "\n    ERROR: Unknown data type.\n\n");
		exit(1);
	}

	// Process the different types
	switch (obj_type) {

		// // Certificate
		// case PKI_DATATYPE_X509_KEYPAIR: {

		// 	X509_PUBKEY * pub_key = NULL;

		// 	pub_key = PKI_X509_get_data(obj, PKI_X509_DATA_PUBKEY);
		// 	if (!pub_key) {
		// 		fprintf(stderr, "\nERROR: Cannot extract the AlgorithmIdentifier from the key.\n\n");
		// 		exit(1);
		// 	}

		// 	if (!X509_PUBKEY_get0_param(NULL, NULL, NULL, &algor, pub_key)) {
		// 		fprintf(stderr, "\nERROR: Cannot extract the AlgorithmIdentifier from the key.\n\n");
		// 		exit(1);
		// 	}
		// } break;

		case PKI_DATATYPE_X509_CERT:
		case PKI_DATATYPE_X509_REQ: {

			if (key_params) {
				
				X509_PUBKEY * pub_key = NULL;

				// X509_ALGOR * al = X509_ALGOR_new();
				pub_key = PKI_X509_get_data(obj, PKI_X509_DATA_X509_PUBKEY);
				
				if (!pub_key) {
					fprintf(stderr, "\nERROR: Cannot extract the AlgorithmIdentifier from the key.\n\n");
					exit(1);
				}

				if (!X509_PUBKEY_get0_param(NULL, NULL, NULL, &algor, pub_key)) {
					fprintf(stderr, "\nERROR: Cannot extract the AlgorithmIdentifier from the key.\n\n");
					exit(1);
				}

				// algor = al;

			} else {

				PKI_DEBUG("Retrieving CERT/REQ Sig Params...");
				algor = PKI_X509_get_data(obj, PKI_X509_DATA_ALGORITHM);
			}

			if (!algor) {
				fprintf(stderr, "\nERROR: Cannot extract the AlgorithmIdentifier from the request.\n\n");
				exit(1);
			}
		} break;

		default:
			fprintf(stderr, "\n    ERROR: signature extraction is not supported for %s type\n\n",
				PKI_X509_get_type_parsed(obj));
			exit(1);
	}

	// If we do not already have the data, we use the ASN1_BIT_STRING (data)
	// pointer to save it into the out_mem
	if (!out_mem) {

		size_t der_len = 0;
		unsigned char * tmp_pnt = NULL;
			// Temporary pointer to handle the i2d_ moving the pointer
		
		// Status Check
		if (!algor) {
			fprintf(stderr, "\n    ERROR: Cannot extract the signature, aborting.\n\n");
			exit(1);
		}

		// Gets the size of the buffer
		der_len = (size_t) i2d_X509_ALGOR(algor, NULL);
		if (der_len == 0) {
			fprintf(stderr, "\n    ERROR: Cannot DER-encode the AlgorithmIdentifier.\n\n");
			exit(1);
		}

		// Allocates the buffer and copy data
		out_mem = PKI_MEM_new(der_len);
		tmp_pnt = out_mem->data;

		// buff = PKI_Malloc((size_t)buff_len);

		out_mem->size = (size_t) i2d_X509_ALGOR(algor, &tmp_pnt);
		if (out_mem->size <= 0 || !out_mem->data) {
			fprintf(stderr, "\n    ERROR: Cannot DER-encode the AlgorithmIdentifier.\n\n");
			exit(1);
		}
	}
	
	// Saves the extracted data to the URI
	if (PKI_OK != URL_put_data(uri, out_mem, NULL, NULL, 0, 0, NULL)) {
		fprintf(stderr, "\n    ERROR: Cannot save to destination file (%s).\n\n", uri);
		exit(1);
	}

	// Free allocated memory
	if (out_mem) PKI_MEM_free(out_mem);
	out_mem = NULL;
	
	// All done
	return PKI_OK;

	// All done
	return PKI_OK;
}

// int pki_tool_save_sigout(PKI_X509 * obj, const char * uri, PKI_DATA_FORMAT outFormVal) {

// 	PKI_MEM * mem = NULL;
// 	PKI_X509_ALGOR_VALUE * val = NULL;
// 	PKI_DATATYPE type = PKI_DATATYPE_ANY;

// 	const ASN1_BIT_STRING * data;
// 		// Pointer to the Signature ASN1_BIT_STRING type

// 	// Input Checks
// 	if (!obj) return PKI_ERR;

// 	// Gets the Value
// 	val = PKI_X509_get_value(obj);
// 	if (!val) return PKI_ERR;

// 	// Gets the type of object we are handling
// 	type = PKI_X509_get_type(obj);
// 	if (type == PKI_DATATYPE_UNKNOWN) {
// 		fprintf(stderr, "\n    ERROR: Unknown object type, aborting.\n\n");
// 		exit(1);
// 	}

// 	// Process the different types
// 	switch (type) {

// 		// Certificate request
// 		case PKI_DATATYPE_X509_REQ: {
// 			data = PKI_X509_get_data(obj, PKI_X509_DATA_SIGNATURE);
// 			if (!data) {
// 				fprintf(stderr, "\nERROR: Cannot extract the key bitstring from the request.\n\n");
// 				exit(1);
// 			}
// 		} break;

// 		// Certificate
// 		case PKI_DATATYPE_X509_CERT: {
// 			// Retrieves the public key from the certificate
// 			data = PKI_X509_get_data(obj, PKI_X509_DATA_PUBKEY_BITSTRING);
// 			if (!data) {
// 				fprintf(stderr, "\nERROR: Cannot extract the key bitstring from the certificate.\n\n");
// 				exit(1);
// 			}
// 		} break;

// 		// Certificate request
// 		case PKI_DATATYPE_X509_CRL: {
// 			ASN1_BIT_STRING * data = NULL;
// 			data = PKI_X509_get_data(obj, PKI_X509_DATA_SIGNATURE);
// 			if (!data) {
// 				fprintf(stderr, "\nERROR: Cannot extract the key bitstring from the request.\n\n");
// 				exit(1);
// 			}
// 		} break;

// 		default:
// 			fprintf(stderr, "\n    ERROR: signature extraction is not supported for %s type\n\n",
// 				PKI_X509_get_type_parsed(obj));
// 			exit(1);
// 	}

// 	// Status Check
// 	if (!data) {
// 		fprintf(stderr, "\n    ERROR: Cannot extract the signature, aborting.\n\n");
// 		exit(1);
// 	}

// 	PKI_MEM * out_sig_mem = NULL;
// 		// Output Buffer

// 	// Copies the data from the certificate
// 	out_sig_mem = PKI_MEM_new_data(data->length, data->data);
// 	if (!out_sig_mem) {
// 		fprintf(stderr, "\n    ERROR: memory allocation error, aborting.\n\n");
// 		exit(1);
// 	}
	
// 	// Saves the extracted data to the URI
// 	if (PKI_OK != URL_put_data(uri, out_sig_mem, NULL, NULL, 0, 0, NULL)) {
// 		fprintf(stderr, "\n    ERROR: Cannot save to destination file (%s).\n\n", uri);
// 		exit(1);
// 	}

// 	// Free allocated memory
// 	if (out_sig_mem) PKI_MEM_free(out_sig_mem);
	
// 	// All done
// 	return PKI_OK;

// }

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

	int bits = 128;
	int token_slot = 0;
	int selfsign = 0;
	int newkey = 0;
	int comp_kofn = 0;

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
	char * pubout_s = NULL;
	char * sigout_s = NULL;
	char * sigalg_s = NULL;
	char * keyalg_s = NULL;

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
		} else if ( strncmp_nocase("-keyalg", argv[i], 7 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			keyalg_s = argv[i];
		} else if ( strncmp_nocase("-outpubkey", argv[i], 10) == 0 ) {
			if( argv[i++] == NULL) usage();
			outpubkey_s = argv[i];
		} else if ( strncmp_nocase("-outprivkey", argv[i], 11) == 0 ) {
			if( argv[i++] == NULL) usage();
			outprivkey_s = argv[i];
		} else if ( strncmp_nocase("-out", argv[i], 4 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			outfile = argv[i];
		}  else if ( strncmp_nocase("-pubout", argv[i], 7 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			pubout_s = argv[i];
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
		} else if ( strncmp_nocase("-kofn", argv[i], 5) == 0 ) {
			if (argv[i++] == NULL) usage();
			comp_kofn = atoi(argv[i]);
			if (comp_kofn < 1) {
				fprintf(stderr, "ERROR: Invalid kofn value (%d)\n\n", comp_kofn);
				usage();
			}
#endif
		} else if ( strncmp_nocase("-signkey", argv[i], 8 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			signkey = argv[i];
			uri = signkey;
		} else if ( strncmp_nocase("-sigout", argv[i], 7 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			sigout_s = argv[i];
		} else if ( strncmp_nocase("-sigalg", argv[i], 7 ) == 0 ) {
			if( argv[i++] == NULL ) usage();
			sigalg_s = argv[i];
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

		PKI_DEBUG("Generating Key Pair: option %s", algor_opt );

		int sec_bits = 0;
		PKI_SCHEME_ID scheme_id = PKI_SCHEME_ID_get_by_name(algor_opt, 
															&sec_bits, 
															NULL);

		if (scheme_id <= 0) {
			PKI_log_err("\n    ERROR, can not find scheme for %s, aborting.\n\n", algor_opt);
			exit(1);
		}

		if (sec_bits >= 0) {
			if (sec_bits < bits) PKI_DEBUG("Selected Scheme (%d) provides %d sec bits instead of the requested %d", sec_bits, bits);
			if (sec_bits > bits) bits = sec_bits;
		}

		PKI_DEBUG("\nSelected Algorithm: %s\n", algor_opt);

		if ((gen_keypair(tk, 
				 bits,
				 param_s,
				 outfile,
				 scheme_id,
				 profile,
				 outFormVal,
#ifdef ENABLE_COMPOSITE
				 comp_keys,
				 comp_keys_num,
				 comp_kofn,
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

			int sec_bits = 0;
			PKI_SCHEME_ID scheme_id = PKI_SCHEME_ID_get_by_name(algor_opt, &sec_bits, NULL);
			if (scheme_id <= 0) {
				PKI_log_err("\n    ERROR, can not find scheme for %s, aborting.\n\n", algor_opt);
				exit(1);
			}

			if (sec_bits >= 0) {
				if (sec_bits < bits) PKI_DEBUG("Selected Scheme (%d) provides %d sec bits instead of the requested %d", sec_bits, bits);
				if (sec_bits > bits) bits = sec_bits;
			}

			if (sec_bits >= 0 && sec_bits < bits) {
				PKI_DEBUG("Selected Scheme (%d) provides %d sec bits instead of the requested %d", sec_bits, bits);
			}

#ifdef ENABLE_COMPOSITE
			if ((gen_keypair(tk, bits, param_s, outkey_s, scheme_id, 
					profile, outFormVal, comp_keys, comp_keys_num, comp_kofn, batch)) == PKI_ERR ) 
			{
				fprintf(stderr, "\nERROR, can not create keypair!\n\n");
				exit(1);
			}
#else
			if ((gen_keypair(tk, bits, param_s, outkey_s, scheme_id, 
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

		// Handles saving the public key
		if (pubout_s) pki_tool_save_object_data(obj, pubout_s, PKI_X509_DATA_PUBKEY_BITSTRING);

		// Handles saving the signature
		if (sigout_s) pki_tool_save_object_data(obj, sigout_s, PKI_X509_DATA_SIGNATURE);

		// Handles saving the key parameters
		if (keyalg_s) pki_tool_save_params(obj, keyalg_s, 1);

		// Handles saving the signature parameters
		if (sigalg_s) pki_tool_save_params(obj, sigalg_s, 0);

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

