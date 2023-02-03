#include <libpki/pki.h>

char *prg_name = NULL;

static char *banner = "\n"
 "  OpenCA Signature Info Tool - v" VERSION "\n"
 "  (c) 2011-2022 by Massimiliano Pala and OpenCA Labs\n"
 "  All Rights Reserved\n";

void usage() {
	printf("%s", banner);

	printf("\n    USAGE: %s [ options ]\n\n", prg_name);
	printf("  Where options are:\n");
	printf("  -signer <URI>    Key source for sig verification (cert or key file\n");
	printf("  -in <URI>        Input object file (cert, req, crl, etc.)\n");
	printf("  -d | -debug      Enables Debugging Info\n");
	printf("  -v | -verbose    Enables Verbose Output\n");
	printf("  -h | -help       Prints this help text\n");
	printf("\n");

	exit(1);
}

int main(int argc, char *argv[])
{
	PKI_X509 *sigObj = NULL;
	PKI_X509 *obj = NULL;

	PKI_X509_KEYPAIR *kp = NULL;
	PKI_X509_KEYPAIR_VALUE *pVal = NULL;
	// PKI_X509_SIGNATURE *sig = NULL;
	PKI_X509_ALGOR_VALUE *algor = NULL;

	PKI_OID *oid = NULL;

	char *pnt = NULL;
	char *sigName = NULL;
	char *kName = NULL;

	int print = 0;
	int verbose = 0;
	int debug = 0;

	int log_level = PKI_LOG_NONE;
	PKI_LOG_FLAGS log_flags = PKI_LOG_FLAGS_NONE;

	int nid = 0;

	if(argv[0]) prg_name = strdup(argv[0]);

	// Check the number of Arguments
	if ( argc < 2 ) usage();

	while( argc > 0 ) {
		argv++;
		argc--;

		if((pnt = *argv) == NULL) break;

		if( strcmp_nocase( pnt, "-in" ) == 0) {
			if( ++argv == NULL ) usage();
			sigName = *argv;
			argc--;
		} else if ( strcmp_nocase(pnt, "-signer") == 0) {
			if( ++argv == NULL ) usage();
			kName = *argv;
			argc--;
		} else if ( strcmp_nocase(pnt, "-print") == 0) {
			print = 1;
		} else if ( strcmp_nocase(pnt, "-verbose") == 0) {
			verbose = 1;
		} else if ( strcmp_nocase(pnt, "-v") == 0) {
			verbose = 1;
		} else if ( strcmp_nocase(pnt, "-debug") == 0) {
			debug = 1;
		} else if ( strcmp_nocase(pnt, "-d") == 0) {
			debug = 1;
		} else if ( strcmp_nocase(pnt, "-h") == 0 ) {
			usage();
		} else if ( strcmp_nocase(pnt, "-help") == 0 ) {
			usage();
		} else {
			fprintf(stderr, "\n    ERROR: unknown param %s\n\n", pnt);
			usage();
		};
	};

	if( !sigName ) sigName = "stdin";

	if( !kName ) {
		fprintf( stderr, "\n    ERROR, signer param is needed!\n\n");
		usage();
	};

	// Init LibPKI
	PKI_init_all();

	if( verbose ) log_level = PKI_LOG_INFO;
	if( debug ) log_flags |= PKI_LOG_FLAGS_ENABLE_DEBUG;

	if(( PKI_log_init (PKI_LOG_TYPE_STDERR, 
					   log_level, 
					   NULL,
                       log_flags, 
					   NULL )) == PKI_ERR ) {
		fprintf(stderr, "\n     ERROR: Cannot initialize LibPKI, aborting.\n\n");
		exit(1);
	}

	// Loads the Signer's Object
	obj = PKI_X509_get( kName, PKI_DATATYPE_ANY, PKI_DATA_FORMAT_UNKNOWN, NULL, NULL);
	if( obj == NULL) {
		fprintf(stderr, "ERROR, can not load key source: %s\n\n", kName);
		exit(1);
	}

	// Loads the Signed Object
	sigObj = PKI_X509_get( sigName, PKI_DATATYPE_ANY, PKI_DATA_FORMAT_UNKNOWN, NULL, NULL);
	if( sigObj == NULL) {
		fprintf(stderr, "ERROR, can not load signed Object: %s\n\n", kName);
		exit(1);
	}

	// Check if the Object is signed (has a signature ?)
	if ( PKI_X509_is_signed ( sigObj ) != PKI_OK ) {
		fprintf(stderr, "ERROR, object (%s) is not signed!\n\n", sigName);
		exit(1);
	}

	// Get the Key from the Key Source
	switch ( PKI_X509_get_type( obj )) {
		case PKI_DATATYPE_X509_KEYPAIR:
			kp = obj;
			break;

		case PKI_DATATYPE_X509_CERT:
			pVal = PKI_X509_get_data ( obj, PKI_X509_DATA_PUBKEY );
			if ( !pVal ) {
				fprintf(stderr, "ERROR, can not retrieve the PubKey!\n\n");
				exit(1);
			};
			kp = PKI_X509_new_value ( PKI_DATATYPE_X509_KEYPAIR, pVal, NULL );
			break;

		default:
			fprintf(stderr, "ERROR, (%s) not a cert or a key (%d)!\n\n", 
				kName,  PKI_X509_get_type( obj ) );
			exit(1);
	}

	if (!kp) {
		fprintf( stderr, "ERROR, no key found in %s!\n\n", kName );
		exit(1);
	};

	printf("Signature:\n    Info:\n");
	printf("        Signed Object Type:\n            %s\n", 
		PKI_X509_get_type_parsed( sigObj ));

	algor = PKI_X509_get_data ( sigObj, PKI_X509_DATA_ALGORITHM );
	if ( algor ) {
		printf("        Algorithm:\n            %s\n", 
			PKI_X509_ALGOR_VALUE_get_parsed ( algor ));
	};

	printf("\n    Signer's Key Info:\n");
	printf("        Scheme: ");

	switch ( PKI_X509_KEYPAIR_get_scheme( kp ))
	{
		case PKI_SCHEME_RSA:
			printf("RSA\n");
			break;

#ifdef ENABLE_DSA
		case PKI_SCHEME_DSA:
			printf("DSA\n");
			break;
#endif

#ifdef ENABLE_ECDSA
		case PKI_SCHEME_ECDSA:
			printf("ECDSA\n");
			nid = PKI_X509_KEYPAIR_get_curve ( kp );
			if((oid = PKI_OID_new_id( nid )) != NULL ) {
				printf("        Curve Name: %s\n", PKI_OID_get_descr( oid ));
				PKI_OID_free ( oid );
			};
			break;
#endif

#ifdef ENABLE_OQS
			// Post Quantum Digital Signature Switches
			case PKI_SCHEME_FALCON: {
				printf("Falcon\n");
			} break;
			
			case PKI_SCHEME_PICNIC: {
				printf("PicNic\n");
			} break;

			case PKI_SCHEME_SPHINCS: {
				// Needs to check for each algorithm
				printf("Sphincs+\n");
			} break;

			case PKI_SCHEME_DILITHIUM: {
				printf("Dilithium\n");
			} break;

			case PKI_SCHEME_DILITHIUMX3: {
				// Experimental Only
				printf("DilithiumX\n");
			} break;

			// Combined Crypto
			case PKI_SCHEME_COMPOSITE_FALCON512_RSA: {
				printf("OQS Hybrid (RSA with Falcon)\n");
			} break;
			
			case PKI_SCHEME_COMPOSITE_FALCON512_P256: {
				printf("OQS Hybrid (ECDSA with Falcon)\n");
			} break;
			
			case PKI_SCHEME_COMPOSITE_DILITHIUM3_RSA:{
				printf("OQS Hybrid (RSA with Dilithium)\n");
			} break;
			
			case PKI_SCHEME_COMPOSITE_DILITHIUM3_P256: {
				printf("OQS Hybrid (ECDSA with Dilithium)\n");
			} break;

			case PKI_SCHEME_NTRU_PRIME: {
				printf("NTRU Prime\n");
			} break;
			
			case PKI_SCHEME_SIKE:{
				printf("SIKE\n");
			} break;

			case PKI_SCHEME_BIKE:{
				printf("BIKE\n");
			} break;
			
			case PKI_SCHEME_FRODOKEM: {
				printf("Frodo KEM\n");
			} break;

			case PKI_SCHEME_DH: {
				printf("Diffie-Hellman\n");
			} break;

			// case PKI_SCHEME_UNKNOWN: {
			// 	PKI_DEBUG("Scheme Not Supported (PKEY ID: %d)", EVP_PKEY_id((EVP_PKEY *)kp->value));
			// 	return PKI_ERR;
			// } break;
#endif

		default:
#ifdef ENABLE_COMPOSITE
			if (EVP_PKEY_id((EVP_PKEY *)kp->value) == OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_COMP_OID)) {
				printf("Composite\n");
			} 
#endif

# ifdef ENABLE_COMBINED
			else if (EVP_PKEY_id((EVP_PKEY *)kp->value) == OBJ_txt2nid(OPENCA_ALG_PKEY_EXP_ALT_OID)) {
				printf("Multikey\n");
			}
#endif
			else if (EVP_PKEY_id((EVP_PKEY *)kp->value) != NID_undef) {
				printf("PQC: %s\n", OBJ_nid2sn(EVP_PKEY_id((EVP_PKEY*)kp->value)));
			} else {
				printf("Unknown!\n\n");
				fprintf(stderr, "\n    ERROR: Unsupported signing scheme (Key Type: %d), aborted.\n\n",
					EVP_PKEY_id((EVP_PKEY *)kp->value));
				exit(1);
			}
	};

	printf("        Key Size: %d\n", PKI_X509_KEYPAIR_get_size( kp ));

	printf("\n    Verify: ");
	if( PKI_X509_verify(sigObj, kp) == PKI_OK) {
		printf("Ok\n");
	} else {
		printf("ERROR!\n");
	}

	if (PKI_X509_get_type(sigObj) == PKI_DATATYPE_X509_CERT) {
		printf("Self Signed: %d\n", PKI_X509_CERT_is_selfsigned(sigObj));
		printf("\n");
	}

	if (print == 1) {

		if (PKI_X509_put(sigObj, PKI_DATA_FORMAT_PEM, "stdout", NULL, NULL, NULL) == PKI_ERR) {
			printf("\n    ERROR: Cannot print the signer object, aborting.\n\n");
		}

	}

	// All Done
	printf("\n");

	return 0;
}

