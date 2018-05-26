#include <libpki/pki.h>

char *prg_name = NULL;

static char *banner = "\n"
 "  OpenCA Signature Info Tool - v" VERSION "\n"
 "  (c) 2011-2015 by Massimiliano Pala and OpenCA Labs\n"
 "  All Rights Reserved\n";

void usage() {
	printf("%s", banner);

	printf("\n    USAGE: %s [ options ]\n\n", prg_name);
	printf("  Where options are:\n");
	printf("  -signer <URI>    Key source for sig verification (cert or key file\n");
	printf("  -in <URI>        Input object file (cert, req, crl, etc.)\n");
	printf("  -v               Verbose\n");
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
	PKI_ALGOR *algor = NULL;

	PKI_OID *oid = NULL;

	char *pnt = NULL;
	char *sigName = NULL;
	char *kName = NULL;

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
		} else if ( strcmp_nocase(pnt, "-h") == 0 ) {
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

	// Loads the Signer's Object
	obj = PKI_X509_get( kName, PKI_DATATYPE_ANY, NULL, NULL);
	if( obj == NULL) {
		fprintf(stderr, "ERROR, can not load key source: %s\n\n", kName);
		exit(1);
	}

	// Loads the Signed Object
	sigObj = PKI_X509_get( sigName, PKI_DATATYPE_ANY, NULL, NULL);
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
			PKI_ALGOR_get_parsed ( algor ));
	};

	printf("\n    Signer's Key Info:\n");
	printf("        Scheme: ");

	switch ( PKI_X509_KEYPAIR_get_scheme( kp ))
	{
		case PKI_SCHEME_RSA:
			printf("RSA\n");
			break;

		case PKI_SCHEME_DSA:
			printf("DSA\n");
			break;

		case PKI_SCHEME_ECDSA:
			printf("ECDSA\n");
			nid = PKI_X509_KEYPAIR_get_curve ( kp );
			if((oid = PKI_OID_new_id( nid )) != NULL ) {
				printf("        Curve Name: %s\n", PKI_OID_get_descr( oid ));
				PKI_OID_free ( oid );
			};
			break;

		default:
			printf("Unknown!\n");
			exit(1);
	};

	printf("        Key Size: %d\n", PKI_X509_KEYPAIR_get_size( kp ));

	printf("\n    Verify: ");
	if( PKI_X509_verify(sigObj, kp) == PKI_OK) {
		printf("Ok\n");
	} else {
		printf("ERROR!\n");
	};

	printf("Self Signed: %d\n", PKI_X509_CERT_is_selfsigned(sigObj));
	printf("\n");

	return 0;
}

