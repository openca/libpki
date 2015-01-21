#include <libpki/pki.h>

char *prg_name = NULL;

static char *banner = "\n"
 "  OpenCA Lightweight Internet Revocation Token - v" VERSION "\n"
 "  (c) 2011-2015 by Massimiliano Pala and OpenCA Labs\n"
 "  All Rights Reserved\n";

void usage() {
	printf("%s", banner);

	printf("\n    USAGE: %s [ options ]\n\n", prg_name);
	printf("  Where options are:\n");
	printf("  -in <URI>         Input (target) certificate\n");
	// printf("  -status <n>       Status Code (0=Valid)\n");
  // printf("  -validity <hrs>   Number of Hours this token is valid for (1d = 24)\n");
	printf("  -token <name>     Name of the token to be used\n");
	printf("  -config <dir>     Token config dir (HOME/.libpki/token.d)\n");
  // printf("  -signerCert <URI> Signer's Certificate\n");
	printf("  -signerKey <URI>  Signer's Keypair\n");
	printf("  -v                Verbose\n");
	printf("\n");

	exit(1);
}

int main(int argc, char *argv[])
{
	PKI_TOKEN *tk = NULL;
	// PKI_X509_CERT *cert = NULL;
	// PKI_X509_CERT *signerCert = NULL;
	// PKI_X509_KEYPAIR *signerKp = NULL;

	char *pnt = NULL;
	char *config = NULL;
	char *targetCertName = NULL;
	char *sigCertName = NULL;
	char *sigKeypairName = NULL;
	char *sigTokenName = NULL;

	// uint8_t status = 0;
	// uint64_t validity = 0;

	if(argv[0]) prg_name = strdup(argv[0]);

	// Check the number of Arguments
	if ( argc < 2 ) usage();

	while( argc > 0 ) {
		argv++;
		argc--;

		if((pnt = *argv) == NULL) break;

		if( strcmp_nocase( pnt, "-in" ) == 0) {
			if( ++argv == NULL ) usage();
			targetCertName = *argv;
			argc--;
		} else if ( strcmp_nocase(pnt, "-signerKey") == 0) {
			if( ++argv == NULL ) usage();
			sigKeypairName = *argv;
			argc--;

		// } else if ( strcmp_nocase(pnt, "-signerCert") == 0) {
		// 	if( ++argv == NULL ) usage();
		// 	sigCertName = *argv;
		// 	argc--;
	
		} else if ( strcmp_nocase(pnt, "-token") == 0) {
			if( ++argv == NULL ) usage();
			sigTokenName = *argv;
			argc--;
		} else if ( strcmp_nocase(pnt, "-config") == 0 ) {
			if( ++argv == NULL ) usage();
			config = *argv;
			argc--;

		// } else if ( strcmp_nocase(pnt, "-status") == 0) {
		// 	if( ++argv == NULL ) usage();
		// 	status = (uint8_t) atoi(*argv);
		// 	argc--;

		// } else if ( strcmp_nocase(pnt, "-validity") == 0) {
		// 	if( ++argv == NULL ) usage();
		// 	validity = (uint64_t) atol(*argv);
		// 	argc--;

		} else if ( strcmp_nocase(pnt, "-h") == 0 ) {
			usage();
		} else {
			fprintf(stderr, "\n    ERROR: unknown param %s\n\n", pnt);
			usage();
		};
	};

	// Init LibPKI
	PKI_init_all();

	// Fix the targetCertName if it is null
	if (!targetCertName) targetCertName = "stdin";

	// Generate a new Token
	if((tk = PKI_TOKEN_new_null()) == NULL ) {
		printf("ERROR, can not allocate token!\n\n");
		exit(1);
	}

	// Check which data to use to populate the token
	if (!sigTokenName) {

		// Here you have to load both the certificate and the keyPair
		if(!sigKeypairName && !sigCertName) {
			fprintf( stderr, "\n    ERROR, signer param is needed!\n\n");
			usage();
		};

		// Loads the Signer's KeyPair
		if((PKI_TOKEN_load_keypair(tk, sigKeypairName)) == PKI_ERR) {
				printf("\nERROR, can not load key [%s]\n\n", sigKeypairName );
				exit(1);
		}

		// Loads the Signer's Certificate
		if((PKI_TOKEN_load_cert(tk, sigCertName)) == PKI_ERR) {
			fprintf(stderr, "ERROR: Can not load signcert (%s)\n\n",
				sigCertName );
			exit(1);
		}
	} else {
		// Load the whole Token
		if((PKI_TOKEN_init(tk, config, sigTokenName)) == PKI_ERR) {
			printf("ERROR, can not load token (enable debug for "
							"details)!\n\n");
			exit(1);
		}
	}

	printf("\nAll Done.\n");

	return 0;
}

