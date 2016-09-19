
#include <libpki/pki.h>

int gen_X509_tk(int scheme, int bits, char *file );

int gen_RSA_PKey( void );

/* File_names */
char *sc_list[] = {
	"rsa",
	"dsa",
	"ecdsa"
};

int main (int argc, char *argv[] ) {

	printf("\n\nlibpki Test - Massimiliano Pala <madwolf@openca.org>\n");
	printf("(c) 2006 by Massimiliano Pala and OpenCA Project\n");
	printf("OpenCA Licensed Software\n\n");

	printf("TOKEN Generation testsuite.\n\n");

	if(( PKI_log_init (PKI_LOG_TYPE_SYSLOG, PKI_LOG_NOTICE, NULL,
			PKI_LOG_FLAGS_ENABLE_DEBUG, NULL )) == PKI_ERR ) {
		exit(1);
	}

	gen_X509_tk(PKI_SCHEME_RSA, 1024, "results/cert_rsa_1024.pem");
	gen_X509_tk(PKI_SCHEME_RSA, 2048, "results/cert_rsa_2048.pem");
	gen_X509_tk(PKI_SCHEME_RSA, 4096, "results/cert_rsa_4096.pem");
	gen_X509_tk(PKI_SCHEME_DSA, 2048,"results/cert_dsa_2048.pem");
	gen_X509_tk(PKI_SCHEME_ECDSA, 256, "results/cert_ecdsa_256.pem");

	PKI_log_end();

	printf("Done.\n\n");

	return (0);
}

int gen_X509_tk(int scheme, int bits, char *file ) {

	PKI_TOKEN *tk = NULL;
	PKI_X509_KEYPAIR *p = NULL;
	PKI_X509_CERT *r = NULL;
	PKI_ALGOR_ID algor = PKI_ALGOR_UNKNOWN;

	switch (scheme) {
		case PKI_SCHEME_RSA:
			printf("  * Generating RSA Key and Certificate:\n");
			algor = PKI_ALGOR_RSA_SHA1;
			break;
		case PKI_SCHEME_DSA:
			printf("  * Generating DSA Key and Certificate:\n");
			algor = PKI_ALGOR_DSA_SHA1;
			break;
		case PKI_SCHEME_ECDSA:
			printf("  * Generating ECDSA Key and Certificate: \n");
			algor = PKI_ALGOR_ECDSA_SHA1;
			break;
		default:
			printf("Unrecognized format!\n");
			return (0);
	}

	printf("    - generating a new token ... " );
	if((tk = PKI_TOKEN_new_null()) == NULL ) {
		printf("ERROR::Can not generate a new Token!\n\n");
		return(0);
	}
	printf("Ok.\n");

	printf("    - setting token algorithm (%d) ... ", algor );
	if((PKI_TOKEN_set_algor ( tk, algor )) == PKI_ERR ) {
		printf("ERROR::Can not set the token algorithm!\n\n");
		return (0);
	}
	printf("Ok.\n");

	printf("    - generating new Keypair (%d bits) ... ", bits );
	if((PKI_TOKEN_new_keypair ( tk, bits, NULL )) == PKI_ERR) {
		printf("ERROR::can not generate a new Keypair!\n\n");
		return (0);
	}
	printf("Ok.\n");

	printf("    - generating a self-signed cert ... " );
	if((PKI_TOKEN_self_sign( tk, NULL, "01", 24*3600, NULL )) == PKI_ERR ) {
		printf("ERROR::Can not generate a new self-signed cert!\n\n");
		return(0);
	}
	printf("Ok.\n");

	/* Assign the Certificate to the Token---when freeing the PKI_TOKEN
	   the cert memory is also freed */
	/*
	if((PKI_TOKEN_set_cert( tk, r )) == 0 ) {
		printf("ERROR!\n");
		return(0);
	}
	*/

	/*
	if(!PKI_X509_CERT_write_file( r, PKI_FORMAT_PEM, file )) {
		fprintf( stderr, "<file write error %s> ", file);
	}
	*/

	// if( tk ) PKI_TOKEN_free ( tk );
	// if( r ) PKI_X509_CERT_free ( r );
	// if( p ) PKI_KEYPAIR_free( p );

	printf("\n");

	if( tk ) PKI_TOKEN_free ( tk );

	return 1;
}


