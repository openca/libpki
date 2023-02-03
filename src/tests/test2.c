
#include <libpki/pki.h>

int gen_RSA_PKey( void );

/* Function Prototypes */
int gen_X509_Cert(int scheme, int bits, char *file );

/* File_names */
char *sc_list[] = {
	"rsa",
	"dsa",
	"ecdsa"
};

int main (int argc, char *argv[] ) {

	const PKI_ALGOR_ID *algs = NULL;
	size_t list_size = 0;
	int i = 0;

	printf("\n\nlibpki Test - Massimiliano Pala <madwolf@openca.org>\n");
	printf("(c) 2006 by Massimiliano Pala and OpenCA Project\n");
	printf("OpenCA Licensed Software\n\n");

	PKI_init_all();

	if(( PKI_log_init (PKI_LOG_TYPE_SYSLOG, PKI_LOG_NOTICE, NULL,
			PKI_LOG_FLAGS_ENABLE_DEBUG, NULL )) == PKI_ERR ) {
		exit(1);
	}

	printf("Available DIGEST algorithms:\n");
	algs=PKI_DIGEST_ALG_ID_list();
	list_size = PKI_ALGOR_ID_list_size( algs );
	for( i = 0; i < PKI_ALGOR_ID_list_size( algs ); i++ ) {
		printf("    - %s (%d)\n" , PKI_ALGOR_ID_txt (algs[i]),
						algs[i]);
	}
	printf("Certificate Generation testsuite (list size: %lu).\n\n", list_size);

	gen_X509_Cert(PKI_SCHEME_RSA, 2048, "results/cert_rsa.pem");
	gen_X509_Cert(PKI_SCHEME_DSA, 2048, "results/cert_dsa.pem");
	gen_X509_Cert(PKI_SCHEME_ECDSA, 256, "results/cert_ecdsa.pem");

	PKI_log_end();

	printf("Done.\n\n");

	return (0);
}

int gen_X509_Cert(int scheme, int bits, char *file ) {
	PKI_X509_KEYPAIR *p = NULL;
	PKI_X509_CERT *r = NULL;
	// PKI_ALGOR * alg = PKI_ALGOR_DEFAULT;
	const PKI_ALGOR_ID *algs = NULL;
	size_t list_size = 0;
	int i = 0;

	char buf[256];

	switch (scheme) {
		case PKI_SCHEME_RSA:
			printf("Generating RSA Key and Certificate:\n");
			// alg = PKI_ALGOR_get ( PKI_ALGOR_RSA_SHA256 );
			sprintf( buf, "results/t2_key_%s_%d.pem", "rsa", bits);
			break;
		case PKI_SCHEME_DSA:
			printf("Generating DSA Key and Certificate:\n");
			// alg = PKI_ALGOR_get (PKI_ALGOR_DSA_SHA1);
			sprintf( buf, "results/t2_key_%s_%d.pem", "dsa", bits);
			break;
		case PKI_SCHEME_ECDSA:
			printf("Generating ECDSA Key and Certificate:\n");
			// alg = PKI_ALGOR_get (PKI_ALGOR_ECDSA_SHA1);
			sprintf( buf, "results/t2_key_%s_%d.pem", "ecdsa", bits);
			break;
		default:
			printf("Unrecognized format!\n");
			return (0);
	}
	printf("  * %d bits ... ", bits);

	p = PKI_X509_KEYPAIR_new((PKI_SCHEME_ID)scheme, bits, NULL, NULL, NULL );

	if( !p ) {
		printf("ERROR::Can not generate a new KeyPair!\n");
		return (0);
	}

	if((PKI_X509_KEYPAIR_put( p, PKI_DATA_FORMAT_PEM, buf, 
						NULL, NULL )) == PKI_ERR ) {
		printf("ERROR::Can not export key (%s)!\n", buf );
		return(0);
	};

	printf(" Ok.\n");

	if ((algs = PKI_ALGOR_ID_list((PKI_SCHEME_ID)scheme)) == NULL) {
		/* No supported Digests for this alg ??? */
		printf("No supported Digests for this scheme!\n");
		return(1);
	}

	list_size = PKI_ALGOR_ID_list_size ( algs );
	for( i=0; i < list_size ; i++ ) {

		printf("    - Generating CERT (%s) ... " ,
					PKI_ALGOR_ID_txt (algs[i]));
		fflush(stdout);

		r = PKI_X509_CERT_new ( NULL, p, NULL, NULL, NULL, 
				PKI_VALIDITY_ONE_HOUR, 
				NULL, PKI_X509_ALGOR_VALUE_get(algs[i]), NULL, NULL );

		if( !r ) {
			if (p) PKI_X509_KEYPAIR_free( p );
			printf("ERROR::Can not generate a new certificate!\n");
			return (0);
		}
		printf("Ok.\n");
	
		sprintf( buf, "results/t2_cert_%s.pem", 
					PKI_ALGOR_ID_txt ( algs[i]) );

		printf("    - Wiriting CERT (%s) ... " , buf );
		if(!PKI_X509_CERT_put ( r, PKI_DATA_FORMAT_PEM, buf, NULL, 
						NULL, NULL )) {
			fprintf( stderr, "<file write error %s> ", buf );
		}
		printf("Ok.\n");
	

		PKI_X509_CERT_free ( r );
	}

	PKI_X509_KEYPAIR_free( p );

	printf("Done.\n\n");

	return 1;
}


