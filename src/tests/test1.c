
#include <libpki/pki.h>

int gen_RSA_PKey( void );

/* Function Prototypes */
int test_gen_PKeys(int scheme);
int gen_X509_Req(int scheme, int bits, char *file );

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

	PKI_init_all();

	if(( PKI_log_init (PKI_LOG_TYPE_SYSLOG, PKI_LOG_NOTICE, NULL,
			PKI_LOG_FLAGS_ENABLE_DEBUG, NULL )) == PKI_ERR ) {
		exit(1);
	}

	test_gen_PKeys( PKI_SCHEME_RSA );
	test_gen_PKeys( PKI_SCHEME_DSA );
	test_gen_PKeys( PKI_SCHEME_ECDSA );

	PKI_log_end();

	gen_X509_Req(PKI_SCHEME_RSA, 2048, "req_rsa.pem");
	gen_X509_Req(PKI_SCHEME_DSA, 2048, "req_dsa.pem");
	gen_X509_Req(PKI_SCHEME_ECDSA, 256, "req_ecdsa.pem");

	printf("Done.\n\n");

	return (0);
}

int gen_X509_Req(int scheme, int bits, char *file ) {

	PKI_X509_KEYPAIR *p = NULL;
	PKI_X509_REQ *r = NULL;
	char *sc = NULL;
	char buf[256];
	int i;
	size_t list_size = 0;

	PKI_ALGOR_ID *algs = NULL;

	switch (scheme) {
		case PKI_SCHEME_RSA:
			printf("Generating RSA Key:\n");
			sc="RSA";
			break;
		case PKI_SCHEME_DSA:
			printf("Generating DSA Key:\n");
			sc="DSA";
			break;
		case PKI_SCHEME_ECDSA:
			printf("Generating ECDSA Key:\n");
			sc="ECDSA";
			break;
		default:
			printf("Unrecognized format!\n");
			return (0);
	}
	printf("  * %d bits ... ", bits);

	if((algs = PKI_ALGOR_list( scheme )) == NULL ) {
		/* No supported Digests for this alg ??? */
		printf("No supported Digests for this scheme!\n");
		return(1);
	}

	p = PKI_X509_KEYPAIR_new( scheme, bits, NULL, NULL, NULL );
	if( !p ) {
		printf("ERROR::Can not generate keypair!\n");
		return (0);
	}
	printf("Ok.\n");

	sprintf( buf, "results/t1_%s_key.pem", sc);

	PKI_X509_KEYPAIR_put( p, PKI_DATA_FORMAT_PEM, buf,  NULL, NULL );


	list_size = PKI_ALGOR_list_size ( algs );
	for( i=0; i < list_size ; i++ ) {
		PKI_DIGEST_ALG *dgst = NULL;

		printf("    - Generating REQ (%s) ... " ,
					PKI_ALGOR_ID_txt (algs[i]));

		if((dgst = PKI_ALGOR_get_digest( PKI_ALGOR_get( algs[i] )))
						== NULL ) {
			printf("ERROR, can not get dgst (%p)\n", dgst);
			return(0);
		};

		sprintf( buf, "results/t1_%s_req.pem", 
					PKI_ALGOR_ID_txt ( algs[i]) );

		PKI_log_debug ("New Req (Alg)");
		r = PKI_X509_REQ_new ( p, NULL, NULL, NULL, dgst, NULL );
		
		if( !r ) {
			if (p) PKI_X509_KEYPAIR_free( p );
			printf("ERROR::Can not generate new request!\n");
			return (0);
		}
	
		printf("Ok\n");

		printf("    - Wiriting REQ (%s) ... " , buf );
			
		if(!PKI_X509_REQ_put ( r, PKI_DATA_FORMAT_PEM, buf, 
							NULL, NULL, NULL)) {
			fprintf( stderr, "<file write error %s>\n", buf);
		} else {
			printf("Ok.\n");
		}

		PKI_X509_REQ_free ( r );
	}

	PKI_X509_KEYPAIR_free( p );

	printf("Done.\n\n");

	return 1;
}


int test_gen_PKeys(int scheme) {

	PKI_X509_KEYPAIR *p = NULL;
	int i = 0;
	int sizes[3][5]  = { {1024, 2048, 3072, 4096,  0},
			     {2048,    0,    0,    0,  0},
			     { 256,  384,  512,    0,  0}  };
	char buf[256];
	int row = 0;
	char *sc_name = NULL;

	switch(scheme) {
		case PKI_SCHEME_RSA:
			printf( "Generating RSA Keys:\n" );
			sc_name = sc_list[0];
			row = 0;
			break;
		case PKI_SCHEME_DSA:
			printf( "Generating DSA Keys:\n" );
			sc_name = sc_list[1];
			row = 1;
			break;
		case PKI_SCHEME_ECDSA:
			printf( "Generating ECDSA Keys:\n" );
			sc_name = sc_list[2];
			row = 2;
			break;
		default:
			return(0);
	}

	for( i = 0; i < sizeof(sizes[row])/sizeof(int) ; i++ ) {
		if( sizes[row][i] < 1 ) continue;
		printf("  * %d bits ... " , sizes[row][i] );
		if( (p = PKI_X509_KEYPAIR_new(scheme,sizes[row][i], 
					NULL, NULL, NULL)) == NULL ) {
			printf("ERROR!\n");
		} else {
			printf("Ok\n");
			bzero(buf, sizeof(buf));
			sprintf(buf, "%s/%s_%d.pem", "results", sc_name, 
					sizes[row][i]);
			if(!PKI_X509_KEYPAIR_put ( p, PKI_DATA_FORMAT_PEM, 
					buf, NULL, NULL )) {
				printf("<file write error %s>\n", buf);
			}
			if( p ) PKI_X509_KEYPAIR_free( p );
		}
	}
	printf("\n");
	return (1);
}

