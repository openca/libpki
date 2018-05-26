
#include <libpki/pki.h>

int main (int argc, char *argv[] ) {

	PKI_TOKEN *tk = NULL;
	PKI_X509_PROFILE *prof =  NULL;
	PKI_OID *oid = NULL;

	PKI_STACK *list = NULL;
	int i = 0;

	printf("\n\nlibpki Test - Massimiliano Pala <madwolf@openca.org>\n");
	printf("(c) 2006 by Massimiliano Pala and OpenCA Project\n");
	printf("OpenCA Licensed Software\n\n");

	if(( PKI_log_init (PKI_LOG_TYPE_STDERR, PKI_LOG_NOTICE, NULL,
			PKI_LOG_FLAGS_ENABLE_DEBUG, NULL )) == PKI_ERR ) {
		exit(1);
	}

	if(( list = PKI_list_all_tokens ( "etc/" )) == NULL ) {
		/* Error, no token found! */
		printf("ERROR, can not load the list of tokens!\n\n");
		exit(1);
	}

	PKI_log_debug( "FOUND %d TOKEN configurations!", 
						PKI_STACK_elements(list));

	for( i = 0; i < PKI_STACK_elements (list) ; i++ ) {
		PKI_log_debug("FOUND TOKEN CONFIG => %s\n", 
					PKI_STACK_get_num( list, i));
	}

	PKI_STACK_free ( list );

	if((tk = PKI_TOKEN_new_null()) == NULL ) {
		printf("ERROR, can not allocate token!\n\n");
		exit(1);
	}

	if(( PKI_TOKEN_init( tk, "etc/", NULL )) == PKI_ERR) {
		printf("ERROR, can not configure token!\n\n");
		exit(1);
	}

	/*
 	if((PKI_TOKEN_set_scheme ( tk, PKI_SCHEME_RSA )) == PKI_ERR ) {
		printf("ERROR, can not set the RSA crypto scheme!\n");
		return (0);
	}
	*/

	if((PKI_TOKEN_set_algor ( tk, PKI_ALGOR_RSA_SHA256 )) == PKI_ERR ) {
		printf("ERROR, can not set the RSA crypto scheme!\n");
		return (0);
	}

	if((PKI_TOKEN_new_keypair ( tk, 2048, NULL )) == PKI_ERR) {
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
	if((PKI_TOKEN_export_req( tk, "results/test4_req1.pem",
			PKI_DATA_FORMAT_PEM )) == PKI_ERR ) {
		printf("ERROR, can not save req results/test4_req1.pem!\n");
		return(0);
	}
	printf("Ok.\n");

	printf("* Self Signing certificate .... ");
	if((PKI_TOKEN_self_sign( tk, NULL, NULL, 24*3600, "Test")) == PKI_ERR) {
		printf("ERROR, can not self sign certificate!\n");
		return(0);
	}
	printf("Ok.\n");

	printf("Writing Certificate to file... \n");
	if((PKI_TOKEN_export_cert( tk, "results/test4_cert1.pem",
			PKI_DATA_FORMAT_PEM )) == PKI_ERR ) {
		printf("ERROR,can not save cert in results/test4_cert1.pem!\n");
		return(0);
	}

	printf("Freeing Token Object!\n");

	if( tk ) PKI_TOKEN_free ( tk );
	if( prof ) PKI_X509_PROFILE_free ( prof );

	PKI_log_end();

	printf("Done.\n\n");

	return (0);
}

