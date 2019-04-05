
#include <libpki/pki.h>

int main (int argc, char *argv[] ) {

	PKI_TOKEN *tk = NULL;
	// PKI_OID *oid = NULL;

	// HSM *hsm = NULL;

	printf("\n\nlibpki Test - Massimiliano Pala <madwolf@openca.org>\n");
	printf("(c) 2006 by Massimiliano Pala and OpenCA Project\n");
	printf("OpenCA Licensed Software\n\n");

	if(( PKI_log_init (PKI_LOG_TYPE_SYSLOG, PKI_LOG_NOTICE, NULL,
			PKI_LOG_FLAGS_ENABLE_DEBUG, NULL )) == PKI_ERR ) {
		exit(1);
	}

	if((tk = PKI_TOKEN_new("etc", "test")) == NULL ) {
		printf("ERROR, can not allocate token!\n\n");
		exit(1);
	}

	printf("* Generating new Request ... ");
	if((PKI_TOKEN_new_req( tk, "CN=Test8, O=OpenCA", "test" )) == PKI_ERR) {
		printf("ERROR, can not generate a new Request!\n");
		exit(1);
	}
	printf("Ok.\n");

	printf("* Writing request to results/test8_req.pem .... ");
	if((PKI_TOKEN_export_req( tk, "results/test8_req.pem",
			PKI_DATA_FORMAT_PEM )) == PKI_ERR ) {
		printf("ERROR, can not save req results/test8_req.pem!\n");
		exit(1);
	}
	printf("Ok.\n");

	printf("* Self Signing certificate .... ");
	if((PKI_TOKEN_self_sign( tk, NULL, "23429", 
				PKI_VALIDITY_ONE_HOUR, "Test" )) == PKI_ERR ) {
		printf("ERROR, can not self sign certificate!\n");
		return(0);
	}
	printf("Ok.\n");

	printf("* Writing certificate to results/test8_cert.pem .... ");
	if((PKI_TOKEN_export_cert( tk, "results/test8_cert.pem",
			PKI_DATA_FORMAT_PEM )) == PKI_ERR ) {
		printf("ERROR, can not save cert results/test8_cert.pem!\n");
		exit(1);
	}
	printf("Ok.\n");

	if( tk ) PKI_TOKEN_free ( tk );

	PKI_log_end();

	printf("\n\n[ Test Ended Succesfully ]\n\n");

	return (0);
}

