
#include <libpki/pki.h>

int main (int argc, char *argv[] ) {

	PKI_MEM * out_mem = NULL;
	PKI_X509_KEYPAIR * k = NULL;

	printf("\n\nlibpki Test - Massimiliano Pala <madwolf@openca.org>\n");
	printf("(c) 2006-2023 by Massimiliano Pala and OpenCA Project\n");
	printf("OpenCA Licensed Software\n\n");

	PKI_init_all();

	if(( PKI_log_init (PKI_LOG_TYPE_SYSLOG, PKI_LOG_NOTICE, NULL,
			PKI_LOG_FLAGS_ENABLE_DEBUG, NULL )) == PKI_ERR ) {
		exit(1);
	}
	
	printf("* Generating a New RSA Key ... ");
	k = PKI_X509_KEYPAIR_new(PKI_SCHEME_RSA, 2048, NULL, NULL, NULL );
	if( !k ) {
		printf("ERROR::Can not generate keypair!\n");
		return (0);
	}
	printf("Ok.\n");

	printf("* Extracting the RAW public key ... :");
	if (PKI_X509_KEYPAIR_get_public_bitstring(k, &out_mem) == NULL) {
		fprintf(stderr, "ERROR!\n");
	}
	printf("Ok.\n");

	// Info
	printf("* Raw public key size ... : %zu\n", PKI_MEM_get_size(out_mem));

	// All Done
	printf("\n* Done.\n\n");

	return (0);
}
