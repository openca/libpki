#include <libpki/pki.h>

int main() {

	printf("\n\nlibpki Test - Massimiliano Pala <madwolf@openca.org>\n");
	printf("(c) 2006 by Massimiliano Pala and OpenCA Project\n");
	printf("OpenCA Licensed Software\n\n");

	PKI_init_all();

	if(( PKI_log_init (PKI_LOG_TYPE_STDERR, 
					   PKI_LOG_ALWAYS,
					   NULL,
					   PKI_LOG_FLAGS_ENABLE_DEBUG,
					   NULL )) == PKI_ERR ) {
		exit(1);
	}

	PKI_X509_KEYPAIR * x = PKI_X509_KEYPAIR_new(PKI_SCHEME_ED25519, 128, NULL, NULL, NULL);
	if (!x) {
		printf("ERROR, can not generate keypair!\n");
		exit(1);
	}

	PKI_X509_REQ * req = PKI_X509_REQ_new(x, NULL, NULL, NULL, EVP_sha256(), NULL);
	if (!req) {
		printf("ERROR, can not generate request!\n");
		exit(1);
	}

	PKI_X509_put(req, PKI_DATA_FORMAT_PEM, "test.req", NULL, NULL, NULL);

	PKI_X509_REQ * req_load = PKI_X509_get("test.req", PKI_DATATYPE_X509_REQ, PKI_DATA_FORMAT_PEM, NULL, NULL);
	if (!req_load) {
		printf("ERROR, can not load request!\n");
		exit(1);
	}

	const ASN1_BIT_STRING * bit = (ASN1_BIT_STRING *)PKI_X509_REQ_get_data(req_load, PKI_X509_DATA_SIGNATURE);
	if (!bit) {
		printf("ERROR, can not get signature!\n");
		exit(1);
	}

	printf("Signature Length = %d\n", ASN1_STRING_length(bit));

	return 0;
}

