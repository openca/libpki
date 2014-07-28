
#include <libpki/pki.h>

int main (int argc, char *argv[] ) {

	PKI_TOKEN *tk = NULL;
	PKI_X509_PROFILE *prof =  NULL;
	PKI_OID *oid = NULL;

	PKI_X509_CRL *crl = NULL;
	PKI_X509_CRL_ENTRY *entry = NULL;

	printf("\n\nlibpki Test - Massimiliano Pala <madwolf@openca.org>\n");
	printf("(c) 2006 by Massimiliano Pala and OpenCA Project\n");
	printf("OpenCA Licensed Software\n\n");

	if((tk = PKI_TOKEN_new_null()) == NULL ) {
		printf("ERROR, can not allocate token!\n\n");
		exit(1);
	}

	printf("Generating a new CRL ENTRY ... ");
	if((entry = PKI_X509_CRL_ENTRY_new_serial ( "12345678", 
			CRL_REASON_HOLD_INSTRUCTION, NULL, NULL )) == NULL ) {
		printf("ERROR!\n");
		exit(1);
	}

	if( tk ) PKI_TOKEN_free ( tk );
	if( prof ) PKI_X509_PROFILE_free ( prof );

	printf("\n\n[ Test Ended Succesfully ]\n\n");

	return (0);
}

