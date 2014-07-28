
#include <libpki/pki.h>

int main (int argc, char *argv[] ) {

	PKI_TOKEN *tk = NULL;
	PKI_X509_PROFILE *prof =  NULL;
	PKI_OID *oid = NULL;

	PKI_X509_CRL *crl = NULL;
	PKI_X509_CRL_ENTRY *entry = NULL;
	PKI_X509_CRL_ENTRY_STACK *sk = NULL;

	printf("\n\nlibpki Test - Massimiliano Pala <madwolf@openca.org>\n");
	printf("(c) 2006 by Massimiliano Pala and OpenCA Project\n");
	printf("OpenCA Licensed Software\n\n");

	if(( PKI_log_init (PKI_LOG_TYPE_STDERR, PKI_LOG_NOTICE, NULL,
			PKI_LOG_FLAGS_ENABLE_DEBUG, NULL )) == PKI_ERR ) {
		exit(1);
	}

	if((tk = PKI_TOKEN_new_null()) == NULL ) {
		printf("ERROR, can not allocate token!\n\n");
		exit(1);
	}

	if(( PKI_TOKEN_init( tk, "etc" , "Default" )) == PKI_ERR) {
		printf("ERROR, can not configure token!\n\n");
		exit(1);
	}

	if((PKI_TOKEN_set_algor ( tk, PKI_ALGOR_RSA_SHA256 )) == PKI_ERR ) {
                printf("ERROR, can not set the RSA crypto scheme!\n");
                return (0);
        }

        if((PKI_TOKEN_new_keypair ( tk, 1024, NULL )) == PKI_ERR) {
                printf("ERROR, can not generate new keypair!\n");
                return (0);
        }

	printf("* Self Signing certificate .... ");
        if((PKI_TOKEN_self_sign( tk, NULL, "23429", 24*3600, "User" )) == PKI_ERR ) {
                printf("ERROR, can not self sign certificate!\n");
                return(0);
        }

	printf("Generating a new CRL ENTRY ... ");
	if((entry = PKI_X509_CRL_ENTRY_new_serial ( "12345678", 
			CRL_REASON_KEY_COMPROMISE, NULL, NULL )) 
								== NULL ) {
		printf("ERROR!\n");
		exit(1);
	}
	printf("Ok\n");

	sk = PKI_STACK_X509_CRL_ENTRY_new();
	PKI_STACK_X509_CRL_ENTRY_push( sk, entry );

	printf("Generating new CRL ... ");
	if((crl = PKI_TOKEN_issue_crl (tk, "3", 
				PKI_VALIDITY_ONE_WEEK, sk, "crl")) == NULL ) {
		printf("ERROR, can not generate new CRL!\n");
		exit(1);
	}
	printf("Ok\n");

	if( tk ) PKI_TOKEN_free ( tk );
	if( prof ) PKI_X509_PROFILE_free ( prof );
	if( crl )  PKI_X509_CRL_free ( crl );

	PKI_log_end();

	printf("\n\n[ Test Ended Succesfully ]\n\n");

	return (0);
}

