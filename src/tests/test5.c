
#include <libpki/pki.h>

int main (int argc, char *argv[] ) {

	PKI_TOKEN *tk = NULL;
	PKI_X509_PROFILE *prof =  NULL;
	PKI_OID *oid = NULL;

	printf("\n\nlibpki Test - Massimiliano Pala <madwolf@openca.org>\n");
	printf("(c) 2006 by Massimiliano Pala and OpenCA Project\n");
	printf("OpenCA Licensed Software\n\n");

	if(( PKI_log_init (PKI_LOG_TYPE_SYSLOG, PKI_LOG_NOTICE, NULL,
			PKI_LOG_FLAGS_ENABLE_DEBUG, NULL )) == PKI_ERR ) {
		exit(1);
	}

	if((tk = PKI_TOKEN_new_null()) == NULL ) {
		printf("ERROR, can not allocate token!\n\n");
		exit(1);
	}

	if(( PKI_TOKEN_init( tk, "etc", NULL )) == PKI_ERR) {
		printf("ERROR, can not configure token!\n\n");
		exit(1);
	}

	printf("Loading specific profile (%s) .... ", 
				"file://etc/profile.d/test.xml");

	prof = PKI_X509_PROFILE_load ( "file://etc/profile.d/test.xml" );
	if( !prof ) {
		printf("ERROR!\n\n");
		exit(1);
	} else {
		printf("Ok.\n");
	}

	printf("Creating a new OID (OpenCA) ... ");
	oid = PKI_TOKEN_OID_new( tk, "OpenCA" );
	if( !oid ) {
		printf("ERROR!\n\n");
		exit(1);
	} else {
		printf("Ok.\n");
	}


	if( tk ) PKI_TOKEN_free ( tk );
	if( prof ) PKI_X509_PROFILE_free ( prof );

	PKI_log_end();

	printf("Done.\n\n");

	return (0);
}

