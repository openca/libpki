
#include <libpki/pki.h>

int print_stack_contents ( PKI_MEM_STACK *sk ) {
	int i;
	PKI_MEM *obj = NULL;
	//int k;

	if (!sk) return (-1);

	for(i=0;i<PKI_STACK_MEM_elements(sk);i++) {
		obj = PKI_STACK_MEM_get_num( sk, i );
		printf("    - Object %d (size %ld bytes)\n", i, obj->size );
		/* To Check the content of the objects, enable this! */
		/*
		for(k=0; k< obj->size; k++ ) {
			printf("%c", obj->data[k]);
		} printf("\n\n");
		*/
	}
	return(0);
}

int print_cert_stack_contents ( PKI_X509_CERT_STACK *sk ) {
	int i;
	PKI_X509_CERT *obj = NULL;
	//int k;

	if (!sk) return (-1);

	for( i = 0; i < PKI_STACK_X509_CERT_elements ( sk ) ; i++) {
		obj = PKI_STACK_X509_CERT_get_num( sk, i );
		printf("    - Subject: %s\n", 
			PKI_X509_CERT_get_parsed( obj, PKI_X509_DATA_SUBJECT ));
		printf("    - Issuer:  %s\n", 
			PKI_X509_CERT_get_parsed( obj, PKI_X509_DATA_ISSUER ));
		printf("    - Not Before: %s\n",
			PKI_X509_CERT_get_parsed( obj, PKI_X509_DATA_NOTBEFORE));
		printf("    - Not After: %s\n",
			PKI_X509_CERT_get_parsed( obj, PKI_X509_DATA_NOTAFTER));
		printf("    - Serial: %s\n",
			PKI_X509_CERT_get_parsed( obj, PKI_X509_DATA_SERIAL));
		printf("===\n\n");
	}

	return(0);
}

int print_crl_stack_contents ( PKI_X509_CRL_STACK *sk ) {
	int i;
	PKI_X509_CRL *obj = NULL;

	if (!sk) return (-1);

	for(i=0;i<PKI_STACK_X509_CERT_elements(sk);i++) {
		obj = PKI_STACK_X509_CRL_get_num( sk, i );
		printf("    - Issuer:  %s\n", 
			PKI_X509_CRL_get_parsed( obj, PKI_X509_DATA_ISSUER ));
	}

	return(0);
}

int main (int argc, char *argv[] ) {

	PKI_TOKEN *tk = NULL;
	PKI_X509_PROFILE *prof =  NULL;
	// PKI_OID *oid = NULL;

	PKI_MEM * mem_data = NULL;

	// PKI_X509_CRL *crl = NULL;
	// PKI_X509_CRL_ENTRY       *entry = NULL;
	PKI_MEM_STACK       *data = NULL;
	PKI_X509_CERT_STACK *cert_data = NULL;
	// PKI_KEY_STACK  *key_data = NULL;
	PKI_X509_CRL_STACK       *crl_data = NULL;

	char *url[] = { 
		"file://COPYING",
		"http://www.apache.org",
		"ldap://ldap.dartmouth.edu:389/cn=Dartmouth CertAuth1, o=Dartmouth College, C=US, dc=dartmouth, dc=edu?cACertificate;binary",
		"mysql://openca:openca@localhost/openca/certificate/?data"
        };

	char *cert_url[] = { 
		"ldap://ldap.dartmouth.edu:389/cn=Dartmouth CertAuth1, o=Dartmouth College, C=US, dc=dartmouth, dc=edu?cACertificate;binary",
		"mysql://openca:openca@localhost/openca/certificate/?data",
		"pkcs11:///usr/lib/libeTPkcs11.so/(slotid=\"0\")(label=\"openca\")?certificate",
		"mysql://openca:openca@localhost/openca/certificate/(cert_key=\"9999\")?data",
		"pg://openca:openca@localhost/openca/certificate/(cert_key=\"9999\")?data",
        };

	/*
	char *key_url[] = {
		"pkcs11:///usr/lib/libeTPkcs11.so/(pin=\"1234567890\")?key",
		"pkcs11:///usr/lib/libeTPkcs11.so/(pin=\"1234567890\")(label=\"openca\")?key"
	};
	*/

	char *crl_url[] = { 
		"ldap://ldap.dartmouth.edu:389/cn=Dartmouth CertAuth1, o=Dartmouth College, C=US, dc=dartmouth, dc=edu?certificateRevocationList;binary"
        };

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

	if(( PKI_TOKEN_init( tk, "etc/", NULL )) == PKI_ERR) {
		printf("ERROR, can not configure token!\n\n");
		exit(1);
	}

	printf("* Getting data from test URLs:\n");
	printf("  o FILE [ %s ] ... ", url[0] );

	if((data = URL_get_data( url[0], 0, 0, NULL )) != NULL ) {
		printf("Ok (got %d objects)\n", PKI_STACK_MEM_elements( data ));
		print_stack_contents( data );
		PKI_STACK_MEM_free_all ( data );
	} else {
		printf("ERROR, can not get FILE data!\n\n");
		exit(1);
	}

	printf("  o HTTP [ %s ] ... ", url[1] );
	if((data = URL_get_data( url[1], 0, 0, NULL )) != NULL ) {
		printf("Ok (got %d objects)\n", PKI_STACK_MEM_elements( data ));
		print_stack_contents( data );
		PKI_STACK_MEM_free_all ( data );
	} else {
		printf("ERROR!\n\n");
		exit(1);
	}

	printf("  o LDAP [ %s ] ... ", url[2] );
	if((data = URL_get_data( url[2], 0, 0, NULL )) != NULL ) {
		printf("Ok (got %d objects)\n", PKI_STACK_MEM_elements( data ));
		print_stack_contents( data );
		PKI_STACK_MEM_free_all ( data );
	} else {
		printf("ERROR!\n\n");
		exit(1);
	}

	printf("  o MYSQL [ %s ] ... ", url[3] );
	if((data = URL_get_data ( url[3], 0, 0, NULL )) != NULL ) {
		printf("Ok (got %d objects)\n", 
				PKI_STACK_MEM_elements( data ));
		print_stack_contents( data );
		PKI_STACK_MEM_free_all ( data );
	} else {
		printf("ERROR!\n\n");
		exit(1);
	}

	/*
	printf("* Retrieving Key(s) from test URLs:\n");
	printf("  o PKCS11 [ %s ] ... ", key_url[0] );
	if((key_data = PKI_KEYPAIR_STACK_get( key_url[0] )) != NULL ) {
		printf("Ok (got %d objects)\n", 
				PKI_STACK_X509_CERT_elements( key_data ));
		print_key_stack_contents( key_data );
		PKI_STACK_KEYPAIR_free_all ( key_data );
	} else {
		printf("ERROR!\n\n");
		exit(1);
	}
	*/

	printf("* Retrieving Certificate(s) from test URLs:\n");
	printf("  o LDAP [ %s ] ... ", cert_url[0] );
	if((cert_data = PKI_X509_CERT_STACK_get( cert_url[0], 
						-1, NULL, NULL )) != NULL ) {
		printf("Ok (got %d objects)\n", 
				PKI_STACK_X509_CERT_elements( cert_data ));
		print_cert_stack_contents( cert_data );
		PKI_STACK_X509_CERT_free_all ( cert_data );
	} else {
		printf("ERROR!\n\n");
		exit(1);
	}

	printf("  o MYSQL [ %s ] ... ", cert_url[1] );
	if((cert_data = PKI_X509_CERT_STACK_get( cert_url[1],
						-1, NULL, NULL )) != NULL ) {
		printf("Ok (got %d objects)\n", 
				PKI_STACK_X509_CERT_elements( cert_data ));
		print_cert_stack_contents( cert_data );
		PKI_STACK_X509_CERT_free_all ( cert_data );
	} else {
		printf("ERROR!\n\n");
		exit(1);
	}

	printf("  o PKCS11 [ %s ] ... ", cert_url[2] );
	if((cert_data = PKI_X509_CERT_STACK_get( cert_url[2],
						-1, NULL, NULL )) != NULL ) {
		printf("Ok (got %d objects)\n", 
				PKI_STACK_X509_CERT_elements( cert_data ));
		print_cert_stack_contents( cert_data );
		PKI_STACK_X509_CERT_free ( cert_data );
	} else {
		printf("ERROR!\n\n");
		exit(1);
	}


	printf("* Putting DATA to test URLs:\n");
	printf("  o MySQL [ %s ] ... ", cert_url[3] );

	mem_data = PKI_MEM_new_null();
	PKI_MEM_add( mem_data, "THIS IS IT", 10);

	/*
	if(URL_put_data(cert_url[3], mem_data, NULL ) == PKI_OK ) {
		printf("Ok!\n");
	} else {
		printf("ERROR!\n\n");
		exit(1);
	}

	printf("  o PosgreSQL [ %s ] ... ", cert_url[4] );
	if(URL_put_data(cert_url[4], mem_data, NULL ) == PKI_OK ) {
		printf("Ok!\n");
	} else {
		printf("ERROR!\n\n");
		exit(1);
	}
	*/


/*
	printf("* Retrieving KEY(s) from test URLs:\n");
	printf("  o PKCS11 [ %s ] ... ", key_url[0] );
	if((key_data = PKI_X509_CERT_STACK_get( key_url[0] )) != NULL ) {
		printf("Ok (got %d objects)\n", 
				PKI_STACK_X509_CERT_elements( key_data ));
		print_key_stack_contents( key_data );
		PKI_STACK_X509_CERT_free_all ( key_data );
	} else {
		printf("ERROR!\n\n");
		exit(1);
	}
*/


	printf("* Retrieving CRL(s) from test URLs:\n");
	printf("  o LDAP [ %s ] ... ", crl_url[0] );
	if((crl_data = PKI_X509_CRL_STACK_get( crl_url[0],
						-1, NULL, NULL )) != NULL ) {
		printf("Ok (got %d objects)\n", 
				PKI_STACK_X509_CRL_elements( crl_data ));
		print_crl_stack_contents( crl_data );
		PKI_STACK_X509_CRL_free_all ( crl_data );
	} else {
		printf("ERROR!\n\n");
		exit(1);
	}

	if( tk ) PKI_TOKEN_free ( tk );
	if( prof ) PKI_X509_PROFILE_free ( prof );

	PKI_log_end();

	printf("\n\n[ Test Ended Succesfully ]\n\n");

	return (0);
}

