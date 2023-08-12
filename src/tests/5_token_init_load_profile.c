
#include <libpki/pki.h>

// ====
// Main
// ====

#define test_name "Test Five (5) - Token Init Load Profile"
#define log_name  "results/5-token-init-load-profile.log"

int subtest1();

int main (int argc, char *argv[] ) {

	// Changes the current directory to be the working
	// main directory to make sure all file paths are correct
	chdir("../..");

	printf("\n\nlibpki Test - Massimiliano Pala <madwolf@openca.org>\n");
	printf("(c) 2006 by Massimiliano Pala and OpenCA Project\n");
	printf("OpenCA Licensed Software\n\n");

	if ((PKI_log_init(PKI_LOG_TYPE_STDERR,
					  PKI_LOG_ALWAYS,
					  log_name,
					  PKI_LOG_FLAGS_ENABLE_DEBUG,
					  NULL)) == PKI_ERR ) {
		fprintf(stderr, "ERROR: cannot initialize the log file!\n");
		exit(1);
	}

	// Info
	PKI_log(PKI_LOG_INFO, "===== %s Test Begin =====", test_name);

	// SubTests Execution
	int success = (
		subtest1()
	);

	// Info
	if (success) {
		PKI_log(PKI_LOG_INFO, "===== %s: Passed Successfully =====", test_name);
	} else {
		PKI_log(PKI_LOG_INFO, "===== %s: Failed =====", test_name);
	}

	// Terminates the logging subsystem
	PKI_log_end();

	// Error Condition
	if (!success) return 1;

	// Success
	return 0;
}

int subtest1() {

	PKI_TOKEN *tk = NULL;
	PKI_X509_PROFILE *prof =  NULL;
	PKI_OID *oid = NULL;

	char * profile_name = "file://etc/profile.d/tests-root-ca.xml";

	if((tk = PKI_TOKEN_new_null()) == NULL ) {
		printf("ERROR, can not allocate token!\n\n");
		exit(1);
	}

	if(( PKI_TOKEN_init( tk, "etc", NULL )) == PKI_ERR) {
		printf("ERROR, can not configure token!\n\n");
		exit(1);
	}

	printf("Loading specific profile (%s) .... ", profile_name);

	prof = PKI_X509_PROFILE_load(profile_name);
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


	printf("Done.\n\n");

	return 1;
}
