
#include <libpki/pki.h>

// ==============
// Global Defines
// ==============

#define test_name "Test Six (6) - Token Digest CRL Sign"
#define log_name  "results/6-token-digest-crl-sign.log"

// ===================
// Function Prototypes
// ===================

int subtest1();

// ====
// Main
// ====

int main (int argc, char *argv[] ) {

	// Changes the current directory to be the working
	// main directory to make sure all file paths are correct
	chdir("../..");

	printf("\n\nlibpki Test - Massimiliano Pala <madwolf@openca.org>\n");
	printf("(c) 2006 by Massimiliano Pala and OpenCA Project\n");
	printf("OpenCA Licensed Software\n\n");

	PKI_init_all();

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
	// PKI_OID *oid = NULL;

	PKI_X509_CRL *crl = NULL;
	PKI_X509_CRL_ENTRY_STACK *sk = NULL;

	if ((tk = PKI_TOKEN_new_null()) == NULL ) {
		PKI_log_err("ERROR, can not allocate token!");
		return 0;
	}

	PKI_log(PKI_LOG_MSG, "Initializing Token (tests-root-ca)");
	if ((PKI_TOKEN_init( tk, "etc" , "tests-root-ca" )) == PKI_ERR) {
		PKI_log_err("Can not configure token!");
		return 0;
	}
	PKI_log(PKI_LOG_MSG, "Token Initialized Successfuly");

	// Let's log into the token
	PKI_log(PKI_LOG_MSG, "Logging into the token");
	if(( PKI_TOKEN_login(tk)) == PKI_ERR ) {
		PKI_log_err("Can not login into the token!\n\n");
		return 0;
	}
	PKI_log(PKI_LOG_MSG, "Token Logged in Successfuly");

	// Let's set the digest algorithm
	PKI_DEBUG("Setting the digest algorithm (sha256))");
	if ((PKI_TOKEN_set_digest_id(tk, PKI_ALGOR_ID_SHA256)) == PKI_ERR ) {
		PKI_log_err("ERROR, can not set the RSA crypto scheme!\n");
		return 0;
	}
	PKI_DEBUG("Digest Algorithm Set Successfuly");

	// if((PKI_TOKEN_new_keypair ( tk, 1024, NULL )) == PKI_ERR) {
	// 		printf("ERROR, can not generate new keypair!\n");
	// 		return (0);
	// }

	// printf("* Self Signing certificate .... ");
	// if((PKI_TOKEN_self_sign( tk, NULL, "23429", 24*3600, "User" )) == PKI_ERR ) {
	// 		printf("ERROR, can not self sign certificate!\n");
	// 		return(0);
	// }

	PKI_DEBUG("Generating a new stack of entries");
	sk = PKI_STACK_X509_CRL_ENTRY_new();
	if (!sk) {
		PKI_log_err("ERROR!\n");
		return 0;
	}
	PKI_DEBUG("Stack of entries generated successfuly");

	PKI_DEBUG("Generating a new CRL ENTRY");
	PKI_X509_CRL_ENTRY *entry = NULL;
	if((entry = PKI_X509_CRL_ENTRY_new_serial("12345678", 
											  CRL_REASON_KEY_COMPROMISE,
											  NULL,
											  NULL,
											  NULL)) == NULL ) {
		PKI_log_err("ERROR!\n");
		return 0;
	}
	PKI_DEBUG("CRL ENTRY Generated Successfuly");
	PKI_STACK_X509_CRL_ENTRY_push( sk, entry );

	PKI_DEBUG("Generating new CRL");

	if((crl = PKI_TOKEN_issue_crl (tk, 
								   "3", 
								   0,
								   PKI_VALIDITY_ONE_WEEK,
								   sk,
								   NULL,
								   "crl")) == NULL ) {
		PKI_log_err("ERROR, can not generate new CRL!\n");
		return 0;
	}

	PKI_DEBUG("CRL Generated Successfuly");

	if( tk ) PKI_TOKEN_free ( tk );
	if( prof ) PKI_X509_PROFILE_free ( prof );
	if( crl )  PKI_X509_CRL_free ( crl );

	PKI_DEBUG("subtest1: Passed");

	// All Done
	return 1;
}

