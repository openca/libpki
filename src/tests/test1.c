
#include <libpki/pki.h>

/* Function Prototypes */
int sign_ocsp_response();

// ====
// Main
// ====

const char * test_name = "Test One";

int subtest1();

int main (int argc, char *argv[] ) {

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

	// Info
	printf("\n * %s Begin\n", test_name);

	// SubTests Execution
	int success = (
		subtest1()
	);

	// Info
	if (success) {
		printf("* %s: Passed Successfully.\n", test_name);
	} else {
		printf("* %s: Failed\n", test_name);
	}

	// Error Condition
	if (!success) return 1;

	// Success
	return 0;
}

int subtest1() {
	
	printf("  - Subtest 1: X509_KEYPAIR PubKey Test and DIGEST test\n");

	// Generate a Keypair
	PKI_X509_KEYPAIR * keypair = PKI_X509_KEYPAIR_new(PKI_SCHEME_ECDSA, 256, NULL, NULL, NULL);
	if (!keypair) {
		PKI_DEBUG("ERROR: Cannot generate an ECDSA key.");
		return 0;
	}

	// Generate the Pub Digest
	PKI_DIGEST * digest = PKI_X509_KEYPAIR_pub_digest(keypair, PKI_DIGEST_ALG_SHA256);
	if (!digest) {
		PKI_DEBUG("ERROR: Cannot generate a new digest.");
		PKI_X509_KEYPAIR_free(keypair);
		return 0;
	}

	// Free Memory
	PKI_DIGEST_free(digest);

	// Info
	printf("  - Subtest 1: Passed\n\n");

	// Test Passed
	return 1;
}
