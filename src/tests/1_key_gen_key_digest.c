
#include <libpki/pki.h>

/* Function Prototypes */
int sign_ocsp_response();

// ====
// Main
// ====

const char * test_name = "Keypair Generation, Key Digest, and PKEY ID/Type Testing";

int subtest1();
int subtest2();
int subtest3();
int subtest4();
int subtest5();
int subtest6();

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
		&& subtest2()
		&& subtest3()
		&& subtest4()
		&& subtest5()
		&& subtest6()
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

#ifdef ENABLE_ECDSA

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
	PKI_X509_KEYPAIR_free(keypair);

	// Info
	printf("  - Subtest 1: Passed\n\n");

#endif

	// Test Passed
	return 1;
}

int subtest2() {


#ifdef PKI_ALGOR_ID_ED25519

	printf("  - Subtest 3: X509_KEYPAIR generation (ED25519)\n");

	// Generate a Keypair
	PKI_X509_KEYPAIR * keypair = PKI_X509_KEYPAIR_new(PKI_SCHEME_ED25519, 128, NULL, NULL, NULL);
	if (!keypair) {
		PKI_DEBUG("ERROR: Cannot generate an ED25519 key.");
		return 0;
	}

	// Free Memory
	PKI_X509_KEYPAIR_free(keypair);
	keypair = NULL;

	// Info
	printf("  - Subtest 2: Passed\n\n");

#endif

	// Test Passed
	return 1;
}

int subtest3() {

#ifdef PKI_ALGOR_ID_ED448

	printf("  - Subtest 3: X509_KEYPAIR generation (ED448)\n");

	// Generate a Keypair
	PKI_X509_KEYPAIR * keypair = PKI_X509_KEYPAIR_new(PKI_SCHEME_ED448, 128, NULL, NULL, NULL);
	if (!keypair) {
		PKI_DEBUG("ERROR: Cannot generate an ED448 key.");
		return 0;
	}

	// Free Memory
	PKI_X509_KEYPAIR_free(keypair);
	keypair = NULL;

	// Info
	printf("  - Subtest 3: Passed\n\n");

#endif

	// Test Passed
	return 1;
}

int subtest4() {

#if defined(ENABLE_OQS) || defined (ENABLE_OQSPROV)

	int sec_level_array[] = { 128, 192, 256 };

	printf("  - Subtest 4: X509_KEYPAIR generation (Dilithium)\n");

	for (int idx = 0; idx < 3; idx++) {

		PKI_X509_KEYPAIR * keypair = NULL;
		int sec_level = sec_level_array[idx];

		// Generate a Keypair (128)
		keypair = PKI_X509_KEYPAIR_new(PKI_SCHEME_DILITHIUM, sec_level, NULL, NULL, NULL);
		if (!keypair) {
			PKI_DEBUG("ERROR: Cannot generate a Dilithium key (Sec Bits: %d).", sec_level);
			return 0;
		}

		// Free Memory
		PKI_X509_KEYPAIR_free(keypair);
		keypair = NULL;
	}

	// Info
	printf("  - Subtest 4: Passed\n\n");

#endif // End of ENABLE_OQS || ENABLE_OQSPROV

	// Test Passed
	return 1;
}

int subtest5() {

#if defined(ENABLE_OQS) || defined(ENABLE_OQSPROV)

	int sec_level_array[] = { 128, 256 };

	printf("  - Subtest 5: X509_KEYPAIR generation (Falcon)\n");

	for (int idx = 0; idx < 3; idx++) {

		PKI_X509_KEYPAIR * keypair = NULL;
		int sec_level = sec_level_array[idx];

		// Generate a Keypair (128)
		keypair = PKI_X509_KEYPAIR_new(PKI_SCHEME_FALCON, sec_level, NULL, NULL, NULL);
		if (!keypair) {
			PKI_DEBUG("ERROR: Cannot generate a Falcon key (Sec Bits: %d).", sec_level);
			return 0;
		}

		// Free Memory
		PKI_X509_KEYPAIR_free(keypair);
		keypair = NULL;
	}

	// Info
	printf("  - Subtest 5: Passed\n\n");

#endif

	// Test Passed
	return 1;
}

int subtest6() {

	PKI_X509_KEYPAIR * keypair = NULL;

	PKI_SCHEME_ID arr[] = {
		PKI_SCHEME_RSA,
#ifdef ENABLE_ECDSA
		PKI_SCHEME_ECDSA,
		PKI_SCHEME_ED25519,
		PKI_SCHEME_ED448,
#endif
#if defined(ENABLE_OQS) || defined(ENABLE_OQSPROV)
		PKI_SCHEME_DILITHIUM,
		PKI_SCHEME_FALCON,
#endif
#ifdef ENABLE_COMPOSITE
		PKI_SCHEME_COMPOSITE,
#endif
		0,
	};

	printf("  - Subtest 6: PKEY identities and OSSL types\n");

	for (int idx = 0; arr[idx] != 0; idx++) {

		printf("	* Testing %s ... ", PKI_SCHEME_ID_get_parsed(arr[idx]));

		// Generate a Keypair
		keypair = PKI_X509_KEYPAIR_new(arr[idx], 128, NULL, NULL, NULL);
		if (!keypair) {
			printf("ERROR: Cannot generate a new key (%s).\n\n", PKI_SCHEME_ID_get_parsed(arr[idx]));
			return 0;
		}

		int pkey_type = PKI_X509_KEYPAIR_get_id(keypair);
		if (pkey_type <= 0) {
			printf("ERROR: Cannot get the PKEY type.\n\n");
			return 0;
		}

		PKI_SCHEME_ID pkey_scheme = PKI_X509_KEYPAIR_get_scheme(keypair);
		if (!pkey_scheme || pkey_scheme != arr[idx]) {
			PKI_DEBUG("ERROR: Expected scheme was %s, got %s.\n\n", 
				PKI_SCHEME_ID_get_parsed(arr[idx]), PKI_SCHEME_ID_get_parsed(pkey_scheme));
			return 0;
		}

		// Free Memory
		PKI_X509_KEYPAIR_free(keypair);
		keypair = NULL;

		printf("Ok.\n");
	}

	// Info
	printf("  - Subtest 6: Passed\n\n");

	// Test Passed
	return 1;
}