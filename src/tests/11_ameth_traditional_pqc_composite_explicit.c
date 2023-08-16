#include <libpki/pki.h>

// ================
// Global Variables
// ================

const char * test_name = "AMETH/PMETH Test";


// ===================
// Function Prototypes
// ===================

int subtest1();


// ====
// Main
// ====

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
	
	int idx = 0;
	int arr[22] = { 0x0 };

	printf("  - Subtest 1: ASN1 method find\n");

	// Populate the array with the algorithm IDs
	arr[idx++] = PKI_ALGOR_ID_RSA;
	arr[idx++] = PKI_ALGOR_ID_RSAPSS;

#ifdef ENABLE_OQS
	arr[idx++] = PKI_ID_get_by_name("dilithium2");
	arr[idx++] = PKI_ID_get_by_name("dilithium3");
	arr[idx++] = PKI_ID_get_by_name("dilithium5");
	arr[idx++] = PKI_ID_get_by_name("falcon512");
	arr[idx++] = PKI_ID_get_by_name("falcon1024");
#endif

#ifdef ENABLE_COMPOSITE
	// Generic Composite
	arr[idx++] = PKI_ID_get_by_name("COMPOSITE");
	// Explicit Composite
	arr[idx++] = PKI_ID_get_by_name("DILITHIUM3-RSA-SHA256");
	arr[idx++] = PKI_ID_get_by_name("DILITHIUM3-P256-SHA256");
	arr[idx++] = PKI_ID_get_by_name("DILITHIUM3-BRAINPOOL256-SHA256");
	arr[idx++] = PKI_ID_get_by_name("DILITHIUM3-ED25519");
	arr[idx++] = PKI_ID_get_by_name("DILITHIUM5-P384-SHA384");
	arr[idx++] = PKI_ID_get_by_name("DILITHIUM5-BRAINPOOL384-SHA384");
	arr[idx++] = PKI_ID_get_by_name("DILITHIUM5-ED448");
	arr[idx++] = PKI_ID_get_by_name("FALCON512-P256-SHA256");
	arr[idx++] = PKI_ID_get_by_name("FALCON512-BRAINPOOL256-SHA256");
	arr[idx++] = PKI_ID_get_by_name("FALCON512-ED25519");
	arr[idx++] = PKI_ID_get_by_name("DILITHIUM3-RSAPSS-SHA256");
	arr[idx++] = PKI_ID_get_by_name("FALCON512-RSA-SHA256");
	arr[idx++] = PKI_ID_get_by_name("DILITHIUM5-FALCON1024-P512-SHA512");
	arr[idx++] = PKI_ID_get_by_name("DILITHIUM5-FALCON1024-RSA-SHA256");
#endif

	const EVP_PKEY_ASN1_METHOD *ameth_one;
	// const EVP_PKEY_ASN1_METHOD *ameth_two;

	for (int idx = 0; idx < 11; idx++) {
		ameth_one = EVP_PKEY_asn1_find(NULL, arr[idx]);
		if (!ameth_one) {
			printf("ERROR, can not find method for %s (%d)!\n",
				PKI_ID_get_txt(arr[idx]), arr[idx]);
			exit(1);
		}
	}

	// Info
	printf("  - Subtest 1: Passed\n\n");

	// All Done
	return 1;
}

