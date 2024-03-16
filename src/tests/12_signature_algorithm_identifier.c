#include <libpki/pki.h>

// ================
// Global Variables
// ================

const char * test_name = "AMETH/PMETH Test";


// ===================
// Function Prototypes
// ===================

int subtest1();
int subtest2();
int subtest3();


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
		&& subtest2()
		&& subtest3()
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
	
#ifdef ENABLE_PQC

	char * oids[8] = {
		OPENCA_ALG_PKEY_EXP_COMP_NAME,
		OPENCA_ALG_PKEY_PQC_DILITHIUM2_NAME,
		OPENCA_ALG_PKEY_PQC_DILITHIUM3_NAME,
		OPENCA_ALG_PKEY_PQC_DILITHIUM5_NAME,
		OPENCA_ALG_PKEY_PQC_FALCON512_NAME,
		OPENCA_ALG_PKEY_PQC_FALCON1024_NAME,
		OPENCA_ALG_PKEY_PQC_SPHINCS128_F_SIMPLE_NAME,
		OPENCA_ALG_PKEY_PQC_SPHINCS192_F_SIMPLE_NAME
	};
	const int oids_size = 8;

	int sigs_oids[64] = { 0x0 };
	const int sigs_size = 64;

	int digest[] = {
		NID_undef,
		NID_sha256,
		NID_sha384,
		NID_sha512,
		NID_sha3_256,
		NID_sha3_384,
		NID_sha3_512,
		NID_shake128,
		NID_shake256,
	};
	const int digest_size = 8;

	printf("   - Subtest 1: Signature Algorithms Manipulation\n");

	int counter = -1;
	int pkey_nid = -1;
	for (int idx = 0; idx < oids_size; idx++) {
		for (int dgst = 0; dgst < digest_size; dgst++) {
			counter++;
			if (counter >= sigs_size) {
				printf("     * ERROR: Internal Index inconsistency\n");
				continue;
			}
			pkey_nid = PKI_ID_get_by_name(oids[idx]);
			if (!pkey_nid) {
				printf("     * ERROR: Cannot find the key OID for %s\n", oids[idx]);
				continue;
			}
			if (!OBJ_find_sigid_by_algs(&sigs_oids[counter], digest[dgst], pkey_nid)) {
				printf("     * ERROR: Cannot find signature OID for %s and %s (%d)\n", 
					OBJ_nid2sn(digest[dgst]), oids[idx], pkey_nid);
				continue;
			}
			if (sigs_oids[counter] == NID_undef) {
				printf("     * ERROR: returned signature OID is 0 for digest %s and pkey %s (%d)\n", 
					OBJ_nid2sn(digest[dgst]), oids[idx], pkey_nid);
				continue;
			}
		}
	}

#endif

	// Info
	printf("   - Subtest 1: Passed\n\n");

	// All Done
	return 1;
}

int subtest2() {
	
#if defined(ENABLE_PQC) || defined(ENABLE_OQSPROV)
	printf("   - Subtest 2: PQC/Dilithium2 and Hash-n-Sign identifiers\n");

	int nid_sigid = NID_undef;

	int nid_digestid_list[] = {
		NID_undef,
#ifdef ENABLE_SHA2
		NID_sha256,
		NID_sha384,
		NID_sha512,
#endif
#ifdef ENABLE_SHA3
		NID_sha3_256,
		NID_sha3_384,
		NID_sha3_512,
#endif
#ifdef ENABLE_SHAKE
		NID_shake128,
		NID_shake256,
#endif
		-1,
	};

	int nid_pkeyid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM2_NAME);
	if (!nid_pkeyid) {
		printf("     * ERROR: Cannot find the key OID for %s\n", OPENCA_ALG_PKEY_PQC_DILITHIUM2_NAME);
		return 0;
	}

	for (int idx = 0; nid_digestid_list[idx] >= 0; idx++) {
	
		if (!OBJ_find_sigid_by_algs(&nid_sigid, nid_digestid_list[idx], nid_pkeyid)) {
			printf("     * ERROR: Cannot find signature OID for %s and %s (%d)\n", 
				OBJ_nid2sn(nid_digestid_list[idx]), OPENCA_ALG_PKEY_PQC_DILITHIUM2_NAME, nid_pkeyid);
			continue;
		} else {
			printf("     * OK: Found signature OID for hash %s and pkey %s (sig nid: %d)\n", 
				OBJ_nid2sn(nid_digestid_list[idx]), OPENCA_ALG_PKEY_PQC_DILITHIUM2_NAME, nid_sigid);
		}

		if (nid_sigid == NID_undef) {
			printf("     * ERROR: returned signature OID is 0 for digest %s and pkey %s (%d)\n", 
				OBJ_nid2sn(nid_digestid_list[idx]), OPENCA_ALG_PKEY_PQC_DILITHIUM2_NAME, nid_pkeyid);
			continue;
		}
	}

#endif

	// Info
	printf("   - Subtest 2: Passed\n\n");

	// All Done
	return 1;
}

int subtest3() {
	

	printf("   - Subtest 3: Composite Crypto and Hash-n-Sign identifiers\n");

#ifdef ENABLE_COMPOSITE

	int nid_sigid = NID_undef;

	int nid_digestid_list[] = {
		NID_undef,
#ifdef ENABLE_SHA2
		NID_sha256,
		NID_sha384,
		NID_sha512,
#endif
#ifdef ENABLE_SHA3
		NID_sha3_256,
		NID_sha3_384,
		NID_sha3_512,
#endif
#ifdef ENABLE_SHAKE
		NID_shake128,
		NID_shake256,
#endif
		-1,
	};

	int nid_pkeyid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_EXP_COMP_NAME);
	if (!nid_pkeyid) {
		printf("     * ERROR: Cannot find the key OID for %s\n", OPENCA_ALG_PKEY_EXP_COMP_NAME);
		return 0;
	}

	for (int idx = 0; nid_digestid_list[idx] >= 0; idx++) {
	
		if (!OBJ_find_sigid_by_algs(&nid_sigid, nid_digestid_list[idx], nid_pkeyid)) {
			printf("     * ERROR: Cannot find signature OID for %s and %s (%d)\n", 
				OBJ_nid2sn(nid_digestid_list[idx]), OPENCA_ALG_PKEY_EXP_COMP_NAME, nid_pkeyid);
			continue;
		} else {
			printf("     * OK: Found signature OID for hash %s and pkey %s (sig nid: %d)\n", 
				OBJ_nid2sn(nid_digestid_list[idx]), OPENCA_ALG_PKEY_EXP_COMP_NAME, nid_sigid);
		}

		if (nid_sigid == NID_undef) {
			printf("     * ERROR: returned signature OID is 0 for digest %s and pkey %s (%d)\n", 
				OBJ_nid2sn(nid_digestid_list[idx]), OPENCA_ALG_PKEY_EXP_COMP_NAME, nid_pkeyid);
			continue;
		}
	}

#endif

	// Info
	printf("   - Subtest 2: Passed\n\n");

	// All Done
	return 1;
}