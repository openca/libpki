#include <libpki/pki.h>

// ================
// Global Variables
// ================

const char * test_name = "OpenCA Composite Crypto Provider Operations Test";


// ===================
// Function Prototypes
// ===================

int subtest1();
// int subtest2();


// ====
// Main
// ====

int main() {

    printf("\n\nlibpki Test - Massimiliano Pala <madwolf@openca.org>\n");
    printf("(c) 2024 by Massimiliano Pala and OpenCA Project\n");
    printf("OpenCA Licensed Software\n\n");

    PKI_init_all();

    if(( PKI_log_init (PKI_LOG_TYPE_STDERR, 
                       PKI_LOG_ALWAYS,
                       NULL,
                       PKI_LOG_FLAGS_ENABLE_DEBUG,
                       NULL)) == PKI_ERR ) {
        fprintf(stderr, "ERROR: Cannot initialize the logging subsystem\n");
        exit(1);
    }

        // Info
    printf("\n * %s Begin\n", test_name);

    // SubTests Execution
    int success = (
        subtest1()
        // && subtest2()
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

    // Test Begin
    printf("   - Subtest 1: Signature Algorithms Manipulation\n");

    // Declare a pointer to the provider
    OSSL_PROVIDER *ocsprovider = NULL;

    // Load the provider
    ocsprovider = OSSL_PROVIDER_load(NULL, "ocsprovider");

    // Check if the provider was loaded successfully
    if (ocsprovider == NULL) {
        // Handle the error
        fprintf(stderr, "Failed to load ocsprovider\n");
        return;
    }

    // At this point, the provider is loaded and can be used

    // Unload the provider when you're done using it
    if (!OSSL_PROVIDER_unload(ocsprovider)) {
        // Handle the error
        fprintf(stderr, "Failed to unload ocsprovider\n");
        return;
    }

    // At this point, the provider is unloaded and can't be used anymore

    // Test Success
    printf("   - Subtest 1: Passed\n\n");

    // All Done
    return 1;
}

// int subtest2() {
    
//     // Test Begin
//     printf("   - Subtest 2: PQC/Dilithium2 and Hash-n-Sign identifiers\n");

//     // Test Success
//     printf("   - Subtest 2: Passed\n\n");

//     // All Done
//     return 1;
// }