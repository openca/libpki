#include <libpki/pki.h>

// ================
// Global Variables
// ================

const char * test_name = "OpenCA ASN.1 Test";


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
    printf("   - Subtest 1: Sequence of BIT_STRING\n");

    ASN1_BIT_STRING_STACK * bit_stack = NULL;

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