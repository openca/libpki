#include "ocsprov.h"

                        // ============
                        // Declarations
                        // ============

// Dispatch table for the OCS provider
const OSSL_DISPATCH ocs_signature_functions[];

// Function declarations
OSSL_FUNC_core_new_error_fn *c_new_error = NULL;
OSSL_FUNC_core_vset_error_fn *c_vset_error = NULL;

// MACRO: SIGALG from OQS provider
#define SIGALG(NAMES, SECBITS, FUNC) \
    { NAMES, "provider=ocsprovider,ocsprovider.security_bits=" #SECBITS "", FUNC }

// Forward declaration of functions for internal use
static OSSL_provider_init_fn ocsprov_init;
static OSSL_FUNC_provider_teardown_fn ocsprov_teardown;
static OSSL_FUNC_provider_gettable_params_fn ocsprovider_gettable_params;
static OSSL_FUNC_provider_get_params_fn ocsprovider_get_params;
static OSSL_FUNC_provider_query_operation_fn ocsprovider_query_operation;
static OSSL_FUNC_provider_get_capabilities_fn ocsprovider_get_capabilities;
static OSSL_FUNC_provider_get_reason_strings_fn ocsprovider_reason_strings;

static const OSSL_ALGORITHM oqsprovider_signatures[] = {
    // Implementation omitted for brevity
    SIGALG("composite", 128, ocs_signature_functions),
};

/* Errors used in this provider */
#define E_MALLOC       1

// Error reasons
static const OSSL_ITEM reasons[] = {
    { E_MALLOC, (void *)"memory allocation failure" },
    { 0, NULL } /* Termination */
};

// Provider function dispatch table
static const OSSL_DISPATCH ocsprov_functions[] = {
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))ocsprovider_gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))ocsprovider_get_params},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))ocsprovider_query_operation},
    {OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))ocsprovider_get_capabilities},
    {OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, (void (*)(void))ocsprovider_reason_strings},
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))ocsprov_teardown},
    {0, NULL}
};

                        // =================================
                        // Provider functions Implementation
                        // =================================

static int ocsprov_init(const OSSL_CORE_HANDLE  * handle, 
                        const OSSL_DISPATCH     * in,
                        const OSSL_DISPATCH    ** out,
                        void                   ** provctx) {
    
    PKI_OSSL_OCSPROV_CTX *pctx = NULL;

    for (; in->function_id != 0; in++)
        switch (in->function_id) {
        case OSSL_FUNC_CORE_NEW_ERROR:
            c_new_error = OSSL_FUNC_core_new_error(in);
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            c_vset_error = OSSL_FUNC_core_vset_error(in);
            break;
        }

    *out = ocsprov_functions;

    if ((pctx = malloc(sizeof(*pctx))) == NULL) {
        /*
         * ALEA IACTA EST, if the core retrieves the reason table
         * regardless, that string will be displayed, otherwise not.
         */
        c_vset_error(handle, E_MALLOC, __FILE__, __LINE__);
        return 0;
    }
    pctx->handle = handle;
    
    return 1; // Return 1 on success
}

static void ocsprov_teardown(void *provctx) {
    // Implementation omitted for brevity
}