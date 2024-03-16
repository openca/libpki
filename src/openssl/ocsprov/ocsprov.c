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

// Provider's initialization and teardown functions
static OSSL_provider_init_fn ocsprov_init;

// Provider's Core functions
static OSSL_FUNC_provider_gettable_params_fn ocsprovider_gettable_params;
static OSSL_FUNC_provider_get_params_fn ocsprovider_get_params;
static OSSL_FUNC_provider_query_operation_fn ocsprovider_query_operation;
static OSSL_FUNC_provider_get_capabilities_fn ocsprovider_get_capabilities;
static OSSL_FUNC_provider_teardown_fn ocsprov_teardown;

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

/* Parameters we provide to the core */
static const OSSL_PARAM ocsprovider_param_types[]
    = {OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
       OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
       OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
       OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
       OSSL_PARAM_END};

// Provider's Signature functions
static const OSSL_ALGORITHM oqsprovider_signatures[] = {
    // Generic Composite Signature Algorithm
    SIGALG(PKI_OSSL_OCSPROV_ALG_COMP_SIG_NAME, 128, ocs_signature_functions),
};

/* Errors used in this provider */
typedef enum {
    E_MALLOC = 1,
    E_PARAM = 2,
    E_RANGE = 3,
    E_POINTER = 4,
    E_INVALID = 5,
    E_NOT_FOUND = 6,
    E_UNKNOWN = 7,
    E_CTX = 8,
    E_REGISTER = 9,
    E_MISSING_OID = 10,
    E_KEY_PARAMS = 17,
    E_KEY_PRIV = 11,
    E_KEY_PUB = 12,
    E_SIGN = 15,
    E_VERIFY = 16,

    E_GENERIC = 0xF0,
    E_DRIVER = 0xF1,
    E_NOT_IMPLEMENTED = 0xF2,
    E_NOT_SUPPORTED = 0xF3,
    E_NOT_AVAILABLE = 0xF4,
    E_NOT_CONFIGURED = 0xF5,
    E_NOT_ENABLED = 0xF6,
    E_NOT_LOADED = 0xF8,
    E_NOT_ALLOWED = 0xF9
} PKI_OSSL_OCSPROV_ERR;

// Error reasons
static const OSSL_ITEM reasons[] = {
    { E_MALLOC, (void *)"memory allocation failure" },
    { E_PARAM, (void *)"parameter error" },
    { E_RANGE, (void *)"range not valid" },
    { E_POINTER, (void *)"pointer failure" },
    { E_INVALID, (void *)"invalid value" },
    { E_NOT_FOUND, (void *)"not found" },
    { E_UNKNOWN, (void *)"unknown" },
    { E_CTX, (void *)"algorithm context failure" },
    { E_REGISTER, (void *)"provider registration failure" },
    { 0, NULL } /* Termination */
};

// Provider function dispatch table
static const OSSL_DISPATCH ocsprov_functions[] = {
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))ocsprovider_gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))ocsprovider_get_params},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))ocsprovider_query_operation},
    {OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))ocsprovider_get_capabilities},
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))ocsprov_teardown},
    {0, NULL}
};

// struct ossl_algorithm_st {
//     const char *algorithm_names;     /* key */
//     const char *property_definition; /* key */
//     const OSSL_DISPATCH *implementation;
//     const char *algorithm_description;
// };

static const OSSL_ALGORITHM ocsprov_encoder[] = {
    // { PKI_OSSL_OCSPROV_ALG_COMP_SIG_NAME, "provider=ocsprovider,output=der,structure=PrivateKeyInfo", ocs_signature_functions, PKI_OSSL_OCSPROV_ALG_COMP_SIG_DESC },
    // { NULL, NULL, NULL, NULL },
    // ENCODER_w_structure("dilithium2", dilithium2, der, PrivateKeyInfo),
//     ENCODER_w_structure("dilithium2", dilithium2, pem, PrivateKeyInfo),
//     ENCODER_w_structure("dilithium2", dilithium2, der, EncryptedPrivateKeyInfo),
//     ENCODER_w_structure("dilithium2", dilithium2, pem, EncryptedPrivateKeyInfo),
//     ENCODER_w_structure("dilithium2", dilithium2, der, SubjectPublicKeyInfo),
//     ENCODER_w_structure("dilithium2", dilithium2, pem, SubjectPublicKeyInfo),
//     ENCODER_TEXT("dilithium2", dilithium2),
// // #define ENCODER_PROVIDER "ocsprovider"
// // #include "ocsencoders.inc"
// //     {NULL, NULL, NULL}
// // #undef ENCODER_PROVIDER
    {NULL, NULL, NULL}
};

static const OSSL_ALGORITHM ocsprov_decoder[] = {
//     DECODER_w_structure("dilithium2", dilithium2, der, PrivateKeyInfo),
//     DECODER_w_structure("dilithium2", dilithium2, pem, PrivateKeyInfo),
//     DECODER_w_structure("dilithium2", dilithium2, der, EncryptedPrivateKeyInfo),
//     DECODER_w_structure("dilithium2", dilithium2, pem, EncryptedPrivateKeyInfo),
//     DECODER_w_structure("dilithium2", dilithium2, der, SubjectPublicKeyInfo),
//     DECODER_w_structure("dilithium2", dilithium2, pem, SubjectPublicKeyInfo),
//     DECODER_TEXT("dilithium2", dilithium2),
// #define DECODER_PROVIDER "ocsprovider"
// // #include "ocsdecoders.inc"
// //     {NULL, NULL, NULL}
// // #undef DECODER_PROVIDER
    {NULL, NULL, NULL}
};

static const OSSL_ALGORITHM oqsprov_encoder_algorithms[] = {
    // { "EVP_KEY", "provider=oqsprov", oqsprov_encoders },
    { NULL, NULL, NULL }
};

                        // =================================
                        // Provider functions Implementation
                        // =================================

/**
 * @brief Composite signatures provider initialization function.
 *
 * This function is called when the provider is first loaded. It should register
 * the provider with OpenSSL and declare its supported capabilities.
 *
 * @return 1 on success, 0 on failure.
 */
static int ocsprov_init(const OSSL_CORE_HANDLE  * handle, 
                        const OSSL_DISPATCH     * in,
                        const OSSL_DISPATCH    ** out,
                        void                   ** provctx) {
    
    COMPOSITE_CTX *pctx = NULL;

    const OSSL_DISPATCH *orig_in = in;
    OSSL_FUNC_core_obj_create_fn *c_obj_create = NULL;

    OSSL_FUNC_core_obj_add_sigid_fn *c_obj_add_sigid = NULL;
    BIO_METHOD *corebiometh;
    OSSL_LIB_CTX *libctx = NULL;

    char *opensslv;
    const char *ossl_versionp = NULL;
    OSSL_PARAM version_request[] = {{"openssl-version", OSSL_PARAM_UTF8_PTR,
                                     &opensslv, sizeof(&opensslv), 0},
                                    {NULL, 0, NULL, 0, 0}};

    // Cycle through the input dispatch table
    // and set the function pointers
    for (; in->function_id != 0; in++) {

        // Check if the function is supported
        switch (in->function_id) {
            
            case OSSL_FUNC_CORE_NEW_ERROR: {
                c_new_error = OSSL_FUNC_core_new_error(in);
            } break;

            case OSSL_FUNC_CORE_VSET_ERROR: {
                c_vset_error = OSSL_FUNC_core_vset_error(in);
            } break;

            case OSSL_FUNC_CORE_GETTABLE_PARAMS: {
                c_gettable_params = OSSL_FUNC_core_gettable_params(in);
            } break;

            case OSSL_FUNC_CORE_GET_PARAMS: {
                c_get_params = OSSL_FUNC_core_get_params(in);
            } break;

            case OSSL_FUNC_CORE_OBJ_CREATE: {
                c_obj_create = OSSL_FUNC_core_obj_create(in);
            } break;

            case OSSL_FUNC_CORE_OBJ_ADD_SIGID: {
                c_obj_add_sigid = OSSL_FUNC_core_obj_add_sigid(in);
            } break;

            default:
                break;
        }
    }

    // // insert all OIDs to the global objects list
    // for (i = 0; i < OQS_OID_CNT; i += 2) {
    //     if (!c_obj_create(handle, oqs_oid_alg_list[i], oqs_oid_alg_list[i + 1],
    //                       oqs_oid_alg_list[i + 1])) {
    //         ERR_raise(ERR_LIB_USER, OQSPROV_R_OBJ_CREATE_ERR);
    //         fprintf(stderr, "error registering NID for %s\n",
    //                 oqs_oid_alg_list[i + 1]);
    //         goto end_init;
    //     }

    //     /* create object (NID) again to avoid setup corner case problems
    //      * see https://github.com/openssl/openssl/discussions/21903
    //      * Not testing for errors is intentional.
    //      * At least one core version hangs up; so don't do this there:
    //      */
    //     if (strcmp("3.1.0", ossl_versionp)) {
    //         OBJ_create(oqs_oid_alg_list[i], oqs_oid_alg_list[i + 1],
    //                    oqs_oid_alg_list[i + 1]);
    //     }

    //     if (!oqs_set_nid((char *)oqs_oid_alg_list[i + 1],
    //                      OBJ_sn2nid(oqs_oid_alg_list[i + 1]))) {
    //         ERR_raise(ERR_LIB_USER, OQSPROV_R_OBJ_CREATE_ERR);
    //         goto end_init;
    //     }

    //     if (!c_obj_add_sigid(handle, oqs_oid_alg_list[i + 1], "",
    //                          oqs_oid_alg_list[i + 1])) {
    //         fprintf(stderr, "error registering %s with no hash\n",
    //                 oqs_oid_alg_list[i + 1]);
    //         ERR_raise(ERR_LIB_USER, OQSPROV_R_OBJ_CREATE_ERR);
    //         goto end_init;
    //     }

    //     if (OBJ_sn2nid(oqs_oid_alg_list[i + 1]) != 0) {
    //         OQS_PROV_PRINTF3(
    //             "OQS PROV: successfully registered %s with NID %d\n",
    //             oqs_oid_alg_list[i + 1], OBJ_sn2nid(oqs_oid_alg_list[i + 1]));
    //     } else {
    //         fprintf(stderr,
    //                 "OQS PROV: Impossible error: NID unregistered for %s.\n",
    //                 oqs_oid_alg_list[i + 1]);
    //         ERR_raise(ERR_LIB_USER, OQSPROV_R_OBJ_CREATE_ERR);
    //         goto end_init;
    //     }
    // }

    *out = ocsprov_functions;

    if ((pctx = malloc(sizeof(*pctx))) == NULL) {
        c_vset_error(handle, E_MALLOC, __FILE__, __LINE__);
        return 0;
    }
    pctx->handle = handle;

    return 1; // Return 1 on success

end_init:

    if (libctx) {
            OSSL_LIB_CTX_free(libctx);
    }
    if (provctx && *provctx) {
        ocsprov_teardown(*provctx);
        *provctx = NULL;
    }
    return 0; // Return 0 on failure                   
}


/**
 * @brief Composite signatures provider gettable parameters function.
 *
 * This function returns the gettable parameters for the provider. In this
 * example, there are no gettable parameters.
 *
 * @param[in] prov The provider.
 * @param[out] pctx The provider context.
 *
 * @return 1 on success, 0 on failure.
 */

static const OSSL_PARAM *ocsprovider_gettable_params(void *provctx) {
    // TODO: Implement this function
    return NULL;
}

static int ocsprovider_get_params(void *provctx, OSSL_PARAM params[]) {
    // TODO: Implement this function
    return 0;
}

static const OSSL_ALGORITHM *ocsprovider_query_operation(void *provctx, int operation_id,
                                               int *no_cache) {
    
     *no_cache = 0;
    switch (operation_id) {
        case OSSL_OP_ENCODER:
            return oqsprov_encoder_algorithms;
        // Add cases for other operations (e.g., decoders, key management) as needed
        default:
            return NULL;
    }

    return NULL;
}

static int ocs_provider_get_capabilities(void *provctx, const char *capability,
                                  OSSL_CALLBACK *cb, void *arg) {
    // TODO: Implement this function
    return 0;
}

static void ocsprov_teardown(void *provctx) {
    // Implementation omitted for brevity
}