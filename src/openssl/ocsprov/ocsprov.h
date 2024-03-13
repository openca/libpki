#ifndef PKI_OSSL_OCSPROV_H
#define PKI_OSSL_OCSPROV_H
# pragma once

// General Includes
#include <string.h>

// LibPKI Includes
#include <libpki/compat.h>

// Local Includes
#include "ocsprov_ctx.h"

BEGIN_C_DECLS

                        // ==============================================
                        // Provider function prototypes and documentation
                        // ==============================================

/**
 * Initializes the OCS provider.
 * This function sets up the necessary resources and configurations for the OCS provider.
 * 
 * @param handle The handle to the core library.
 * @param in The input dispatch table.
 * @param out The output dispatch table.
 * @return Returns 0 on success, or a negative error code on failure.
 */
static int ocsprov_init(const OSSL_CORE_HANDLE *  handle, 
                        const OSSL_DISPATCH    *  in,
                        const OSSL_DISPATCH    ** out,
                        void                   ** provctx);

/**
 * @brief Performs the teardown process for the OCS provisioning.
 *
 * This function is responsible for cleaning up any resources used during the OCS provisioning process.
 * It should be called after the provisioning is complete or when an error occurs.
 *
 * @param provctx The context of the OCS provisioning.
 * @return None
 */
static void ocsprov_teardown(void *provctx);

END_C_DECLS

#endif // PKI_OSSL_OCSPROV_H