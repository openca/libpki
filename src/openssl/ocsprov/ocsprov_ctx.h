#ifndef COMPOSITE_CTX_H
#define COMPOSITE_CTX_H
# pragma once

// LibPKI includes
#include <libpki/os.h>

// Local includes
#include "ocsprov_lcl.h"

BEGIN_C_DECLS

                        // ==============================
                        // OCS provider context functions
                        // ==============================

// Memory management functions

COMPOSITE_CTX * COMPOSITE_CTX_new(const EVP_MD * alg);

COMPOSITE_CTX * COMPOSITE_CTX_new_null();

void COMPOSITE_CTX_free(COMPOSITE_CTX * comp_ctx);

// Digest functions

int COMPOSITE_CTX_set_md(COMPOSITE_CTX * ctx, const EVP_MD * md);

const EVP_MD * COMPOSITE_CTX_get_md(COMPOSITE_CTX * ctx);

int COMPOSITE_CTX_set_default_md(COMPOSITE_CTX * ctx, const EVP_MD * md);

const EVP_MD * COMPOSITE_CTX_get_default_md(COMPOSITE_CTX * ctx);

// Pkey stack functions

int COMPOSITE_CTX_pkey_push(COMPOSITE_CTX * comp_ctx, 
                            EVP_PKEY             * pkey);

int COMPOSITE_CTX_pkey_pop(COMPOSITE_CTX  * comp_ctx,
                           EVP_PKEY             ** pkey,
                           const EVP_MD         ** md);

int COMPOSITE_CTX_pkey_clear(COMPOSITE_CTX * comp_ctx);

// Component stack functions

int COMPOSITE_CTX_components_get0(const COMPOSITE_CTX        * const ctx,
                                  const EVP_PKEY_STACK ** const components);

int COMPOSITE_CTX_components_set0(COMPOSITE_CTX       * ctx, 
                                  EVP_PKEY_STACK * const components);

int COMPOSITE_CTX_components_detach(COMPOSITE_CTX        * ctx, 
                                    EVP_PKEY_STACK ** const components);

int COMPOSITE_CTX_algors_clear(COMPOSITE_CTX  * const ctx);

int COMPOSITE_CTX_explicit_algors_new0(COMPOSITE_CTX              * ctx,
                                       const int                    pkey_type,
                                       const ASN1_ITEM            * asn1_item,
                                       const EVP_PKEY_STACK  * const components,
                                       X509_ALGORS               ** algors);

int COMPOSITE_CTX_algors_new0(COMPOSITE_CTX              * ctx,
                              const int                    pkey_type,
                              const ASN1_ITEM            * const asn1_item,
                              const EVP_PKEY_STACK  * const components,
                              X509_ALGORS               ** algors);

int COMPOSITE_CTX_algors_get0(const COMPOSITE_CTX  * const ctx,
                              const X509_ALGORS   ** const algors);

int COMPOSITE_CTX_algors_set0(COMPOSITE_CTX * const ctx,
                              X509_ALGORS   * const algors);

int COMPOSITE_CTX_algors_detach(COMPOSITE_CTX  * const ctx,
                                X509_ALGORS   ** const algors);

int COMPOSITE_CTX_set_kofn(COMPOSITE_CTX * ctx, int kofn);

int COMPOSITE_CTX_get_kofn(COMPOSITE_CTX * ctx);

END_C_DECLS

#endif // PKI_OSSL_OCSPROV_H