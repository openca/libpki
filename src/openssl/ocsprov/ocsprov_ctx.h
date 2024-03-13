#ifndef PKI_OSSL_OCSPROV_CTX_H
#define PKI_OSSL_OCSPROV_CTX_H
# pragma once

// LibPKI includes
#include <libpki/compat.h>

// Local includes
#include "ocsprov_asn1.h"

BEGIN_C_DECLS

                        // ==============================
                        // OCS provider context functions
                        // ==============================

// Memory management functions

PKI_OSSL_OCSPROV_CTX * COMPOSITE_CTX_new(const EVP_MD * alg);

PKI_OSSL_OCSPROV_CTX * COMPOSITE_CTX_new_null();

void COMPOSITE_CTX_free(PKI_OSSL_OCSPROV_CTX * comp_ctx);

// Digest functions

int COMPOSITE_CTX_set_md(PKI_OSSL_OCSPROV_CTX * ctx, const EVP_MD * md);

const EVP_MD * COMPOSITE_CTX_get_md(PKI_OSSL_OCSPROV_CTX * ctx);

int COMPOSITE_CTX_set_default_md(PKI_OSSL_OCSPROV_CTX * ctx, const EVP_MD * md);

const EVP_MD * COMPOSITE_CTX_get_default_md(PKI_OSSL_OCSPROV_CTX * ctx);

// Pkey stack functions

int COMPOSITE_CTX_pkey_push(PKI_OSSL_OCSPROV_CTX * comp_ctx, 
                            EVP_PKEY             * pkey);

int COMPOSITE_CTX_pkey_pop(PKI_OSSL_OCSPROV_CTX  * comp_ctx,
                           EVP_PKEY             ** pkey,
                           const EVP_MD         ** md);

int COMPOSITE_CTX_pkey_clear(PKI_OSSL_OCSPROV_CTX * comp_ctx);

// Component stack functions

int COMPOSITE_CTX_components_get0(const PKI_OSSL_OCSPROV_CTX        * const ctx,
                                  const EVP_PKEY_STACK ** const components);

int COMPOSITE_CTX_components_set0(PKI_OSSL_OCSPROV_CTX       * ctx, 
                                  EVP_PKEY_STACK * const components);

int COMPOSITE_CTX_components_detach(PKI_OSSL_OCSPROV_CTX        * ctx, 
                                    EVP_PKEY_STACK ** const components);

int COMPOSITE_CTX_algors_clear(PKI_OSSL_OCSPROV_CTX  * const ctx);

int COMPOSITE_CTX_explicit_algors_new0(PKI_OSSL_OCSPROV_CTX              * ctx,
                                       const int                    pkey_type,
                                       const ASN1_ITEM            * asn1_item,
                                       const EVP_PKEY_STACK  * const components,
                                       X509_ALGORS               ** algors);

int COMPOSITE_CTX_algors_new0(PKI_OSSL_OCSPROV_CTX              * ctx,
                              const int                    pkey_type,
                              const ASN1_ITEM            * const asn1_item,
                              const EVP_PKEY_STACK  * const components,
                              X509_ALGORS               ** algors);

int COMPOSITE_CTX_algors_get0(const PKI_OSSL_OCSPROV_CTX  * const ctx,
                              const X509_ALGORS   ** const algors);

int COMPOSITE_CTX_algors_set0(PKI_OSSL_OCSPROV_CTX * const ctx,
                              X509_ALGORS   * const algors);

int COMPOSITE_CTX_algors_detach(PKI_OSSL_OCSPROV_CTX  * const ctx,
                                X509_ALGORS   ** const algors);

int COMPOSITE_CTX_set_kofn(PKI_OSSL_OCSPROV_CTX * ctx, int kofn);

int COMPOSITE_CTX_get_kofn(PKI_OSSL_OCSPROV_CTX * ctx);

END_C_DECLS

#endif // PKI_OSSL_OCSPROV_H