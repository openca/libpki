/* BEGIN: composite_local.h */

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala

#ifndef _LIBPKI_COMPOSITE_CTX_H
#define _LIBPKI_COMPOSITE_CTX_H

#ifndef _LIBPKI_COMPOSITE_TYPES_H
#include <libpki/openssl/composite/composite_types.h>
#endif

#ifndef _LIBPKI_OID_DEFS_H
#include <libpki/openssl/pki_oid_defs.h>
#endif

#ifndef _LIBPKI_COMPAT_H
#include <libpki/compat.h>
#endif

#ifndef _LIBPKI_LOG_H
#include <libpki/pki_log.h>
#endif

#ifndef _LIBPKI_ERRORS_H
#include <libpki/pki_err.h>
#endif

#ifndef _LIBPKI_KEYPAIR_H
#include <libpki/pki_keypair.h>
#endif

BEGIN_C_DECLS

// ====================
// Functions Prototypes
// ====================

// COMPOSITE_CTX: Utility Functions
// --------------------------------

/*! \brief Allocates a new Composite CTX */
COMPOSITE_CTX * COMPOSITE_CTX_new_null();

/*! \brief Frees the memory associated with a Composite CTX */
void COMPOSITE_CTX_free(COMPOSITE_CTX * ctx);

/*! \brief Allocates a new Composite CTX from an MD */
COMPOSITE_CTX * COMPOSITE_CTX_new(const PKI_DIGEST_ALG * md);

/*! \brief Sets the MD for the Composite CTX */
int COMPOSITE_CTX_set_md(COMPOSITE_CTX * ctx, const PKI_DIGEST_ALG * md);

/*! \brief Returns the MD set for the CTX */
const EVP_MD * COMPOSITE_CTX_get_md(COMPOSITE_CTX * ctx);

/*! \brief Adds a new key to the CTX for Key Generation Ops */
int COMPOSITE_CTX_pkey_push(COMPOSITE_CTX          * comp_ctx, 
                            PKI_X509_KEYPAIR_VALUE * pkey,
                            const PKI_DIGEST_ALG   * md);

/*! \brief Removes and returns an entry from the stack of Keys */
int COMPOSITE_CTX_pkey_pop(COMPOSITE_CTX           * ctx,
                           PKI_X509_KEYPAIR_VALUE ** pkey,
                           const PKI_DIGEST_ALG   ** md);

/*! \brief Clears the stack of keys in the Composite CTX */
int COMPOSITE_CTX_pkey_clear(COMPOSITE_CTX * ctx);

/*! \brief Returns a reference to the stack of keys from the CTX */
int COMPOSITE_CTX_components_get0(const COMPOSITE_CTX        * const ctx,
                                  const COMPOSITE_KEY_STACK ** const components,
                                  const COMPOSITE_MD_STACK  ** components_md);

/*! \brief Sets the MD for the Composite CTX */
int COMPOSITE_CTX_components_set0(COMPOSITE_CTX       * ctx, 
                                  COMPOSITE_KEY_STACK * const components,
                                  COMPOSITE_MD_STACK  * const components_md);

/*! \brief Sets the MD for the Composite CTX */
int COMPOSITE_CTX_X509_get_algors(COMPOSITE_CTX  * ctx,
                                  X509_ALGORS   ** algors);

/*! \brief Sets the K-of-N for the Composite CTX */
int COMPOSITE_CTX_set_kofn(COMPOSITE_CTX * ctx, int kofn);

/*! \brief Returns the K-of-N set for the CTX */
int COMPOSITE_CTX_get_kofn(COMPOSITE_CTX * ctx);

END_C_DECLS

#endif // End of _LIBPKI_COMPOSITE_CTX_H

/* END: composite_ctx.h */
