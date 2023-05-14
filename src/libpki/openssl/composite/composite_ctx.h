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

/*!
 * @brief Allocates a new Composite CTX and sets the default digest
 *
 * This function allocates a new Composite CTX and sets the default
 * digest algorithm to be used when no digest is specified for the
 * composite operation and one or more components require a digest.
 * 
 * @param alg The digest algorithm to be used as default
 * @retval The new Composite CTX or NULL in case of errors
 */
COMPOSITE_CTX * COMPOSITE_CTX_new(const PKI_DIGEST_ALG * md);

/*! \brief Frees the memory associated with a Composite CTX */
void COMPOSITE_CTX_free(COMPOSITE_CTX * ctx);

/*! \brief Sets the MD for the Composite CTX */
int COMPOSITE_CTX_set_md(COMPOSITE_CTX * ctx, const PKI_DIGEST_ALG * md);

/*! \brief Returns the MD set for the CTX */
const EVP_MD * COMPOSITE_CTX_get_md(COMPOSITE_CTX * ctx);

/*! \brief Sets the default MD for the Generic Composite with no hash-n-sign */
int COMPOSITE_CTX_set_default_md(COMPOSITE_CTX * ctx, const EVP_MD * md);

/*! \brief Returns the default MD that is used in Generic Composite with no hash-n-sign */
const EVP_MD * COMPOSITE_CTX_get_default_md(COMPOSITE_CTX * ctx);

/*! \brief Adds a new key to the CTX for Key Generation Ops */
int COMPOSITE_CTX_pkey_push(COMPOSITE_CTX          * comp_ctx, 
                            PKI_X509_KEYPAIR_VALUE * pkey);

/*! \brief Removes and returns an entry from the stack of Keys */
int COMPOSITE_CTX_pkey_pop(COMPOSITE_CTX           * ctx,
                           PKI_X509_KEYPAIR_VALUE ** pkey,
                           const PKI_DIGEST_ALG   ** md);

/*! \brief Clears the stack of keys in the Composite CTX */
int COMPOSITE_CTX_pkey_clear(COMPOSITE_CTX * ctx);

/*! \brief Returns a reference to the stack of keys from the CTX */
int COMPOSITE_CTX_components_get0(const COMPOSITE_CTX        * const ctx,
                                  const COMPOSITE_KEY_STACK ** const components);

/*! \brief Sets the MD for the Composite CTX */
int COMPOSITE_CTX_components_set0(COMPOSITE_CTX       * ctx, 
                                  COMPOSITE_KEY_STACK * const components);

/*! \brief Detaches the components from the CTX */
int COMPOSITE_CTX_components_detach(COMPOSITE_CTX        * ctx, 
                                    COMPOSITE_KEY_STACK ** const components);

/*! \brief Generates and returns the list of signature algorithms 
 * 
 * This function generates the list of signature algorithms for the
 * set of configured keys inside the context.
 * 
 * For each key in the components stack, the algorithm is selected
 * by the following criteria:
 * - If the key is an explicit composite, the algorithm selection is
 *   determined by the signature OID itself that must match the key
 *   type (OID).
 * - If the key is a generic composite, the algorithm selection is
 *   determined by looking at the presence of the ctx->md algorithm
 *   that indicates the use of has-n-sign (all algorithms will use
 *   the same digest). If the ctx->md is not set, then the default
 *   algorithm (ctx->default_md) is used when the algorithm does not
 *   support direct signing.
 * 
 * The ownership of the returned structure is not transferred to
 * the caller, so the caller should not free it.
 * 
 * @param ctx The Composite CTX to use for signing operation
 * @param algors The return pointer that references the internal structure
 * @retval Returns PKI_OK on success, PKI_ERR on failure
*/
int COMPOSITE_CTX_algors_new0(COMPOSITE_CTX              * ctx,
                              const int                    pkey_type,
                              const COMPOSITE_KEY_STACK  * const components,
                              X509_ALGORS               ** algors);

/*! \brief Generates and returns the list of explicit algorithms 
 * 
 * This function generates the list of signature algorithms for the
 * set of configured keys inside the context.
 * 
 * For each key in the components stack, the algorithm is selected
 * by looking at the pkey_type (same ID for Keys and Signatures).
 * 
 * The ownership of the returned structure is not transferred to
 * the caller, so the caller should not free it.
 * 
 * @param ctx The Composite CTX to use for signing operation
 * @param algors The return pointer that references the internal structure
 * @retval Returns PKI_OK on success, PKI_ERR on failure
*/
int COMPOSITE_CTX_explicit_algors_new0(COMPOSITE_CTX              * ctx,
                                       const int                    pkey_type,
                                       const COMPOSITE_KEY_STACK  * const components,
                                       X509_ALGORS               ** algors);

/*! \brief Clears the list of signature algorithms */
int COMPOSITE_CTX_algors_clear(COMPOSITE_CTX  * const ctx);

/*!
 * @brief Returns a reference the list of signature algorithms
 *
 * This function returns a reference to the list of signature algorithms
 * that are supported by the Composite CTX. The list is returned as a
 * pointer to a X509_ALGORS structure.
 * 
 * For each key in the components stack, the algorithm is selected
 * by the following criteria:
 * - If the key is an explicit composite, the algorithm selection is
 *   determined by the signature OID itself that must match the key
 *   type (OID).
 * - If the key is a generic composite, the algorithm selection is
 *   determined by looking at the presence of the ctx->md algorithm
 *   that indicates the use of has-n-sign (all algorithms will use
 *   the same digest). If the ctx->md is not set, then the default
 *   algorithm (ctx->default_md) is used when the algorithm does not
 *   support direct signing.
 * 
 * The ownership of the returned structure is transferred to the
 * ctx, so the caller should not free it.
 * 
 * @param ctx The Composite CTX to use for signing operation
 * @param algors The pointer to the X509_ALGORS structure
 * @return 
 */
int COMPOSITE_CTX_algors_set0(COMPOSITE_CTX * const ctx,
                              X509_ALGORS   * const algors);

/*!
 * @brief Returns a reference the list of signature algorithms
 *
 * This function returns a reference to the list of configured
 * signature algorithms. The list is returned as a pointer to a
 * X509_ALGORS structure.
 * 
 * The ownership of the returned structure is not transferred to
 * the ctx, so the caller should free it.
 * 
 * @param ctx The Composite CTX to use for signing operation
 * @param algors The return pointer to the internal structure
 * @retval Returns PKI_OK on success, PKI_ERR on failure
 */
int COMPOSITE_CTX_algors_get0(const COMPOSITE_CTX  * const ctx,
                              const X509_ALGORS   ** const algors);

/*!
 * @brief Detaches the list of signature algorithms
 *
 * This function returns a reference to the list of configured
 * signature algorithms and detaches it from the ctx. The list is
 * returned as a pointer to a X509_ALGORS structure.
 * 
 * The ownership of the returned structure is transferred to
 * the ctx, so the caller should manage it (i.e., free it if 
 * it was allocated or simply discarded).
 * 
 * @param ctx The Composite CTX to use for signing operation
 * @param algors The return pointer to the internal structure
 * @retval Returns PKI_OK on success, PKI_ERR on failure
 */
int COMPOSITE_CTX_algors_detach(COMPOSITE_CTX  * const ctx,
                                X509_ALGORS   ** const algors);

/*! \brief Sets the K-of-N for the Composite CTX */
int COMPOSITE_CTX_set_kofn(COMPOSITE_CTX * ctx, int kofn);

/*! \brief Returns the K-of-N set for the CTX */
int COMPOSITE_CTX_get_kofn(COMPOSITE_CTX * ctx);

END_C_DECLS

#endif // End of _LIBPKI_COMPOSITE_CTX_H

/* END: composite_ctx.h */
