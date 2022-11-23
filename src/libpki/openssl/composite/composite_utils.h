/* BEGIN: composite_utils.h */

// Composite Crypto authentication methods.
// (c) 2021 by Massimiliano Pala

#ifndef _LIBPKI_COMPOSITE_UTILS_H
#define _LIBPKI_COMPOSITE_UTILS_H

#ifndef _LIBPKI_COMPOSITE_LOCAL_H
#include <libpki/openssl/composite/composite_internals.h>
#endif

BEGIN_C_DECLS

// Declares the assign function, we can not use the
// define mechanism because the EVP_PKEY_COMPOSITE is
// not defined at compile time

/// \brief Assigns a COMPOSITE key to the OpenSSL's PKEY
int EVP_PKEY_assign_COMPOSITE(EVP_PKEY *pkey, void *comp_key);

/// \brief Clears (and free the memory) of the components of the key
void COMPOSITE_KEY_clear(COMPOSITE_KEY *key);

/// \brief Free the memory associated with the composite key itself
void COMPOSITE_KEY_free(COMPOSITE_KEY * key);

/// \brief Sets the PKEY ID in a PKEY Method
int EVP_PKEY_meth_set_id(EVP_PKEY_METHOD * meth, int pkey_id, int flags);

/// \brief Sets the PKEY ID in a ANS1 Method
int EVP_PKEY_asn1_meth_set_id(EVP_PKEY_ASN1_METHOD * pkey_ameth, int pkey_id);

END_C_DECLS

#endif

/* END: composite_utils.h */

// #endif // ENABLE_COMPOSITE