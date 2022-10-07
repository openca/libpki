#ifndef _LIBPKI_PQC_LOCAL_H
#define _LIBPKI_PQC_LOCAL_H

#include <libpki/os.h>
#include <libpki/compat.h>

#ifndef OQS_H
#include <oqs/oqs.h>
#endif

#ifndef LIBPKI_X509_DATA_ST_H
#include "../internal/x509_data_st.h"
#endif

BEGIN_C_DECLS

/*
 * OQS context
 */
typedef struct
{
  /* OpenSSL NID */
  int nid;
  /* OQS signature context */
  OQS_SIG *s;
  /* OQS public key */
  uint8_t *pubkey;
  /* OQS private key */
  uint8_t *privkey;
  /* Classical key pair for hybrid schemes; either a private or public key depending on context */
  EVP_PKEY *classical_pkey;
  /* Security bits for the scheme */
  int security_bits;
  /* digest engine for CMS: */
  EVP_MD_CTX * digest;
} OQS_KEY;

/*
 * OQS key type
 */
typedef enum {
    KEY_TYPE_PUBLIC,
    KEY_TYPE_PRIVATE,
} oqs_key_type_t;

END_C_DECLS

# endif // End of _LIBPKI_PQC_LOCAL_H