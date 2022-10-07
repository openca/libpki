
#ifndef _LIBPKI_PQC_PKEY_METH_LOCAL_H
#define _LIBPKI_PQC_PKEY_METH_LOCAL_H

#ifndef _LIBPKI_OS_H
#include <libpki/os.h>
#endif

#ifndef _LIBPKI_COMPAT_H
#include <libpki/compat.h>
#endif

#ifndef _LIBPKI_PQC_DEFS_H
#include <libpki/openssl/pqc/pqc_defs.h>
#endif

#ifndef LIBPKI_X509_DATA_ST_H
#include "../internal/x509_data_st.h"
#endif

#ifndef _LIBPKI_PQC_TOOLS_H
#include "pqc_tools.h"
#endif

#ifndef HEADER_ERR_H
#include <openssl/err.h>
#endif

BEGIN_C_DECLS

// =======================
// EVP PKEY Meth Functions
// =======================

int pkey_oqs_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);

int pkey_oqs_keygen_init(EVP_PKEY_CTX *ctx);

int pkey_oqs_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);

int pkey_oqs_sign_init(EVP_PKEY_CTX *ctx);

int pkey_oqs_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
                               size_t *siglen, const unsigned char *tbs,
                               size_t tbslen);

int pkey_oqs_verify_init(EVP_PKEY_CTX *ctx);

int pkey_oqs_verify(EVP_PKEY_CTX *ctx,
                   const unsigned char *sig, size_t siglen,
                   const unsigned char *tbs, size_t tbslen);

int pkey_oqs_signctx_init (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);

int pkey_oqs_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, EVP_MD_CTX *mctx);

int pkey_oqs_verifyctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);

int pkey_oqs_verifyctx(EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
                      EVP_MD_CTX *mctx);

int pkey_oqs_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);

int pkey_oqs_digestsign(EVP_MD_CTX *ctx, unsigned char *sig,
                               size_t *siglen, const unsigned char *tbs,
                               size_t tbslen);

int pkey_oqs_digestverify(EVP_MD_CTX *ctx, const unsigned char *sig,
                                 size_t siglen, const unsigned char *tbs,
                                 size_t tbslen);

int pkey_oqs_digestcustom(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);


END_C_DECLS

#endif // End of _LIBPKI_PQC_PKEY_METH_LOCAL_H
