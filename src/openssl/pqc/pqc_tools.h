
#ifndef _LIBPKI_PQC_TOOLS_H
#define _LIBPKI_PQC_TOOLS_H

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

#ifndef HEADER_ERR_H
#include <openssl/err.h>
#endif

#ifndef _LIBPKI_PQC_LOCAL_H
#include "pqc_data_st.h"
#endif

BEGIN_C_DECLS

int* _get_oqssl_sig_nids(void);

int* _get_oqssl_kem_nids(void);

char* _get_oqs_alg_name(int openssl_nid);

const char *_OQSKEM_options(void);

const char *_OQSSIG_options(void);

// int is_oqs_hybrid_alg(int openssl_nid);

// int get_classical_nid(int hybrid_id);

int get_oqs_nid(int hybrid_id);

// int get_classical_key_len(oqs_key_type_t keytype, int classical_id);

// int get_classical_sig_len(int classical_id);

int oqs_key_init(OQS_KEY **p_oqs_key, int nid, oqs_key_type_t keytype);

int get_oqs_security_bits(int openssl_nid);

void oqs_pkey_ctx_free(OQS_KEY* key);

// int is_EC_nid(int nid);

// int decode_EC_key(oqs_key_type_t keytype, int nid, const unsigned char* encoded_key, int key_len, OQS_KEY* oqs_key);

int oqs_int_update(EVP_MD_CTX *ctx, const void *data, size_t count);

END_C_DECLS

#endif // End of _LIBPKI_PQC_TOOLS_H
