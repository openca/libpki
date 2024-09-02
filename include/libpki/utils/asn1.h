

#ifndef _LIBPKI_SYSTEM_H
#include <libpki/libconf/system.h>
#endif

#ifndef _LIBPKI_UTILS_TYPES_H
#include <libpki/utils/types.h>
#endif

#ifndef _LIBPKI_CRYPTO_TYPES_H
#include <libpki/x509/types.h>
#endif

#ifndef _LIBPKI_ASN1_UTILS_H
#define _LIBPKI_ASN1_UTILS_H

BEGIN_C_DECLS

int i2d(unsigned char **out, size_t *size, void *in, int type);
int d2i(void *out, unsigned char **in, size_t size, int type);

int i2d_PKI_X509(unsigned char **out, size_t *size, PKI_X509 *in);
int d2i_PKI_X509(PKI_X509 *out, unsigned char **in, size_t size);

int i2d_PKI_X509_sk(unsigned char **out, size_t *size, PKI_X509_STACK *in);

int i2d_PKI_STACK(unsigned char **out, size_t *size, PKI_STACK *sk, int sk_type);
int d2i_PKI_STACK(PKI_STACK **sk, unsigned char *in, size_t size, int sk_type);

END_C_DECLS

#endif /* _LIBPKI_ASN1_UTILS_H */
