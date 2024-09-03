/* openssl_hsm_core.h */

#ifndef _LIBPKI_CRYPTO_HSM_OPENSSL_TYPES_H
#include <libpki/crypto/hsm/openssl/types.h>
#endif

#ifndef _LIBPKI_CRYPTO_HSM_TYPES_H
#include <libpki/crypto/hsm/types.h>
#endif

#ifndef _LIBPKI_CRYPTO_HSM_OPENSSL_CORE_H
#define _LIBPKI_CRYPTO_HSM_OPENSSL_CORE_H

int HSM_OPENSSL_is_fips_mode(const HSM *hsm);

int HSM_OPENSSL_login ( HSM *hsm, PKI_CRED *cred );

int HSM_OPENSSL_logout ( HSM *hsm );

HSM *HSM_OPENSSL_new(const char * const dir, const char * const name );

void HSM_OPENSSL_free ( HSM *hsm );

int HSM_OPENSSL_init( HSM *hsm );

int HSM_OPENSSL_set_fips_mode(const HSM *hsm, int k);

#endif /* _LIBPKI_CRYPTO_HSM_OPENSSL_CORE_H */


