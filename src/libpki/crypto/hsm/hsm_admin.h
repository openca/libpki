/* HSM API */

#ifndef _LIBPKI_HSM_TYPES_H
#include <libpki/crypto/hsm/types.h>
#endif

#ifndef _LIBPKI_CRYPTO_TYPES_H
#include <libpki/crypto/types.h>
#endif

#ifndef _LIBPKI_CRYPTO_HSM_STORE_H
#include <libpki/crypto/hsm/hsm_store.h>
#endif

#ifndef _LIBPKI_CRYPTO_HSM_CRYPTO_H
#include <libpki/crypto/hsm/hsm_crypto.h>
#endif

#ifndef _LIBPKI_CRYPTO_HSM_ADMIN_H
#define _LIBPKI_CRYPTO_HSM_ADMIN_H

BEGIN_C_DECLS

                    // ===================
                    // HSM Admin Functions
                    // ===================

int CRYPTO_HSM_new (void ** driver, const PKI_CONFIG * config);

int CRYPTO_HSM_init( HSM *hsm );

int CRYPTO_HSM_free(void * driver);

int CRYPTO_HSM_login ( HSM *hsm, PKI_CRED *cred );

int CRYPTO_HSM_logout ( HSM *hsm );

int CRYPTO_HSM_sign_algor ( HSM *hsm, unsigned char * oid );

int CRYPTO_HSM_set_fips_mode(const HSM *hsm, int k);

int CRYPTO_HSM_is_fips_mode(const HSM *hsm);

END_C_DECLS

#endif /* _LIBPKI_CRYPTO_HSM_ADMIN_H */
