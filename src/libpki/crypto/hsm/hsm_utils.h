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

#ifndef _LIBPKI_UTILS_TYPES_H
#include <libpki/utils/types.h>
#endif

#ifndef _LIBPKI_CRYPTO_HSM_CORE_H
#define _LIBPKI_CRYPTO_HSM_CORE_H

BEGIN_C_DECLS

                    // ==============
                    // Core Interface
                    // ==============

HSM * HSM_new(const char * const dir,
                    const char * const name );

void HSM_free (HSM *hsm);

const HSM * HSM_get_default(void);

END_C_DECLS

#endif /* _LIBPKI_CRYPTO_HSM_CORE_H */
