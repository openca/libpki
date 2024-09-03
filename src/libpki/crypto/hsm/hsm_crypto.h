/* HSM API */

#ifndef _LIBPKI_HSM_TYPES_H
#include <libpki/crypto/hsm/types.h>
#endif

#ifndef _LIBPKI_CRYPTO_TYPES_H
#include <libpki/crypto/hsm/types.h>
#endif

#ifndef _LIBPKI_CRYPTO_HSM_CRYPTO_H
#define _LIBPKI_CRYPTO_HSM_CRYPTO_H

BEGIN_C_DECLS

unsigned long HSM_get_errno ( const HSM *hsm );

char *HSM_get_errdesc ( unsigned long err, const HSM *hsm );

int HSM_sign(const unsigned char   * data, 
             size_t                  data_sz, 
             unsigned char        ** sig, 
             size_t                * sig_sz,
			 void  				   * driver_key,
			 HSM                   * hsm);

int HSM_verify(const unsigned char  * data, 
               size_t                 data_sz, 
               const unsigned char  * sig, 
               size_t                 sig_sz,
			   void  			    * driver_key,
			   HSM                  * hsm);

int HSM_derive(const unsigned char  * out, 
               size_t                 out_sz, 
               const unsigned char  * sig, 
               size_t                 sig_sz,
			   void  			    * driver_key,
			   HSM                  * hsm);

int HSM_encrypt(const unsigned char * data, 
               size_t                 data_sz, 
               const unsigned char  * sig, 
               size_t                 sig_sz,
			   void  			    * driver_key,
			   HSM                  * hsm);

int HSM_decrypt(const unsigned char  * data, 
               size_t                 data_len, 
               const unsigned char  * sig, 
               size_t                 sig_len,
			   void  			    * driver_key,
			   HSM                  * hsm);

END_C_DECLS

#endif /* _LIBPKI_CRYPTO_HSM_H */
