/* HSM API */

#ifndef _LIBPKI_HSM_TYPES_H
#include <libpki/crypto/hsm/types.h>
#endif

#ifndef _LIBPKI_CRYPTO_TYPES_H
#include <libpki/crypto/types.h>
#endif

#ifndef _LIBPKI_CRYPTO_HSM_STORE_H
#define _LIBPKI_CRYPTO_HSM_STORE_H

BEGIN_C_DECLS

// const HSM_STORE_CALLBACKS c_openssl_hsm_crypto_cb = {
// 	NULL, // store_num
// 	NULL, // store_info_get
// 	NULL, // store_info_free
// 	NULL, // select_slot
// 	NULL, // clear_slot
// 	NULL, // get_objects
// 	NULL, // add_objects
// 	NULL, // del_objects
// 	NULL, // key_wrap
// 	NULL  // key_unwrap
// };

unsigned long HSM_STORE_num(HSM *hsm);
HSM_STORE_INFO * HSM_STORE_INFO_get ( unsigned long num, HSM *hsm );
void HSM_STORE_INFO_free ( HSM_STORE_INFO *sl_info, HSM *hsm );

int HSM_STORE_select(HSM *hsm, unsigned long num, PKI_CRED *cred);
int HSM_STORE_clear(HSM *hsm, unsigned long num);

int HSM_STORE_login(HSM *hsm, unsigned long num, PKI_CRED *cred);

int HSM_STORE_INFO_print( unsigned long num, HSM *hsm );

int HSM_STORE_wrap(byte ** out, size_t * out_size, PKI_CRED *cred, void * driver_raw_key, HSM *hsm);
int HSM_STORE_unwrap(void * driver_raw_key, byte * in, size_t * in_size, PKI_CRED *cred, HSM *hsm);

int HSM_STORE_del(byte * label, PKI_CRED *cred, HSM *hsm);
int HSM_STORE_add(void * obj, byte * label, PKI_CRED *cred, HSM *hsm);
int HSM_STORE_get(PKI_STACK ** sk, PKI_TYPE type, byte * label, PKI_TYPE format, HSM *hsm);

END_C_DECLS

#endif /* _LIBPKI_CRYPTO_HSM_STORE_H */

