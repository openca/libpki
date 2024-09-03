/* ENGINE Object Management Functions */

#ifndef _LIBPKI_CRYPTO_HSM_TYPES_H
#include <libpki/crypto/hsm/types.h>
#endif

#ifndef _LIBPKI_UTILS_STACK_H
#include <libpki/utils/stack.h>
#endif

#ifndef _LIBPKI_CRYPTO_HSM_OPENSSL_STORE_H
#define _LIBPKI_CRYPTO_HSM_OPENSSL_STORE_H

BEGIN_C_DECLS

const HSM_STORE_CALLBACKS c_openssl_hsm_store_cb = {
	NULL, /* store_num */
	NULL, /* store_info_get */
	NULL, /* store_info_free */
	NULL, /* select_slot */
	NULL, /* clear_slot */
	NULL, /* get_objects */
	NULL, /* add_objects */
	NULL, /* del_objects */
	NULL, /* key_wrap */
	NULL, /* key_unwrap */
};

END_C_DECLS
// /* ------------------- Retrieves a stack of objects ------------------- */
// PKI_STACK * HSM_OPENSSL_OBJSK_get_url ( PKI_DATATYPE type, URL *url, 
// 						PKI_CRED *cred, void *hsm );

// int HSM_OPENSSL_OBJSK_add_url ( PKI_STACK *sk, PKI_DATATYPE type, URL *url, 
// 						PKI_CRED *cred, void *hsm );

// int HSM_OPENSSL_OBJSK_del_url ( PKI_STACK *sk, PKI_DATATYPE type, URL *url,
// 						PKI_CRED *cred, void *hsm);

// PKI_MEM_STACK * HSM_OPENSSL_OBJSK_wrap_url ( PKI_STACK *, PKI_DATATYPE type, 
// 					URL *url, PKI_CRED *cred, void *hsm);

// /* --------------------- Internal Functions --------------------------- */
// PKI_X509_KEYPAIR_STACK * HSM_OPENSSL_KEYPAIR_get_url (URL *url, PKI_CRED *cred, 
// 								HSM *hsm);

#endif

