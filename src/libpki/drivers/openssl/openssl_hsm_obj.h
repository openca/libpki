/* ENGINE Object Management Functions */

#ifndef _LIBPKI_HEADERS_OPENSSL_OBJSK_H
#define _LIBPKI_HEADERS_OPENSSL_OBJSK_H

/* ------------------- Retrieves a stack of objects ------------------- */
PKI_STACK * HSM_OPENSSL_OBJSK_get_url ( PKI_DATATYPE type, URL *url, 
						PKI_CRED *cred, void *hsm );

int HSM_OPENSSL_OBJSK_add_url ( PKI_STACK *sk, PKI_DATATYPE type, URL *url, 
						PKI_CRED *cred, void *hsm );

int HSM_OPENSSL_OBJSK_del_url ( PKI_STACK *sk, PKI_DATATYPE type, URL *url,
						PKI_CRED *cred, void *hsm);

PKI_MEM_STACK * HSM_OPENSSL_OBJSK_wrap_url ( PKI_STACK *, PKI_DATATYPE type, 
					URL *url, PKI_CRED *cred, void *hsm);

/* --------------------- Internal Functions --------------------------- */
PKI_X509_KEYPAIR_STACK * HSM_OPENSSL_KEYPAIR_get_url (URL *url, PKI_CRED *cred, 
								HSM *hsm);
#endif

