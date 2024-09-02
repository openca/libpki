/* PKCS#11 Object Management Functions */

#ifndef _LIBPKI_HEADERS_PKCS11_OBJSK_H
#define _LIBPKI_HEADERS_PKCS11_OBJSK_H

/* ------------------- Retrieves a stack of objects ------------------- */

PKI_X509_STACK * HSM_PKCS11_OBJSK_get_url ( PKI_DATATYPE type, URL *url, 
			PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm );

int HSM_PKCS11_OBJSK_add_url ( PKI_X509_STACK *sk, URL *url, 
						PKI_CRED *cred, HSM *hsm );

int HSM_PKCS11_OBJSK_del_url ( PKI_DATATYPE, URL *url,
						PKI_CRED *cred, HSM *hsm);

/* --------------------- Internal Functions --------------------------- */

PKI_X509_STACK *HSM_PKCS11_STACK_get_url( PKI_DATATYPE type, URL *url, 
			PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *driver );

int HSM_PKCS11_STACK_add_url( PKI_X509_STACK *sk, URL *url, 
			PKI_CRED *cred, HSM *hsm );

/* ------------------------ get Template(s) functions --------------------- */
int HSM_PKCS11_X509_CERT_get_template (CK_ATTRIBUTE *templ, PKI_X509_CERT *x,
			char *label, int label_len,
			char *id, int id_len );
/* ------------------------ get KEYPAIR functions ------------------------- */
PKI_X509_KEYPAIR_STACK * HSM_PKCS11_KEYPAIR_get_url (URL *url,
			PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm);
PKI_STACK * HSM_PKCS11_KEYPAIR_wrap_url ( URL *url, PKI_CRED *cred, 
			HSM *driver );
PKI_STACK * HSM_PKCS11_KEYPAIR_STACK_wrap ( PKI_X509_KEYPAIR_STACK *sk, 
			PKI_CRED *cred, HSM *driver );
/* ------------------------ add KEYPAIR functions ------------------------- */
int HSM_PKCS11_KEYPAIR_add_url ( PKI_X509_KEYPAIR *pk, URL *url, PKI_CRED *cred,
			HSM *driver );
int HSM_PKCS11_KEYPAIR_STACK_add_url ( PKI_STACK *sk, URL *url, PKI_CRED *cred,
			HSM *driver );
/* ------------------------ Find functions ------------------------------ */

CK_OBJECT_HANDLE * HSM_PKCS11_X509_CERT_find_private_key ( PKI_X509_CERT *x,
			CK_SESSION_HANDLE *hSession, PKCS11_HANDLER *lib );
#endif

