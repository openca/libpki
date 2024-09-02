/* src/pki_cred.c */


#ifndef _LIBPKI_PKI_CRED_H
#define _LIBPKI_PKI_CRED_H

#include <sys/types.h>

// typedef pki_ssl_st;

typedef struct pki_cred_st {
	const char *username;
	const char *password;
	const char *prompt_info;
	ssize_t len;

	// struct pki_ssl_st *ssl;
	struct pki_ssl_t *ssl;
} PKI_CRED;

PKI_CRED *PKI_CRED_new_null ( void );
PKI_CRED *PKI_CRED_new ( const char * const user, const char * const pwd );

void PKI_CRED_free(PKI_CRED *cred);
PKI_CRED *PKI_CRED_dup ( const PKI_CRED * const cred );

const struct pki_ssl_t * PKI_CRED_get_ssl(const PKI_CRED * const cred);
int PKI_CRED_set_ssl(PKI_CRED *cred, struct pki_ssl_t * const ssl);

#endif
