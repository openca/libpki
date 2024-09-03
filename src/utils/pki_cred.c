/* src/pki_cred.c */

#include <libpki/pki.h>

/*!
 * \brief Allocates a new PKI_CRED structure
 *
 * Allocates memory for a new PKI_CRED structure. The returned data
 * structure contains a copy (strdup) of the passed user and pwd
 * strings.
 *
 * The function returns a pointer to a PKI_CRED structure in case
 * of success, otherwise it returns NULL.
 */

PKI_CRED *PKI_CRED_new ( const char * const user, const char * const pwd ) {

	PKI_CRED * cred = NULL;

	if ((cred = PKI_CRED_new_null()) == NULL )
		return ( NULL );

	memset(cred, 0, sizeof(PKI_CRED));

	if (user) cred->username = strdup( user );
	if (pwd) cred->password = strdup( pwd );

	return ( cred );
}

/*!
 * \brief Allocates a new PKI_CRED structure
 *
 * Allocates memory for a new PKI_CRED structure. The returned data
 * structure is already zeroized.
 *
 * The function returns a pointer to a PKI_CRED structure in case
 * of success, otherwise it returns NULL.
 */

PKI_CRED *PKI_CRED_new_null ( void ) {

	PKI_CRED *c = NULL;

	c = (PKI_CRED *) PKI_Malloc (sizeof(PKI_CRED));

	return (c);
}

/*!
 * \brief Free a PKI_CRED memory region
 *
 * This function frees a PKI_CRED data structure. The internal data
 * is also freed (no need to free the internal structures before
 * calling this function.
 *
 * No value is returned (void).
 */

void PKI_CRED_free( PKI_CRED *cred ) {

	if( !cred ) return;

	if( cred->password != NULL ) {
		PKI_ZFree_str ( (char *) cred->password );
	}

	if( cred->username != NULL ) {
		PKI_ZFree_str ( (char *) cred->username );
	}

	if( cred->prompt_info != NULL ) {
		PKI_ZFree_str ( (char *) cred->prompt_info );
	}

	if( cred->ssl != NULL ) {
		PKI_SSL_free((PKI_SSL *)cred->ssl);
	}

	PKI_Free( cred );

	return;
}

/*! \brief Duplicates a PKI_CRED data structure */

PKI_CRED *PKI_CRED_dup ( const PKI_CRED * const cred ) {

	PKI_CRED *ret = NULL;

	if (!cred ) return ( NULL );

	if (( ret = PKI_CRED_new_null()) == NULL ) return NULL;

	if( cred->password != NULL ) {
		ret->password = strdup ( cred->password );
	}

	if( cred->username != NULL ) {
		ret->username = strdup ( cred->username );
	}

	if( cred->prompt_info != NULL ) {
		ret->prompt_info = strdup ( cred->prompt_info );
	}

	if( cred->ssl != NULL ) {
		PKI_log_debug("WARNING: Cred's PKI_SSL will not duplicate!");
	}

	return ( ret );
}

/*! \brief Sets the SSL configuration for Creds */

int PKI_CRED_set_ssl(PKI_CRED *cred, struct pki_ssl_t * const ssl) {

	if (!cred || !ssl) return PKI_ERR;

	if (cred->ssl) {
		PKI_log_debug( "Warning: overriding existing CRED SSL");
	}

	cred->ssl = ssl;

	return PKI_OK;
}

/*! \brief Gets the pointer to the PKI_SSL structure inside a CRED */

const struct pki_ssl_t * PKI_CRED_get_ssl(const PKI_CRED * const cred) {

	if (!cred || !cred->ssl) return NULL;

	return cred->ssl;
}
