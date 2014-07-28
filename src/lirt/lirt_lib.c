/* LIRT Data Structure Management Functions
 * (c) 2004-2012 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 *
 * OpenCA Licensed Software :: GPLv2
 */

#include <libpki/pki.h>

void PKI_X509_LIRT_free_void( void *x ) {
	PKI_X509_LIRT_free((PKI_X509_LIRT *)x);
}

void PKI_X509_LIRT_free ( PKI_X509_LIRT *x ) {
	if (!x) return;

	PKI_X509_free ( x );

	return;
}


/*! \brief Create an empty LIRT data structure */

PKI_LIRT *PKI_LIRT_new_null ( void ) {
	PKI_LIRT *ret = NULL;

	if((ret = PKI_LIRT_new()) == NULL ) {
		return ( NULL );
	}

	return ( ret );
}

PKI_X509_LIRT *PKI_X509_LIRT_new_null ( void ) {
	PKI_X509_LIRT *ret = NULL;

	if((ret = PKI_X509_new ( PKI_DATATYPE_X509_LIRT, NULL )) == NULL ) {
		return NULL;
	}

	if((ret->value = PKI_LIRT_new()) == NULL ) {
		PKI_X509_free ( ret );
		return NULL;
	}

	return ret;
}


