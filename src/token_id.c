/* TOKEN ID Object Management Functions */

#include <libpki/pki.h>

/* Set the ID to be used for current operations */
int PKI_TOKEN_ID_set ( PKI_TOKEN *tk, int id ) {
	return ( PKI_ERR );
}

/* Get the number of available IDs from the current token */
int PKI_TOKEN_ID_num ( PKI_TOKEN *tk ) {

	return ( 0 );
}

/* Get the list of IDs from the Token */
PKI_ID_INFO_STACK *PKI_TOKEN_ID_INFO_list ( PKI_TOKEN *tk ) {

	return ( NULL );
}

/* Get the PKI_ID_INFO from the TOKEN */
PKI_ID_INFO * PKI_TOKEN_ID_INFO_get ( PKI_TOKEN *tk, int num ) {

	return ( NULL );
}

