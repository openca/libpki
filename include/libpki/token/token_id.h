/* TOKEN ID Object Management Functions */

#ifndef _LIBPKI_TOKEN_ID_HEADERS_H
#define _LIBPKI_TOKEN_ID_HEADERS_H

/* Set the ID to be used for current operations */
int PKI_TOKEN_ID_set ( PKI_TOKEN *tk, int id );

/* Get the number of available IDs from the current token */
int PKI_TOKEN_ID_num ( PKI_TOKEN *tk );

/* Get the list of IDs from the Token */
PKI_ID_INFO_STACK *PKI_TOKEN_ID_INFO_list ( PKI_TOKEN *tk );

/* Get the PKI_ID_INFO from the TOKEN */
PKI_ID_INFO * PKI_TOKEN_ID_INFO_get ( PKI_TOKEN *tk, int num );

#endif

