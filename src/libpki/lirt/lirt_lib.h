/* LIRT Data Structure Management Functions
 * (c) 2004-2012 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 *
 * OpenCA Licensed Software :: GPLv2
 */

#ifndef _LIBPKI_X509_LIRT_LIB_H
#define _LIBPKI_X509_LIRT_LIB_H

void PKI_X509_LIRT_free_void( void *x );
void PKI_X509_LIRT_free ( PKI_X509_LIRT *x );

PKI_LIRT *PKI_LIRT_new_null ( void );
PKI_X509_LIRT *PKI_X509_LIRT_new_null ( void );

#endif
