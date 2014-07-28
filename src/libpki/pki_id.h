/* ID management for libpki */

#ifndef _LIBPKI_PKI_ID_H
#define _LIBPKI_PKI_ID_H

PKI_ID PKI_ID_get_by_name ( char *name );
PKI_ID PKI_ID_get( PKI_ID id );
const char * PKI_ID_get_txt( PKI_ID id );

#endif


