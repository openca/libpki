/* libpki/net/pki_pg.h */

#ifndef _LIBPKI_URL_PKCS11_H
#define _LIBPKI_URL_PKCS11_H

#ifdef HAVE_P11

#include <libp11.h>

#endif /* HAVE_P11 */

char *pkcs11_parse_url_libpath(const URL * url);

PKI_MEM_STACK *URL_get_data_pkcs11(const char * url_s,
		                           ssize_t      size );

PKI_MEM_STACK *URL_get_data_pkcs11_url(const URL * url,
		                               ssize_t     size );

#endif /* _LIBPKI_URL_PKCS11_H */
