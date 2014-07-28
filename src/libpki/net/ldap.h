/*
 * LIBPKI - Easy PKI Library
 * by Massimiliano Pala (madwolf@openca.org)
 * OpenCA project 2007
 *
 * Copyright (c) 2007 The OpenCA Project.  All rights reserved.
 *
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#ifndef _LIBPKI_LDAP_H
#define _LIBPKI_LDAP_H

#if defined(LDAP_VENDOR_SUN) || defined (LDAP_VENDOR_OPENLDAP) || \
	defined(LDAP_VENDOR_MICROSOFT)
#include <ldap.h>

LDAP *URL_LDAP_connect( URL *url, int timeout );
PKI_MEM_STACK *URL_get_data_ldap_url(URL *url, int timeout, ssize_t size);

#endif

#endif
