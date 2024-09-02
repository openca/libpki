/*
 * LIBPKI - Easy PKI Library
 * by Massimiliano Pala (madwolf@openca.org)
 *
 * Copyright (c) 2007-2012 by Massimiliano Pala and OpenCA Labs.
 * All rights reserved.
 *
 * ====================================================================
 *
 */

#ifndef _LIBPKI_DNS_H
#define _LIBPKI_DNS_H

#ifdef HAVE_LIBRESOLV
#include <netinet/in.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#ifndef T_AAAA
#include <arpa/nameser_compat.h>
#endif
#include <resolv.h>
#endif

enum pki_dns {
	pki_ns_t_address = 300
};

#ifndef T_CERT
#define T_CERT	36
#endif

PKI_MEM_STACK *URL_get_data_dns_url(const URL * url,
		                            ssize_t     size);

int URL_get_dns_type(const char *str);

#endif
