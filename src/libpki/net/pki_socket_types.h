/*
 * LIBPKI - OpenSource PKI library
 * by Massimiliano Pala (madwolf@openca.org) and OpenCA project
 *
 * Copyright (c) 2001-2007 The OpenCA Project.  All rights reserved.
 *
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#ifndef _LIBPKI_PKI_SOCKET_TYPES_H_
#define _LIBPKI_PKI_SOCKET_TYPES_H_

#ifndef _LIBPKI_PKI_SSL_TYPES_H
#include <libpki/net/ssl_types.h>
#endif

#ifndef _LIBPKI_URL_TYPES_H
#include <libpki/net/url_types.h>
#endif

BEGIN_C_DECLS

typedef enum {
	PKI_SOCKET_TYPE_UNKNOWN = -1,
	PKI_SOCKET_FD	   = 0,
	PKI_SOCKET_SSL	   = 1,
} PKI_SOCKET_TYPE;

typedef enum {
	PKI_SOCKET_DISCONNECTED		= 0,
	PKI_SOCKET_CONNECTED		= 1,
} PKI_SOCKET_STATUS;

typedef struct pki_socket_st {
	PKI_SOCKET_TYPE type;
	int status;

	int fd;
	PKI_SSL *ssl;

	URL *url;

} PKI_SOCKET;

END_C_DECLS

#endif
