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

#ifndef _LIBPKI_PKI_SOCKET_H_
#define _LIBPKI_PKI_SOCKET_H_

#include <libpki/net/ssl.h>

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

// #include <libpki/net/url.h>

/* PKI_SOCKET management functions */
PKI_SOCKET *PKI_SOCKET_new ( void );
PKI_SOCKET *PKI_SOCKET_new_ssl ( PKI_SSL *ssl );
PKI_SOCKET *PKI_SOCKET_new_fd ( int fd );
void PKI_SOCKET_free ( PKI_SOCKET *sock);

int PKI_SOCKET_set_flags(PKI_SOCKET * sock,
		         int          flags);

int PKI_SOCKET_set_trusted(PKI_SOCKET          * sock,
		           PKI_X509_CERT_STACK * sk);

int PKI_SOCKET_open(PKI_SOCKET * sock,
		    const char * url_s,
		    int          timeout);

int PKI_SOCKET_open_url(PKI_SOCKET * sock,
		        const URL  * url_s,
			int          timeout);

int PKI_SOCKET_connect(PKI_SOCKET * sock,
		       const URL  * url,
		       int          timeout );

int PKI_SOCKET_connect_ssl(PKI_SOCKET * sock,
		           const URL  * url,
			   int          timeout );

int PKI_SOCKET_close(PKI_SOCKET *sock);

int PKI_SOCKET_set_ssl(PKI_SOCKET * sock,
		       PKI_SSL    * ssl );

const PKI_SSL * PKI_SOCKET_get_ssl(const PKI_SOCKET *sock);

int PKI_SOCKET_set_fd(PKI_SOCKET * sock,
		      int          fd );

int PKI_SOCKET_get_fd(const PKI_SOCKET * sock);

int PKI_SOCKET_start_ssl(PKI_SOCKET * sock);

ssize_t PKI_SOCKET_read(const PKI_SOCKET * sock,
		        const char       * buf,
			size_t             n,
			int                timeout );

ssize_t PKI_SOCKET_write(const PKI_SOCKET * sock,
		         const char       * buf,
			 size_t             n);

const URL * PKI_SOCKET_get_url(const PKI_SOCKET * sock);

#endif
