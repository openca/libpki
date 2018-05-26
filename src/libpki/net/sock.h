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

#ifndef __OPENCA_SOCK_WRAP_H
#define __OPENCA_SOCK_WRAP_H

#ifdef HAVE_SYS_SOCKET_H
# include <sys/select.h>
#else
# include <sys/types.h>
# include <sys/socket.h>
#endif

#include <netdb.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <strings.h>
#include <string.h>

#include <libpki/net/url.h>

#define INTERRUPTED_BY_SIGNAL (errno == EINTR || errno == ECHILD)

#define SA struct sockaddr

typedef enum {
	PKI_NET_SOCK_STREAM		= SOCK_STREAM,
	PKI_NET_SOCK_DGRAM		= SOCK_DGRAM,
} PKI_NET_SOCK_TYPE;

/* Public Functions */
int PKI_NET_socket(int family, int type, int protocol);
int PKI_NET_listen(const char *host, int port, PKI_NET_SOCK_TYPE socktype);
int PKI_NET_accept(int sock, int timeout);
int PKI_NET_open(const URL *url, int timeout);
int PKI_NET_close(int sock);
ssize_t PKI_NET_write (int fd, const void *bufptr, size_t nbytes);
ssize_t PKI_NET_read (int fd, const void *bufptr, size_t nbytes, int timeout);
PKI_MEM *PKI_NET_get_data ( int fd, int timeout, size_t max_size );

/* Datagrams functions */
ssize_t PKI_NET_recvfrom (int fd, const void *bufptr, size_t nbytes, const struct sockaddr_in *cli, socklen_t size);
ssize_t PKI_NET_sendto (int sock, const char *host, int port, const void *data, size_t len);

/* Internal Socket Wrapping functions */
int _Listen (const char *hostname, int port, PKI_NET_SOCK_TYPE socktype);
int _Accept (int listen_sockfd, const SA *cliaddr, const socklen_t *addrlenp);
ssize_t _Read (int fd, const void *bufptr, size_t nbytes);
ssize_t _Write (int fd, const void *bufptr, size_t nbytes);
int _Select (int maxfdp1, fd_set *readset, fd_set *writeset, 
			fd_set *exceptset, struct timeval *timeout);

/* Externally available functions */
int inet_connect ( const URL *url );
int inet_close ( int fd );

#endif
