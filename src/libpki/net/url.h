/* net/url.h */
/*
 * LIBPKI - OpenSource PKI library
 * by Massimiliano Pala (madwolf@openca.org) and OpenCA project
 *
 * Copyright (c) 2001-2008 The OpenCA Project.  All rights reserved.
 *
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */


#ifndef _LIBPKI_URL_H
#define _LIBPKI_URL_H

typedef enum {
	URI_PROTO_FILE			= 0,
	URI_PROTO_LDAP			= 1,
	URI_PROTO_HTTP			= 2,
	URI_PROTO_HTTPS			= 3,
	URI_PROTO_FTP			= 4,
	URI_PROTO_ID			= 5,
	URI_PROTO_FD			= 6,
	URI_PROTO_MYSQL			= 10,
	URI_PROTO_PG			= 20,
	URI_PROTO_PKCS11		= 30,
	URI_PROTO_SOCK			= 40,
	URI_PROTO_DNS			= 50,
} URI_PROTO;

#define DEFAULT_LDAP_PORT		389
#define DEFAULT_HTTP_PORT		80
#define DEFAULT_HTTPS_PORT		443
#define DEFAULT_FTP_PORT		21
#define DEFAULT_MYSQL_PORT		3306
#define DEFAULT_PG_PORT			3456
#define DEFAULT_PKCS11_PORT		-1
#define DEFAULT_DNS_PORT		-1

#include <libpki/stack.h>

typedef struct url_data_st {

	/* Original URL string */
	char * url_s;

	/* Protocol, currently supported LDAP and FILE */
	URI_PROTO proto;

	/* URL requires SSL/TLS :: 0 = NO, 1 = YES */
	int ssl;

	/* Address or filename */
	char *addr;

	/* Communication Port (where supported by the protocol) */
	int port;

	/* Authentication (where supported by the protocol) */
	char *usr;
	char *pwd;

	/* Search facility - for LDAP the DN is in the path, while
	   the attributes for filtering the responses are here in
	   the attrs stack. The same for mysql:// or postgres://
	   urls */
	char *attrs;

	/* Path - Used by HTTP/LDAP/ID/etc... */
	char *path;

	/* Object Number - Used to identify a specific object
	   when multiple objects are matched */
	int object_num;
} URL;

typedef struct http_headers {

	/* Method */
	PKI_HTTP_METHOD method;

	/* HTTP version as float number */
	float version;

	/* Returned Code */
	int code;

	/* Returned Location - in case a 30X is found */
	char *location;

	/* Content Type */
	char *type;

	/* URL for GET methods */
	// URL *url;

	/* Path */
	char *path;

	/* Protocol */
	int proto;

	/* Headers Data */
	PKI_MEM *head;

	/* HTTP body data */
	PKI_MEM *body;

} PKI_HTTP;

#define LIBPKI_URL_BUF_SIZE	8192

#include <libpki/pki_mem.h>
#include <libpki/net/pki_socket.h>

/* ----------------------- URL Function prototypes --------------------- */
void URL_free ( URL *url );
URL *URL_new ( char *url );
char *URL_get_parsed ( URL *url );

const char *URL_proto_to_string ( URI_PROTO proto );
char * URL_get_local_addr ( void );

/* ----------------------- URL wrapping functions ---------------------- */
PKI_MEM_STACK *URL_get_data ( char *url_s, int timeout, 
				ssize_t max_size, PKI_SSL *ssl );
PKI_MEM_STACK *URL_get_data_url ( URL *url, int timeout, 
				ssize_t max_size, PKI_SSL *ssl );
PKI_MEM_STACK *URL_get_data_socket ( PKI_SOCKET *sock, int timeout, 
				ssize_t size );

int URL_put_data ( char *url_s, PKI_MEM *data, char *contType, 
			PKI_MEM_STACK **ret_sk, int timeout, ssize_t max_size, 
				PKI_SSL *ssl );

int URL_put_data_url ( URL *url, PKI_MEM *data, char *contType,
			PKI_MEM_STACK **ret_sk, int timeout, ssize_t max_size, 
				PKI_SSL *ssl );

int URL_put_data_socket (PKI_SOCKET *sock, PKI_MEM *data, char *contType, 
		PKI_MEM_STACK **ret_sk, int timeout, ssize_t max_size );

/* ------------------------ Actual I/O implementation ------------------- */
PKI_MEM_STACK *URL_get_data_fd( URL *url, ssize_t size );
PKI_MEM_STACK *URL_get_data_file( URL *url, ssize_t size );

int URL_put_data_fd ( URL *url, PKI_MEM *data );
int URL_put_data_file ( URL *url, PKI_MEM *data );

/* ---------------------------- URL macros ------------------------------ */
#define getParsedUrl( a ) URL_new ( a )

#endif
