/* openca/pkicrypto/url.h */
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


#ifndef _LIBPKI_PKI_SSL_H
#define _LIBPKI_PKI_SSL_H

#include <openssl/ssl.h>

/*! \brief Algorithms for PKI_SSL connections */
#define PKI_SSL_ALGOR			SSL_METHOD

/* Client Algorithms */
#define PKI_SSL_CLIENT_ALGOR_SSL2	SSLv2_client_method()
#define PKI_SSL_CLIENT_ALGOR_SSL3	SSLv3_client_method()
#define PKI_SSL_CLIENT_ALGOR_TLS1	TLSv1_client_method()
#define PKI_SSL_CLIENT_ALGOR_DTLS1	DTLSv1_client_method()

/* Server Algorithms */
#define PKI_SSL_SERVER_ALGOR_SSL2	SSLv2_server_method()
#define PKI_SSL_SERVER_ALGOR_SSL3	SSLv3_server_method()
#define PKI_SSL_SERVER_ALGOR_TLS1	TLSv1_server_method()
#define PKI_SSL_SERVER_ALGOR_DTLS1	DTLSv1_server_method()

/*! \brief Flags for algorithm exclusion in PKI_SSL connections */

typedef enum {
	PKI_SSL_FLAGS_NO_SSL2		= SSL_OP_NO_SSLv2,
	PKI_SSL_FLAGS_NO_SSL3		= SSL_OP_NO_SSLv3,
	PKI_SSL_FLAGS_NO_TLS1		= SSL_OP_NO_TLSv1,
#ifdef SSL_OP_NO_DTLSv1
	PKI_SSL_FLAGS_NO_DTLS1		= SSL_OP_NO_DTLSv1,
#else
	PKI_SSL_FLAGS_NO_DTLS1		= 0,
#endif

} PKI_SSL_FLAGS;

/*! \brief Flags for Verify Behavior: PRQP, CRL, OCSP */

typedef enum {
	PKI_SSL_VERIFY_NONE			= 0,
	PKI_SSL_VERIFY_PEER			= 1,
	PKI_SSL_VERIFY_PEER_REQUIRE		= 2,
	PKI_SSL_VERIFY_CRL			= 4,
	PKI_SSL_VERIFY_CRL_REQUIRE		= 8,
	PKI_SSL_VERIFY_OCSP			= 16,
	PKI_SSL_VERIFY_OCSP_REQUIRE		= 32,
	PKI_SSL_VERIFY_NO_SELFSIGNED		= 64,
	PKI_SSL_VERIFY_ENABLE_PRQP		= 128,
} PKI_SSL_VERIFY;

#define PKI_SSL_VERIFY_NORMAL \
		PKI_SSL_VERIFY_CRL | \
		PKI_SSL_VERIFY_OCSP | \
		PKI_SSL_VERIFY_ENABLE_PRQP

#define PKI_SSL_VERIFY_REQUIRE \
		PKI_SSL_VERIFY_CRL_REQUIRE | \
		PKI_SSL_VERIFY_OCSP_REQUIRE | \
		PKI_SSL_VERIFY_ENABLE_PRQP

/*! \brief PKI_SSL data structure for SSL/TLS */

typedef struct  pki_ssl_t {

	/* Connection flags -> to disable specific SSL/TLS versions */
	int flags;

	/* Authentication -> none, client, server, all */
	int auth;

	/* Pointers to the OpenSSL data structures */
	SSL *ssl;
	SSL_CTX *ssl_ctx;
	char *cipher;
	PKI_SSL_ALGOR *algor;

	/* Pointer to the PKI_TOKEN to be used for the communication */
	struct pki_token_st *tk;

	/* PKI_X509_CERT_STACK of trusted certificates */
	PKI_X509_CERT_STACK *trusted_certs;

	/* Set to 1 while the socket is connected, 0 otherwise */
	int connected;

	/* Server name - used to set the TLS extension */
	char *servername;

	/* Not Used, yet */
	char *session;

	/* After authentication, if set to 1 we continue */
	int verify_ok;

	/* Enabling certificate validation flags */
	unsigned int verify_flags;

	/* Peer Certificates Chain */
	PKI_X509_CERT_STACK *peer_chain;

} PKI_SSL;
	
#include <libpki/net/url.h>

/* SSL helper functions */
PKI_SSL * PKI_SSL_new ( PKI_SSL_ALGOR *algor );
PKI_SSL *PKI_SSL_dup ( PKI_SSL *ssl );
void PKI_SSL_free ( PKI_SSL *ssl );

int PKI_SSL_set_algor ( PKI_SSL *ssl, PKI_SSL_ALGOR *algor );
int PKI_SSL_set_flags ( PKI_SSL *ssl, PKI_SSL_FLAGS flags );
int PKI_SSL_set_cipher ( PKI_SSL *ssl, char *cipher );

int PKI_SSL_set_fd ( PKI_SSL *ssl, int fd );
int PKI_SSL_get_fd ( PKI_SSL *ssl );

int PKI_SSL_set_verify ( PKI_SSL *ssl, PKI_SSL_VERIFY vflags );
int PKI_SSL_check_verify ( PKI_SSL *ssl, PKI_SSL_VERIFY flag );

int PKI_SSL_connect_url ( PKI_SSL *ssl, URL *url, int timeout );
int PKI_SSL_connect ( PKI_SSL *ssl, char *url_s, int timeout );

int PKI_SSL_start_ssl ( PKI_SSL *ssl, int fd );

int PKI_SSL_set_token ( PKI_SSL *ssl, struct pki_token_st *tk );
int PKI_SSL_set_trusted ( PKI_SSL *ssl, PKI_X509_CERT_STACK *sk );
int PKI_SSL_close ( PKI_SSL *ssl );

ssize_t PKI_SSL_write ( PKI_SSL *ssl, char * buf, ssize_t size );
ssize_t PKI_SSL_read ( PKI_SSL *ssl, char * buf, ssize_t size );

struct pki_x509_st * PKI_SSL_get_peer_cert ( PKI_SSL *ssl );
PKI_X509_CERT_STACK * PKI_SSL_get_peer_chain ( PKI_SSL *ssl );

const char *PKI_SSL_get_servername ( PKI_SSL *ssl );

#endif
