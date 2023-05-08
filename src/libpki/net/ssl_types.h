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


#ifndef _LIBPKI_PKI_SSL_TYPES_H
#define _LIBPKI_PKI_SSL_TYPES_H

// ================
// OpenSSL Includes
// ================

#ifndef HEADER_SSL_H
#include <openssl/ssl.h>
#endif

/*! \brief Algorithms for PKI_SSL connections */
typedef SSL_METHOD PKI_SSL_ALGOR;

/* Client Algorithms */
#define PKI_SSL_CLIENT_ALGOR_UNKNOWN 0

#ifdef SSL2_VERSION
#define PKI_SSL_CLIENT_ALGOR_SSL2	SSLv2_client_method()
#else
#define PKI_SSL_CLIENT_ALGOR_SSL2	PKI_SSL_CLIENT_ALGOR_UNKNOWN
#endif

#ifdef SSL3_VERSION
#define PKI_SSL_CLIENT_ALGOR_SSL3	SSLv3_client_method()
#else
#define PKI_SSL_CLIENT_ALGOR_SSL3	PKI_SSL_CLIENT_ALGOR_UNKNOWN
#endif

#ifdef TLS1_VERSION
#define PKI_SSL_CLIENT_ALGOR_TLS1	TLSv1_client_method()
#else
#define PKI_SSL_CLIENT_ALGOR_TLS1	PKI_SSL_CLIENT_ALGOR_UNKNOWN
#endif

#ifdef TLS1_1_VERSION
#define PKI_SSL_CLIENT_ALGOR_TLS1_1 TLSv1_1_client_method()
#else
#define PKI_SSL_CLIENT_ALGOR_TLS1_1 PKI_SSL_CLIENT_ALGOR_UNKNOWN
#endif

#ifdef TLS1_2_VERSION
#define PKI_SSL_CLIENT_ALGOR_TLS1_2 TLSv1_2_client_method()
#else
#define PKI_SSL_CLIENT_ALGOR_TLS1_2 PKI_SSL_CLIENT_ALGOR_UNKNOWN
#endif

#ifdef DTLSv1_client_method
#define PKI_SSL_CLIENT_ALGOR_DTLS1	DTLSv1_client_method()
#else
#define PKI_SSL_CLIENT_ALGOR_DTLS1  PKI_SSL_CLIENT_ALGOR_UNKNOWN
#endif

/* Generic method that implements all SSLv2, SSLv3, TLSv1.0,
 * TLSv1.1, and TLSv1.2 */
#define PKI_SSL_CLIENT_ALGOR_ALL SSLv23_client_method()

/* Default Client Method */
#define PKI_SSL_CLIENT_ALGOR_DEFAULT PKI_SSL_CLIENT_ALGOR_ALL

/* Server Algorithms */
#define PKI_SSL_SERVER_ALGOR_UNKNOWN 0

#ifdef SSL2_VERSION
#define PKI_SSL_SERVER_ALGOR_SSL2	SSLv2_server_method()
#else
#define PKI_SSL_SERVER_ALGOR_SSL2	PKI_SSL_SERVER_ALGOR_UNKNOWN
#endif

#ifdef SSL3_VERSION
#define PKI_SSL_SERVER_ALGOR_SSL3	SSLv3_server_method()
#else
#define PKI_SSL_SERVER_ALGOR_SSL3	PKI_SSL_SERVER_ALGOR_UNKNOWN
#endif

#ifdef TLS1_VERSION
#define PKI_SSL_SERVER_ALGOR_TLS1	TLSv1_server_method()
#else
#define PKI_SSL_SERVER_ALGOR_TLS1 PKI_SSL_SERVER_ALGOR_UNKNOWN
#endif

#ifdef TLS1_1_VERSION
#define PKI_SSL_SERVER_ALGOR_TLS1_1	TLSv1_1_server_method()
#else
#define PKI_SSL_SERVER_ALGOR_TLS1_1	PKI_SSL_SERVER_ALGOR_UNKNOWN
#endif

#ifdef TLS1_2_VERSION
#define PKI_SSL_SERVER_ALGOR_TLS1_2	TLSv1_2_server_method()
#else
#define PKI_SSL_SERVER_ALGOR_TLS1_2	PKI_SSL_SERVER_ALGOR_UNKNOWN
#endif

#ifdef DTLSv1_server_method
#define PKI_SSL_SERVER_ALGOR_DTLS1	DTLSv1_server_method()
#else
#define PKI_SSL_SERVER_ALGOR_DTLS1	PKI_SSL_SERVER_ALGOR_UNKNOWN
#endif

/* Generic method that implements all SSLv2, SSLv3, TLSv1.0,
 * TLSv1.1, and TLSv1.2 */
#define PKI_SSL_SERVER_ALGOR_ALL	SSLv23_server_method()

/* Default Server Method */
#define PKI_SSL_SERVER_ALGOR_DEFAULT PKI_SSL_SERVER_ALGOR_TLS1_2

/*! \brief Flags for algorithm exclusion in PKI_SSL connections */

typedef enum {
#ifdef SSL_OP_NO_SSLv2
	PKI_SSL_FLAGS_NO_SSL2		= SSL_OP_NO_SSLv2,
#else
	PKI_SSL_FLAGS_NO_SSL2		= 0,
#endif
#ifdef SSL_OP_NO_SSLv3
	PKI_SSL_FLAGS_NO_SSL3		= SSL_OP_NO_SSLv3,
#else
	PKI_SSL_FLAGS_NO_SSL3		= 0,
#endif
#ifdef SSL_OP_NO_TLSv1
	PKI_SSL_FLAGS_NO_TLS1		= SSL_OP_NO_TLSv1,
#else
	PKI_SSL_FLAGS_NO_TLS1		= 0,
#endif
#ifdef SSL_OP_NO_TLSv1_1
	PKI_SSL_FLAGS_NO_TLS1_1	= SSL_OP_NO_TLSv1_1,
#else
	PKI_SSL_FLAGS_NO_TLS1_1	= 0,
#endif
#ifdef SSL_OP_NO_TLSv1_2
	PKI_SSL_FLAGS_NO_TLS1_2	= SSL_OP_NO_TLSv1_2,
#else
	PKI_SSL_FLAGS_NO_TLS1_2	= 0,
#endif
#ifdef SSL_OP_NO_DTLSv1
	PKI_SSL_FLAGS_NO_DTLS1		= SSL_OP_NO_DTLSv1,
#else
	PKI_SSL_FLAGS_NO_DTLS1		= 0,
#endif

} PKI_SSL_FLAGS;

#define PKI_SSL_FLAGS_DEFAULT \
 (PKI_SSL_FLAGS_NO_SSL2 | PKI_SSL_FLAGS_NO_SSL3)

/*! \brief Flags for Verify Behavior: PRQP, CRL, OCSP */

typedef enum {
	PKI_SSL_VERIFY_NONE           = 0,
	PKI_SSL_VERIFY_PEER           = 1,
	PKI_SSL_VERIFY_PEER_REQUIRE   = 2,
	PKI_SSL_VERIFY_CRL            = 4,
	PKI_SSL_VERIFY_CRL_REQUIRE    = 8,
	PKI_SSL_VERIFY_OCSP           = 16,
	PKI_SSL_VERIFY_OCSP_REQUIRE   = 32,
	PKI_SSL_VERIFY_NO_SELFSIGNED  = 64,
	PKI_SSL_VERIFY_ENABLE_PRQP    = 128,
} PKI_SSL_VERIFY;

#define PKI_SSL_VERIFY_NORMAL \
		PKI_SSL_VERIFY_CRL | \
		PKI_SSL_VERIFY_OCSP | \
		PKI_SSL_VERIFY_ENABLE_PRQP

#define PKI_SSL_VERIFY_REQUIRE \
		PKI_SSL_VERIFY_CRL_REQUIRE | \
		PKI_SSL_VERIFY_OCSP_REQUIRE | \
		PKI_SSL_VERIFY_ENABLE_PRQP

/* Ciphers for the different protocols */
#define PKI_SSL_CIPHERS_SSL3 \
	"HIGH:MEDIUM:!NULL"

#define PKI_SSL_CIPHERS_TLS1 \
	"ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA" \
	":DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA"        \
	":ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA"    \
	":ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA"  \
	":DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA"        \
	":PSK-AES128-CBC-SHA"

#define PKI_SSL_CIPHERS_TLS1_1 \
	":TLS_RSA_WITH_IDEA_CBC_SHA:TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:" \
	":TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:"                          \
	":ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA"               \
	":DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA"                       \
	":ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA"                   \
	":ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA"                 \
	":DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA"                       \
	":PSK-AES128-CBC-SHA"

#define PKI_SSL_CIPHERS_TLS1_2 \
	"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384"  \
	":ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384"         \
	":DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256"           \
	":ECDH-RSA-AES256-GCM-SHA384:ECDH-ECDSA-AES256-GCM-SHA384"   \
	":ECDH-RSA-AES256-SHA384:ECDH-ECDSA-AES256-SHA384"           \
	":ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256" \
	":ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256"         \
	":DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256"           \
	":ECDH-RSA-AES128-GCM-SHA256:ECDH-ECDSA-AES128-GCM-SHA256"   \
	":ECDH-RSA-AES128-SHA256:ECDH-ECDSA-AES128-SHA256"           \
	":AES256-GCM-SHA384:AES256-SHA256"                           \
	":AES128-GCM-SHA256:AES128-SHA256"

#define PKI_SSL_CIPHERS_ALL       \
	PKI_SSL_CIPHERS_TLS1_2    \
	PKI_SSL_CIPHERS_TLS1_1    \
	PKI_SSL_CIPHERS_TLS1      \
	PKI_SSL_CIPHERS_SSL3

/* Default SSL/TLS Ciphers */
#define PKI_SSL_CIPHERS_DEFAULT \
	PKI_SSL_CIPHERS_TLS1_2

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
	const PKI_SSL_ALGOR *algor;

	/* Pointer to the PKI_TOKEN to be used for the communication */
	struct pki_token_st *tk;

	/* PKI_X509_CERT_STACK of trusted certificates */
	PKI_X509_CERT_STACK *trusted_certs;

	/* PKI_X509_CERT_STACK of other certificates (e.g., SubCAs to facilitate
	 * the certificate's chain building) */
	PKI_X509_CERT_STACK *other_certs;

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

#endif // End of _LIBPKI_PKI_SSL_ST_H
