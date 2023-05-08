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

// ================
// OpenSSL Includes
// ================

#ifndef HEADER_SSL_H
#include <openssl/ssl.h>
#endif

// #ifndef _LIBPKI_PKI_DATATYPES_H
// #include <libpki/datatypes.h>
// #endif

#ifndef _LIBPKI_PKI_X509_TYPES_H
#include <libpki/pki_x509_types.h>
#endif

#ifndef _LIBPKI_URL_H
#include <libpki/net/url_types.h>
#endif

/* SSL helper functions */
PKI_SSL * PKI_SSL_new ( const PKI_SSL_ALGOR *algor );
PKI_SSL *PKI_SSL_dup ( PKI_SSL *ssl );
void PKI_SSL_free ( PKI_SSL *ssl );

int PKI_SSL_set_algor ( PKI_SSL *ssl, PKI_SSL_ALGOR *algor );
int PKI_SSL_set_flags ( PKI_SSL *ssl, PKI_SSL_FLAGS flags );
int PKI_SSL_set_cipher ( PKI_SSL *ssl, char *cipher );

int PKI_SSL_set_token ( PKI_SSL *ssl, struct pki_token_st *tk );

int PKI_SSL_set_trusted ( PKI_SSL *ssl, PKI_X509_CERT_STACK *sk );
int PKI_SSL_add_trusted ( PKI_SSL *ssl, PKI_X509_CERT *cert );
int PKI_SSL_set_others ( PKI_SSL *ssl, PKI_X509_CERT_STACK *sk );
int PKI_SSL_add_other ( PKI_SSL *ssl, PKI_X509_CERT *cert );

int PKI_SSL_set_fd ( PKI_SSL *ssl, int fd );
int PKI_SSL_get_fd ( PKI_SSL *ssl );

int PKI_SSL_set_host_name ( PKI_SSL *ssl, const char * hostname );

int PKI_SSL_set_verify ( PKI_SSL *ssl, PKI_SSL_VERIFY vflags );
int PKI_SSL_check_verify ( PKI_SSL *ssl, PKI_SSL_VERIFY flag );

int PKI_SSL_connect_url ( PKI_SSL *ssl, URL *url, int timeout );
int PKI_SSL_connect ( PKI_SSL *ssl, char *url_s, int timeout );

int PKI_SSL_start_ssl ( PKI_SSL *ssl, int fd );
int PKI_SSL_close ( PKI_SSL *ssl );

ssize_t PKI_SSL_write(const PKI_SSL * ssl,
		      const char    * buf,
		      ssize_t         size);

ssize_t PKI_SSL_read(const PKI_SSL * ssl,
		     const char    * buf,
		     ssize_t         size );

struct pki_x509_st * PKI_SSL_get_peer_cert ( PKI_SSL *ssl );
PKI_X509_CERT_STACK * PKI_SSL_get_peer_chain ( PKI_SSL *ssl );

const char *PKI_SSL_get_servername ( PKI_SSL *ssl );

#endif
