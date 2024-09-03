/*
 * PRQP Library - HTTP client functions
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

#ifndef _LIBPKI_PRQP_HTTP_CLIENT_H
#define _LIBPKI_PRQP_HTTP_CLIENT_H

/* Functions */
/*
BIO *http_connect( URL *url );
BUF_MEM *http_get_data ( BIO *in, ssize_t max_size );
PKI_PRQP_RESP *PRQP_http_get_resp ( URL *url, PKI_PRQP_REQ *req, unsigned long max_size );
BUF_MEM *http_get ( URL *url, unsigned long max_size, char *version );
int parse_http_headers ( BIO *in );
*/

PKI_X509_PRQP_RESP *PKI_X509_PRQP_RESP_get_http ( URL *url,
                PKI_X509_PRQP_REQ *req, unsigned long max_size );

#endif
