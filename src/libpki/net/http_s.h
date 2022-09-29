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


#ifndef _LIBPKI_PKI_HTTP_H
#define _LIBPKI_PKI_HTTP_H

#include <libpki/pki_mem.h>
#include <libpki/net/url.h>
#include <libpki/stack.h>

#include <openssl/ssl.h>

#define LIBPKI_HTTP_BUF_SIZE		8192
#define LIBPKI_HTTPS_BUF_SIZE		8192

/* ----------------------------- HTTP HELP Functions -------------------- */

void PKI_HTTP_free(PKI_HTTP *rv);

PKI_HTTP * PKI_HTTP_new(void);

char * PKI_HTTP_get_header_txt(const char * data,
		                       const char * header);

char * PKI_HTTP_get_header(const PKI_HTTP * http,
		                   const char     * header);

PKI_HTTP *PKI_HTTP_get_message(const PKI_SOCKET * sock,
		                       int                timeout,
							   size_t             max_size);

/* --------------------- HTTP Generic GET/POST Functions ---------------- */

int PKI_HTTP_get_url (const URL      * url,
	              const char     * data,
		      size_t           data_size,
		      const char     * content_type,
		      int              method,
		      int              timeout,
	              size_t           max_size,
	              PKI_MEM_STACK ** sk,
	              PKI_SSL  * ssl );

int PKI_HTTP_get_socket (const PKI_SOCKET * sock,
		         const char       * data,
			 size_t             data_size,
		         const char       * content_type,
			 int                method,
			 int                timeout,
		         size_t             max_size,
			 PKI_MEM_STACK   ** sk );

/* ------------------------------ HTTP Get Functions -------------------- */

int PKI_HTTP_GET_data(const char     * url_s,
		              int              timeout,
					  size_t           max_size,
					  PKI_MEM_STACK ** ret,
					  PKI_SSL  * ssl);

int PKI_HTTP_GET_data_url(const URL      * url,
		                  int              timeout,
						  size_t           max_size,
					      PKI_MEM_STACK ** ret,
					      PKI_SSL  * ssl);

int PKI_HTTP_GET_data_socket(const PKI_SOCKET * url,
		                     int                timeout,
							 size_t             max_size,
					         PKI_MEM_STACK   ** ret);

/* ------------------------------HTTP Put Functions -------------------- */

int PKI_HTTP_POST_data(const char     * url_s,
		               const char     * data,
					   size_t           size,
			           const char     * content_type,
					   int              timeout,
					   size_t           max_size,
				       PKI_MEM_STACK ** ret_sk,
					   PKI_SSL  * ssl);

int PKI_HTTP_POST_data_url(const URL      * url,
		                   const char     * data,
						   size_t           size,
			               const char     * content_type,
						   int              timeout,
						   size_t           max_size,
				           PKI_MEM_STACK ** ret_sk,
						   PKI_SSL  * ssl);

int PKI_HTTP_POST_data_socket(const PKI_SOCKET *sock,
		                      const char       * data,
							  size_t             size,
			                  const char       * content_type,
							  int                timeout,
							  size_t             max_size,
				              PKI_MEM_STACK   ** ret_sk );

#endif
