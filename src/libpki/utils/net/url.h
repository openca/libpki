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

#ifndef _LIBPKI_NET_TYPES_H
#include <libpki/utils/net/types.h>
#endif

#ifndef _LIBPKI_URL_H
#define _LIBPKI_URL_H

/* ----------------------- URL Function prototypes --------------------- */

void URL_free(URL *url);

URL * URL_new(const char * url);

const char * URL_get_parsed(const URL *url);

const char * URL_proto_to_string(URI_PROTO proto);

char * URL_get_local_addr(void);

/* ----------------------- URL wrapping functions ---------------------- */

PKI_MEM_STACK * URL_get_data(const char *url_s,
                             int timeout,
                             ssize_t max_size,
                             PKI_SSL *ssl);

PKI_MEM_STACK * URL_get_data_url(const URL * url,
                                 int         timeout,
                                 ssize_t     max_size,
                                 PKI_SSL *ssl);

PKI_MEM_STACK * URL_get_data_socket(const PKI_SOCKET *sock,
                                    int timeout,
                                    ssize_t size);

int URL_put_data(const char     * url_s,
                 const PKI_MEM  * data,
                 const char     * contType,
                 PKI_MEM_STACK ** ret_sk,
                 int              timeout,
                 ssize_t          max_size,
                 PKI_SSL        * ssl);

int URL_put_data_raw(const char          * url_s,
                     const unsigned char * data,
                     const size_t           size,
                     const char          * contType,
                     PKI_MEM_STACK      ** ret_sk,
                     int                   timeout,
                     ssize_t               max_size,
                     PKI_SSL             * ssl);

int URL_put_data_url(const URL      * url,
                     const PKI_MEM  * data,
                     const char     * contType,
                     PKI_MEM_STACK ** ret_sk,
                     int              timeout,
                     ssize_t          max_size,
                     PKI_SSL        * ssl);

int URL_put_data_socket(const PKI_SOCKET * sock,
                        const PKI_MEM    * data,
                        const char       * contType,
                        PKI_MEM_STACK   ** ret_sk,
                        int                timeout,
                        ssize_t            max_size);

/* ------------------------ Actual I/O implementation ------------------- */

PKI_MEM_STACK *URL_get_data_fd(const URL * url,
                               ssize_t     size);

PKI_MEM_STACK *URL_get_data_file(const URL * url,
                                 ssize_t     size);

int URL_put_data_fd(const URL     * url,
                    const PKI_MEM * data);

int URL_put_data_file(const URL     * url,
                      const PKI_MEM * data);

/* ---------------------------- URL macros ------------------------------ */

#define getParsedUrl(a) URL_new(a)

#endif
