/* PKI Resource Query Protocol Message implementation
 * (c) 2007 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 *
 * This software is released under the GPL2 License included
 * in the archive. You can not remove this copyright notice.
 */
                                                                                

#ifndef _LIBPKI_PRQP_BIO_H
#define _LIBPKI_PRQP_BIO_H

#define PEM_STRING_PKI_PRQP_REQ "PRQP REQUEST"
#define PEM_STRING_PKI_PRQP_RESP "PRQP RESPONSE"

#define PKI_CONTENT_TYPE_PKI_PRQP_REQ "application/prqp-request"
#define PKI_CONTENT_TYPE_PKI_PRQP_RESP "application/prqp-response"

/* Request BIO */
PKI_PRQP_REQ * d2i_PRQP_REQ_bio ( BIO *bp, PKI_PRQP_REQ *p );
PKI_PRQP_REQ * PEM_read_bio_PRQP_REQ( BIO *bp );
int i2d_PRQP_REQ_bio(BIO *bp, PKI_PRQP_REQ *o );
int PEM_write_bio_PRQP_REQ( BIO *bp, PKI_PRQP_REQ *o );

PKI_PRQP_RESP * d2i_PRQP_RESP_bio( BIO *bp, PKI_PRQP_RESP *p );
PKI_PRQP_RESP * PEM_read_bio_PRQP_RESP( BIO *bp );
int i2d_PRQP_RESP_bio( BIO *bp, PKI_PRQP_RESP *o );
int PEM_write_bio_PRQP_RESP( BIO *bp, PKI_PRQP_RESP *o );

/* PRQP REQ get/put interface */
/*
PKI_PRQP_REQ *PKI_PRQP_REQ_get( char *url_s );
PKI_PRQP_REQ *PKI_PRQP_REQ_get_url( URL *url );
PKI_PRQP_REQ *PKI_PRQP_REQ_get_fd( int fd );
PKI_PRQP_REQ *PKI_PRQP_REQ_get_mem( PKI_MEM *mem );

int PKI_PRQP_REQ_put( PKI_PRQP_REQ *req, char *url_s, int format );
int PKI_PRQP_REQ_put_url( PKI_PRQP_REQ *req, URL *url, int format );
int PKI_PRQP_REQ_put_mem( PKI_PRQP_REQ *req, PKI_MEM *mem, int format );
int PKI_PRQP_REQ_put_fp( PKI_PRQP_REQ *req, FILE * file, int format );
*/

/* PRQP RESP get/put interface */
/*
PKI_PRQP_RESP *PKI_PRQP_RESP_get( char *url_s, int timeout );
PKI_PRQP_RESP *PKI_PRQP_RESP_get_url( URL *url, int timeout );
PKI_PRQP_RESP *PKI_PRQP_RESP_get_fd( int fd );
PKI_PRQP_RESP *PKI_PRQP_RESP_get_mem( PKI_MEM *mem );

int PKI_PRQP_RESP_put(PKI_PRQP_RESP *res, char *url_s, PKI_DATA_FORMAT format);
int PKI_PRQP_RESP_put_url(PKI_PRQP_RESP *res, URL *url, PKI_DATA_FORMAT format);
int PKI_PRQP_RESP_put_fp( PKI_PRQP_RESP *res, FILE *file, 
							PKI_DATA_FORMAT format);
int PKI_PRQP_RESP_put_mem( PKI_PRQP_RESP *res, PKI_MEM *mem,
							PKI_DATA_FORMAT format);
*/

#endif
