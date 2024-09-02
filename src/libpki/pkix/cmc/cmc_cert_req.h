/* CMS Support for LibPKI 
 * (c) 2008 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 *
 * This software is released under the GPL2 License included
 * in the archive. You can not remove this copyright notice.
 */
                                                                                
CERT_REQ_MSG *d2i_CERT_REQ_MSG_bio ( BIO *bp, CERT_REQ_MSG *p );
int i2d_CERT_REQ_MSG_bio(BIO *bp, CERT_REQ_MSG *o );

CERT_REQ_MSG *PEM_read_bio_CERT_REQ_MSG( BIO *bp );
int PEM_write_bio_CERT_REQ_MSG( BIO *bp, CERT_REQ_MSG *o );

/* ======================== REQ get API ========================== */

CERT_REQ_MSG *CERT_REQ_MSG_get( char *url_s );
CERT_REQ_MSG *CERT_REQ_MSG_get_url( URL *url );
CERT_REQ_MSG *CERT_REQ_MSG_get_fd( int fd );
CERT_REQ_MSG *CERT_REQ_MSG_get_mem( PKI_MEM *mem );

/* ====================== CERT_REQ_MSG REQ put API ====================== */

int CERT_REQ_MSG_put( CERT_REQ_MSG *req, char *url_s, 
				int format, PKI_MEM_STACK **ret_sk );
int CERT_REQ_MSG_put_url( CERT_REQ_MSG *req, URL *url, 
				int format, PKI_MEM_STACK **ret_sk );

int CERT_REQ_MSG_put_fp( CERT_REQ_MSG *req, FILE * file, int format);
int CERT_REQ_MSG_put_mem( CERT_REQ_MSG *req, PKI_MEM *mem, int format);

