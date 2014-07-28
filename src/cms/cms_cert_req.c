/* CMS Support for LibPKI 
 * (c) 2008 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 *
 * This software is released under the GPL2 License included
 * in the archive. You can not remove this copyright notice.
 */
                                                                                
#include <libpki/pki.h>

/* DER <-> INTERNAL Macros */
CERT_REQ_MSG *d2i_CERT_REQ_MSG_bio ( BIO *bp, CERT_REQ_MSG *p ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	return (CERT_REQ_MSG *) ASN1_d2i_bio(
			(char *(*)(void))CERT_REQ_MSG_new, 
			(char *(*)(void **, const unsigned char **, long))d2i_CERT_REQ_MSG, 
			bp, (unsigned char **) &p);
#else
	return (CERT_REQ_MSG *) ASN1_d2i_bio(
			(void *(*)(void))CERT_REQ_MSG_new, 
			(void *(*)(void **, const unsigned char **, long))d2i_CERT_REQ_MSG, 
			bp, (void **) &p);
#endif
}

int i2d_CERT_REQ_MSG_bio(BIO *bp, CERT_REQ_MSG *o ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	return ASN1_i2d_bio( (int (*)(CERT_REQ_MSG *, unsigned char **)) i2d_CERT_REQ_MSG, bp, (unsigned char *) o);
#else
	return ASN1_i2d_bio( (i2d_of_void *) i2d_CERT_REQ_MSG, bp, (unsigned char *) o);
#endif
}


/* PEM <-> INTERNAL Macros */
CERT_REQ_MSG *PEM_read_bio_CERT_REQ_MSG( BIO *bp ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	return (CERT_REQ_MSG *) PEM_ASN1_read_bio( (char *(*)()) d2i_CERT_REQ_MSG, 
				PEM_STRING_CERT_REQ_MSG, bp, NULL, NULL, NULL);
#else
	return (CERT_REQ_MSG *) PEM_ASN1_read_bio( (void *(*)()) d2i_CERT_REQ_MSG, 
				PEM_STRING_CERT_REQ_MSG, bp, NULL, NULL, NULL);
#endif
}


int PEM_write_bio_CERT_REQ_MSG( BIO *bp, CERT_REQ_MSG *o ) {
	return PEM_ASN1_write_bio ( (int (*)())i2d_CERT_REQ_MSG, 
			PEM_STRING_CERT_REQ_MSG, bp, (char *) o, NULL, 
				NULL, 0, NULL, NULL );
}

/* ======================== REQ get API ========================== */

/*! 
 * \brief Retrieves a CERT_REQ_MSG request from the resource specified in the
 *        provided URI string
*/

CERT_REQ_MSG *CERT_REQ_MSG_get( char *url_s ) {

	URL *url = NULL;

	if( !url_s ) return ( NULL );

	if((url = URL_new( url_s )) == NULL ) {
		return (NULL);
	}

	return ( CERT_REQ_MSG_get_url( url ));
}

/*! 
 * \brief Retrieves a CERT_REQ_MSG request from the resource specified in the
 *        provided URL structure
*/

CERT_REQ_MSG *CERT_REQ_MSG_get_url( URL *url ) {

        CERT_REQ_MSG *ret = NULL;
        PKI_MEM_STACK *mem_sk = NULL;
	PKI_MEM *in = NULL;

        if(!url) return NULL;

        if((mem_sk = URL_get_data_url ( url, 60, 0, NULL )) == NULL ) {
                return(NULL);
        }

	if((in = PKI_STACK_MEM_pop( mem_sk )) != NULL ) {
		ret = CERT_REQ_MSG_get_mem( in );
	}

        if( mem_sk ) PKI_STACK_MEM_free_all ( mem_sk );

	return ( ret );
}

/*! 
 * \brief Retrieves a CERT_REQ_MSG request from the specified file descriptor
*/

CERT_REQ_MSG *CERT_REQ_MSG_get_fd( int fd ) {

	PKI_MEM *mem = NULL;
	CERT_REQ_MSG *ret = NULL;

	char buf[1024];
	ssize_t n = 0;

	if((mem = PKI_MEM_new_null()) == NULL ) {
		PKI_log_debug("Memory Allocation error (%s:%d)!",
			__FILE__, __LINE__ );

		return ( NULL );
	}

	while( (n = _Read( fd, buf, sizeof( buf ))) > 0 ) {
		PKI_MEM_add( mem, buf, (size_t) n );
	}

	ret = CERT_REQ_MSG_get_mem( mem );

	PKI_MEM_free ( mem );

	return ( ret );
}

/*! 
 * \brief Retrieves a CERT_REQ_MSG request from the passed PKI_MEM
*/

CERT_REQ_MSG *CERT_REQ_MSG_get_mem( PKI_MEM *mem ) {

	BIO *bp = NULL;
	BUF_MEM *p = NULL;
	CERT_REQ_MSG *ret = NULL;

	size_t curr = 0;

	bp = BIO_new_mem_buf( mem->data, (int) mem->size );

	p = (BUF_MEM *) bp->ptr;
	curr = (size_t) p->length;

	if((ret = PEM_read_bio_CERT_REQ_MSG(bp)) == NULL){

		/* Resetting the BIO to previous pointer */
#if ( OPENSSL_VERSION_NUMBER >= 0x10000000L )
		p->length = (size_t) curr;
#else
		p->length = (int) curr;
#endif
		p->data -= curr;

		/* Is it DER encoded (???) */
		if((ret = d2i_CERT_REQ_MSG_bio(bp,NULL)) == NULL ) {
			/* Format is not recognized! */
			PKI_log_debug("ERROR, can not load CERT_REQ_MSG!");
		}
	}

	return ( ret );
}

/* =========================== CERT_REQ_MSG REQ put API ========================= */

/*! 
 * \brief Sends/Writes a CERT_REQ_MSG request in the resource specified in the
 *        provided URI string
*/

int CERT_REQ_MSG_put( CERT_REQ_MSG *req, char *url_s, 
					int format, PKI_MEM_STACK **ret_sk ) {

	URL *url = NULL;

	if( !url_s ) return ( PKI_ERR );

	if((url = URL_new( url_s )) == NULL ) {
		return ( PKI_ERR );
	}

	return CERT_REQ_MSG_put_url( req, url, format, ret_sk );
}

/*! 
 * \brief Sends/Writes a CERT_REQ_MSG request in the resource specified in the
 *        provided URL structure
*/

int CERT_REQ_MSG_put_url( CERT_REQ_MSG *req, URL *url, 
					int format, PKI_MEM_STACK **ret_sk ) {

	PKI_MEM *mem = NULL;
	int ret = 0;

	if( !url ) return ( PKI_ERR );
	
	if((mem = PKI_MEM_new_null()) == NULL ) {
		return ( PKI_ERR );
	}

	if(CERT_REQ_MSG_put_mem( req, mem, format ) == PKI_ERR ) {
		if( mem ) PKI_MEM_free ( mem );
		return (PKI_ERR);
	}

	ret = URL_put_data_url(url, mem, PKI_CONTENT_TYPE_CERT_REQ_MSG,
				 ret_sk, 60, 0, NULL );

	if( mem ) PKI_MEM_free ( mem );

	return ( ret );
}

/*! 
 * \brief Writes a CERT_REQ_MSG request in the provided file descriptior
*/

int CERT_REQ_MSG_put_fp( CERT_REQ_MSG *req, FILE * file, int format ) {

	int ret = 0;
	ssize_t n = 0;
	int fd = 0;
	PKI_MEM *mem = NULL;

	if((mem = PKI_MEM_new_null()) == NULL ) {
		PKI_log_debug("Memory Allocation error (%s:%d)!",
			__FILE__, __LINE__ );

		return ( PKI_ERR );
	};

	if( CERT_REQ_MSG_put_mem( req, mem, format ) == PKI_ERR ) {
		if( mem ) PKI_MEM_free ( mem );
		return ( PKI_ERR );
	}

	fd = fileno( file );

	if((n = _Write( fd, mem->data, mem->size )) < 0 ) {
		ret = PKI_ERR;
	} else {
		ret = PKI_OK;
	}

	return ( ret );
}

/*! 
 * \brief Sends/Store a CERT_REQ_MSG request in a PKI_MEM structure
*/

int CERT_REQ_MSG_put_mem( CERT_REQ_MSG *req, PKI_MEM *mem, int format ) {

	BIO *mem_bio = NULL;
	BUF_MEM *buf = NULL;

	int rv = 0;

	if( !req || !mem ) return ( PKI_ERR );

	if((mem_bio = BIO_new(BIO_s_mem())) == NULL ) {
		return ( PKI_ERR );
	}

	switch ( format ) {
		case PKI_DATA_FORMAT_PEM:
			rv = PEM_write_bio_CERT_REQ_MSG( mem_bio, req );
			break;
		case PKI_DATA_FORMAT_ASN1:
			rv = i2d_CERT_REQ_MSG_bio( mem_bio, req );
			break;
		default:
			/* Format not supported! */
			goto err;
	}

	if ( rv == 0 ) goto err;

	BIO_get_mem_ptr( mem_bio, &buf );
	rv = PKI_MEM_add( mem, buf->data, (size_t) buf->length );

	if( mem_bio ) BIO_free ( mem_bio );

	return ( rv );
err:

	if( mem_bio ) BIO_free (mem_bio);

	return ( PKI_ERR );
}


