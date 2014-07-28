/* PKI Resource Query Protocol Message implementation
 * (c) 2007 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 *
 * This software is released under the GPL2 License included
 * in the archive. You can not remove this copyright notice.
 */
                                                                                
#include <libpki/pki.h>

/*
#define PEM_read_PKI_PRQP_REQ (fp,x,cb,u) (PKI_PRQP_REQ *) PEM_ASN1_read( \
	(char *(*)())d2i_PKI_PRQP_REQ,PEM_STRING_PKI_PRQP_REQ,fp,(char **)x,cb,u)
#define PEM_read_PKI_PRQP_RESP (fp,x,cb,u) (PKI_PRQP_RESP *) PEM_ASN1_read( \
	(char *(*)())d2i_PKI_PRQP_RESP,PEM_STRING_PKI_PRQP_RESP,fp,(char **)x,cb,u)
*/

/*
PKI_PRQP_REQ *d2i_PRQP_SIGNATURE_bio ( BIO *bp, PRQP_SIGNATURE *p ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	return (PRQP_SIGNATURE *) ASN1_d2i_bio(
			(char *(*)(void))PRQP_SIGNATURE_new, 
			(char *(*)(void **, const unsigned char **, long))d2i_PRQP_SIGNATURE, 
			bp, (unsigned char **) &p);
#else
	return (PRQP_SIGNATURE *) ASN1_d2i_bio(
			(void *(*)(void))PRQP_SIGNATURE_new, 
			(void *(*)(void **, const unsigned char **, long))d2i_PRQP_SIGNATURE, 
			bp, (void **) &p);
#endif
}

int i2d_PRQP_SIGNATURE_bio(BIO *bp, PRQP_SIGNATURE *o ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	return ASN1_i2d_bio( (int (*)(PRQP_SIGNATURE *, unsigned char **)) 
			i2d_PRQP_SIGNATURE, bp, (unsigned char *) o);
#else
	return ASN1_i2d_bio( (i2d_of_void *) i2d_PRQP_SIGNATURE, 
						bp, (unsigned char *) o);
#endif
}
*/

/* DER <-> INTERNAL Macros */
PKI_PRQP_REQ *d2i_PRQP_REQ_bio ( BIO *bp, PKI_PRQP_REQ *p ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	return (PKI_PRQP_REQ *) ASN1_d2i_bio(
			(char *(*)(void))PKI_PRQP_REQ_new, 
			(char *(*)(void **, const unsigned char **, long))d2i_PKI_PRQP_REQ, 
			bp, (unsigned char **) &p);
#else
	return (PKI_PRQP_REQ *) ASN1_d2i_bio(
			(void *(*)(void))PKI_PRQP_REQ_new, 
			(void *(*)(void **, const unsigned char **, long))d2i_PKI_PRQP_REQ, 
			bp, (void **) &p);
#endif
}

int i2d_PRQP_REQ_bio(BIO *bp, PKI_PRQP_REQ *o ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	return ASN1_i2d_bio( (int (*)(PKI_PRQP_REQ *, unsigned char **)) i2d_PKI_PRQP_REQ, bp, (unsigned char *) o);
#else
	return ASN1_i2d_bio( (i2d_of_void *) i2d_PKI_PRQP_REQ, bp, (unsigned char *) o);
#endif
}

PKI_PRQP_RESP *d2i_PRQP_RESP_bio( BIO *bp, PKI_PRQP_RESP *p ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	return (PKI_PRQP_RESP *) ASN1_d2i_bio(
			(char *(*)(void))PKI_PRQP_RESP_new, 
			(char *(*)(void **, const unsigned char **, long))d2i_PKI_PRQP_RESP, 
			bp, (unsigned char **) &p);
#else
	return (PKI_PRQP_RESP *) ASN1_d2i_bio(
			(void *(*)(void))PKI_PRQP_RESP_new, 
			(void *(*)(void **, const unsigned char **, long))d2i_PKI_PRQP_RESP, 
			bp, (void **) &p);
#endif
}

int i2d_PRQP_RESP_bio( BIO *bp, PKI_PRQP_RESP *o ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	return ASN1_i2d_bio( (int (*)(PKI_PRQP_RESP *, unsigned char **)) i2d_PKI_PRQP_RESP, bp, (unsigned char *) o);
#else
	return ASN1_i2d_bio((i2d_of_void *)i2d_PKI_PRQP_RESP, bp, (unsigned char *) o);
#endif
}


/* PEM <-> INTERNAL Macros */
PKI_PRQP_REQ *PEM_read_bio_PRQP_REQ( BIO *bp ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	return (PKI_PRQP_REQ *) PEM_ASN1_read_bio( (char *(*)()) d2i_PKI_PRQP_REQ, 
				PEM_STRING_PKI_PRQP_REQ, bp, NULL, NULL, NULL);
#else
	return (PKI_PRQP_REQ *) PEM_ASN1_read_bio( (void *(*)()) d2i_PKI_PRQP_REQ, 
				PEM_STRING_PKI_PRQP_REQ, bp, NULL, NULL, NULL);
#endif
}

PKI_PRQP_RESP *PEM_read_bio_PRQP_RESP( BIO *bp ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	return (PKI_PRQP_RESP *) PEM_ASN1_read_bio( (char *(*)()) d2i_PKI_PRQP_RESP, 
				PEM_STRING_PKI_PRQP_RESP, bp, NULL, NULL, NULL);
#else
	return (PKI_PRQP_RESP *) PEM_ASN1_read_bio( (void *(*)()) d2i_PKI_PRQP_RESP, 
				PEM_STRING_PKI_PRQP_RESP, bp, NULL, NULL, NULL);
#endif
}

int PEM_write_bio_PRQP_REQ( BIO *bp, PKI_PRQP_REQ *o ) {
	return PEM_ASN1_write_bio ( (int (*)())i2d_PKI_PRQP_REQ, 
			PEM_STRING_PKI_PRQP_REQ, bp, (char *) o, NULL, 
				NULL, 0, NULL, NULL );
}

int PEM_write_bio_PRQP_RESP( BIO *bp, PKI_PRQP_RESP *o ) {
	return PEM_ASN1_write_bio ( (int (*)()) i2d_PKI_PRQP_RESP, 
			PEM_STRING_PKI_PRQP_RESP, bp, (char *) o, NULL, 
				NULL, 0, NULL, NULL );
}

/* ======================== REQ get API ========================== */

/*! 
 * \brief Retrieves a PRQP request from the resource specified in the
 *        provided URI string
*/

/*
PKI_PRQP_REQ *PKI_PRQP_REQ_get( char *url_s ) {

	URL *url = NULL;

	if( !url_s ) return ( NULL );

	if((url = URL_new( url_s )) == NULL ) {
		return (NULL);
	}

	return ( PKI_PRQP_REQ_get_url( url ));
}
*/

/*! 
 * \brief Retrieves a PRQP request from the resource specified in the
 *        provided URL structure
*/

/*
PKI_PRQP_REQ *PKI_PRQP_REQ_get_url( URL *url ) {

        PKI_PRQP_REQ *ret = NULL;
        PKI_MEM_STACK *mem_sk = NULL;
	PKI_MEM *in = NULL;

        if(!url) return NULL;

        if((mem_sk = URL_get_data_url ( url, 0 )) == NULL ) {
                return(NULL);
        }

	if((in = PKI_STACK_MEM_pop( mem_sk )) != NULL ) {
		ret = PKI_PRQP_REQ_get_mem( in );
	}

        if( mem_sk ) PKI_STACK_MEM_free_all ( mem_sk );

	return ( ret );
}
*/

/*! 
 * \brief Retrieves a PRQP request from the specified file descriptor
*/

/*
PKI_PRQP_REQ *PKI_PRQP_REQ_get_fd( int fd ) {

	PKI_MEM *mem = NULL;
	PKI_PRQP_REQ *ret = NULL;

	char buf[1024];
	int n = 0;

	if((mem = PKI_MEM_new_null()) == NULL ) {
		PKI_log_debug("Memory Allocation error (%s:%d)!",
			__FILE__, __LINE__ );

		return ( NULL );
	}

	while( (n = _Read( fd, buf, sizeof( buf ))) > 0 ) {
		PKI_MEM_add( mem, buf, n );
	}

	ret = PKI_PRQP_REQ_get_mem( mem );

	PKI_MEM_free ( mem );

	return ( ret );
}
*/

/*! 
 * \brief Retrieves a PRQP request from the passed PKI_MEM
*/

/*
PKI_PRQP_REQ *PKI_PRQP_REQ_get_mem( PKI_MEM *mem ) {

	BIO *bp = NULL;
	BUF_MEM *p = NULL;
	PKI_PRQP_REQ *ret = NULL;

	int curr;

	bp = BIO_new_mem_buf( mem->data, mem->size );

	p = (BUF_MEM *) bp->ptr;
	curr = p->length;

	if((ret = PEM_read_bio_PKI_PRQP_REQ(bp)) == NULL){

		p->length = curr;
		p->data -= curr;

		if((ret = d2i_PKI_PRQP_REQ_bio(bp,NULL)) == NULL ) {
			PKI_log_debug("ERROR, can not load PKI_PRQP_REQ!");
		}
	}

	return ( ret );
}
*/

/* =========================== PRQP REQ put API ========================= */

/*! 
 * \brief Sends/Store a PRQP request in a PKI_MEM structure
*/

/*
int PKI_PRQP_REQ_put_mem( PKI_PRQP_REQ *req, PKI_MEM *mem, int format ) {

	BIO *mem_bio = NULL;
	BUF_MEM *buf = NULL;

	int rv = 0;

	if( !req || !mem ) return ( PKI_ERR );

	if((mem_bio = BIO_new(BIO_s_mem())) == NULL ) {
		return ( PKI_ERR );
	}

	switch ( format ) {
		case PKI_FORMAT_PEM:
			rv = PEM_write_bio_PKI_PRQP_REQ( mem_bio, req );
			break;
		case PKI_FORMAT_ASN1:
			rv = i2d_PKI_PRQP_REQ_bio( mem_bio, req );
			break;
		default:
			goto err;
	}

	if ( rv == 0 ) goto err;

	BIO_get_mem_ptr( mem_bio, &buf );
	rv = PKI_MEM_add( mem, buf->data, buf->length );

	if( mem_bio ) BIO_free ( mem_bio );

	return ( rv );
err:

	if( mem_bio ) BIO_free (mem_bio);

	return ( PKI_ERR );
}
*/

/*! 
 * \brief Sends/Writes a PRQP request in the resource specified in the
 *        provided URL structure
*/

/*
int PKI_PRQP_REQ_put_url( PKI_PRQP_REQ *req, URL *url, int format ) {

	PKI_MEM *mem = NULL;
	int ret = 0;

	if( !url ) return ( PKI_ERR );
	
	if((mem = PKI_MEM_new_null()) == NULL ) {
		return ( PKI_ERR );
	}

	if(PKI_PRQP_REQ_put_mem( req, mem, format ) == PKI_ERR ) {
		if( mem ) PKI_MEM_free ( mem );
		return (PKI_ERR);
	}

	ret = URL_put_data_url( url, mem, PKI_CONTENT_TYPE_PKI_PRQP_REQ );

	if( mem ) PKI_MEM_free ( mem );

	return ( ret );
}
*/

/*! 
 * \brief Sends/Writes a PRQP request in the resource specified in the
 *        provided URI string
*/

/*
int PKI_PRQP_REQ_put( PKI_PRQP_REQ *req, char *url_s, int format ) {

	URL *url = NULL;

	if( !url_s ) return ( PKI_ERR );

	if((url = URL_new( url_s )) == NULL ) {
		return ( PKI_ERR );
	}

	return PKI_PRQP_REQ_put_url( req, url, format );
}
*/

/* 
 * Writes a PRQP request in the provided file descriptior
*/

/*
int PKI_PRQP_REQ_put_fp( PKI_PRQP_REQ *req, FILE * file, int format ) {

	int ret = 0;
	int n = 0;
	int fd = 0;
	PKI_MEM *mem = NULL;

	if((mem = PKI_MEM_new_null()) == NULL ) {
		PKI_log_debug("Memory Allocation error (%s:%d)!",
			__FILE__, __LINE__ );

		return ( PKI_ERR );
	};

	if( PKI_PRQP_REQ_put_mem( req, mem, format ) == PKI_ERR ) {
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
*/


/* ======================== PRQP RESP get API ========================= */

/*
PKI_PRQP_RESP *PKI_PRQP_RESP_get( char *url_s, int timeout ) {

	URL *url = NULL;

	if( !url_s ) return ( NULL );

	if((url = URL_new( url_s )) == NULL ) {
		return (NULL);
	}

	return ( PKI_PRQP_RESP_get_url( url ));
}

PKI_PRQP_RESP *PKI_PRQP_RESP_get_url( URL *url, int timeout ) {

        PKI_PRQP_RESP *ret = NULL;
        PKI_MEM_STACK *mem_sk = NULL;
	PKI_MEM *in = NULL;

        if(!url) return NULL;

        if((mem_sk = URL_get_data_url ( url, timeout, 0 )) == NULL ) {
                return(NULL);
        }

	if((in = PKI_STACK_MEM_pop( mem_sk )) != NULL ) {
		ret = PKI_PRQP_RESP_get_mem( in );
	}

        if( mem_sk ) PKI_STACK_MEM_free_all ( mem_sk );

	return ( ret );
}

PKI_PRQP_RESP *PKI_PRQP_RESP_get_fd ( int fd ) {

	PKI_MEM *mem = NULL;
	PKI_PRQP_RESP *ret = NULL;
	int n = 0;

	char buf[1024];

	if((mem = PKI_MEM_new_null()) == NULL ) {
		PKI_log_debug("Memory Allocation error (%s:%d)!",
			__FILE__, __LINE__ );

		return ( NULL );
	}

	while( (n = _Read( fd, buf, sizeof( buf ))) > 0 ) {
		PKI_MEM_add( mem, buf, (size_t) n );
	}

	ret = PKI_PRQP_RESP_get_mem( mem );

	PKI_MEM_free ( mem );

	return ( ret );
}

PKI_PRQP_RESP *PKI_PRQP_RESP_get_mem ( PKI_MEM *mem ) {

	BIO *bp = NULL;
	BUF_MEM *p = NULL;
	PKI_PRQP_RESP *ret = NULL;

	int curr;

	bp = BIO_new_mem_buf( mem->data, (int) mem->size );

	p = (BUF_MEM *) bp->ptr;
	curr = p->length;

	if((ret = PEM_read_bio_PRQP_RESP(bp)) == NULL){

		p->length = curr;
		p->data -= curr;

		if((ret = d2i_PRQP_RESP_bio(bp,NULL)) == NULL ) {
			PKI_log_debug("ERROR, can not load PKI_PRQP_REQ!");
		}
	}

	return ( ret );
}
*/

/* ======================== PRQP RESP put API ============================ */

/*
int PKI_PRQP_RESP_put( PKI_PRQP_RESP *resp, char *url_s, PKI_DATA_FORMAT format ) {

	URL *url = NULL;

	if( !url_s ) return ( PKI_ERR );

	if((url = URL_new( url_s )) == NULL ) {
		return ( PKI_ERR );
	}

	return ( PKI_PRQP_RESP_put_url( resp, url, format ));
}


int PKI_PRQP_RESP_put_url( PKI_PRQP_RESP *resp, URL *url, PKI_DATA_FORMAT format ) {

	PKI_MEM *mem = NULL;
	int ret = 0;

	if( !resp || !url ) return ( PKI_ERR );

	if((mem = PKI_MEM_new_null()) == NULL ) {
		PKI_log_debug("Memory Alloc Error (%s:%d)", 
						__FILE__, __LINE__ );
		return (PKI_ERR);
	}

	if(PKI_PRQP_RESP_put_mem( resp, mem, format ) == PKI_ERR ) {
		if( mem ) PKI_MEM_free ( mem );
		return ( PKI_ERR );
	}

	ret = URL_put_data_url( url, mem, PKI_CONTENT_TYPE_PKI_PRQP_RESP, NULL);

	if( mem ) PKI_MEM_free ( mem );

	return ( ret );
}

int PKI_PRQP_RESP_put_fp( PKI_PRQP_RESP *resp, FILE * file, PKI_DATA_FORMAT format ) {

	int ret = 0;
	int n = 0;
	int fd = 0;
	PKI_MEM *mem = NULL;

	if((mem = PKI_MEM_new_null()) == NULL ) {
		PKI_log_debug("Memory Allocation error (%s:%d)!",
			__FILE__, __LINE__ );

		return ( PKI_ERR );
	};

	if( PKI_PRQP_RESP_put_mem( resp, mem, format ) == PKI_ERR ) {
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

int PKI_PRQP_RESP_put_mem( PKI_PRQP_RESP *resp, PKI_MEM *mem, 
						PKI_DATA_FORMAT format ) {

	BIO *mem_bio = NULL;
	BUF_MEM *buf = NULL;

	int rv = 0;

	if( !resp || !mem ) return ( PKI_ERR );

	if((mem_bio = BIO_new(BIO_s_mem())) == NULL ) {
		return ( PKI_ERR );
	}

	switch ( format ) {
		case PKI_DATA_FORMAT_PEM:
			rv = PEM_write_bio_PRQP_RESP( mem_bio, resp );
			break;
		case PKI_DATA_FORMAT_ASN1:
			rv = i2d_PRQP_RESP_bio( mem_bio, resp );
			break;
		default:
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
*/
