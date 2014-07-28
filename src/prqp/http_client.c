/*
 * OCSP responder
 * by Massimiliano Pala (madwolf@openca.org)
 * OpenCA project 2001
 *
 * Copyright (c) 2001 The OpenCA Project.  All rights reserved.
 *
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <libpki/pki.h>

/* Functions */
/*
BIO *http_connect( URL *url ) {

	BIO *cbio = NULL;
	int sock = -1;

	if( !url || !(url->addr) ) {
		PKI_log( PKI_LOG_ERR, "Missing address for HTTP connect!");
		return ( NULL );
	}

	if((sock = inet_connect( url )) < 1 ) {
		PKI_log( PKI_LOG_ERR, "ERROR, can not connect to server %s",
						url->addr );
		return ( NULL );
	}

	if((cbio = BIO_new_fd( sock, 0 )) == NULL ) {
		PKI_log( PKI_LOG_ERR, "ERROR, can not assign FD %d to BIO",
							sock );
		inet_close ( sock );
		return( NULL );
	}

	return cbio;
}
*/
/*
BUF_MEM *http_get_data ( BIO *in, ssize_t max_size ) {

	BUF_MEM *buf = NULL;
	size_t fullsize = 0;
	int newsize  = 0;

	if( !in )
		return NULL;

	buf = BUF_MEM_new();
	for (;;) {
		if ((buf == NULL) || (!BUF_MEM_grow(buf, (int) (fullsize+512)))) {
			PKI_log( PKI_LOG_ERR, "Memory Allocation Err (%s:%d)",
					__FILE__, __LINE__ );
			return ( NULL );
		}

		newsize   = BIO_read(in, &(buf->data[fullsize]), 512);
		if (newsize == 0) break;

		if (newsize < 0) {
			BUF_MEM_free( buf );
			return NULL;
		}

		fullsize += (size_t) newsize;

		if( (max_size > 0) && (fullsize > max_size)) {
			// fprintf( stderr, 
			// 	"ERROR::HTTP::Read::Max read size exceeded "
			// 	" [ %d ]", max_size );
			BUF_MEM_free( buf );
			return NULL;
		}
	}

	buf->data[fullsize] = '\x0';

	return buf;
}
*/
PKI_X509_PRQP_RESP *PKI_X509_PRQP_RESP_get_http ( URL *url,
		PKI_X509_PRQP_REQ *req, unsigned long max_size ) {

	PKI_MEM *mem = NULL;
	PKI_X509_PRQP_RESP *resp = NULL;
	PKI_MEM_STACK *mem_sk = NULL;

	if(( mem = PKI_X509_PRQP_REQ_put_mem ( req, 
			PKI_DATA_FORMAT_ASN1, NULL, NULL, NULL  )) == NULL ) {
		return NULL;
	}
	
	if ( URL_put_data_url ( url, mem, "application/prqp-request", 
				&mem_sk, 60, 0, NULL ) == PKI_ERR ) {
		PKI_MEM_free ( mem );
		return NULL;
	}

	PKI_MEM_free ( mem );

	if ( PKI_STACK_MEM_elements ( mem_sk ) <= 0 ) {
		PKI_log_debug ("No Responses received!");
	}

	if((mem = PKI_STACK_MEM_pop ( mem_sk )) == NULL ) {
		PKI_log_debug ("STACK Memory Error");
		PKI_STACK_MEM_free_all ( mem_sk );
		return NULL;
	}

	if((resp = PKI_X509_PRQP_RESP_get_mem ( mem, 
					NULL, NULL )) == NULL ) {
		PKI_log_debug ( "Can not read response from Memory.");
	}

	PKI_STACK_MEM_free_all ( mem_sk );

	return resp;
	
}

/*
PKI_PRQP_RESP *PRQP_http_get_resp ( URL *url, PKI_PRQP_REQ *req,
					unsigned long max_size ) {
	int sock = 1;
	BIO *mem = NULL;

	PKI_MEM *pki_buf = NULL;
	char tmp_buff[BUFF_MAX_SIZE];

	PKI_PRQP_RESP *resp = NULL;

	int len = 0;

	int rv = PKI_OK;

	static char req_txt[] = 
			"POST %s HTTP/1.1\r\n"
			"Host: %s\r\n"
			"Content-Type: application/prqp-request\r\n"
			"Content-Length: %d\r\n\r\n";

	len = i2d_PKI_PRQP_REQ(req, NULL );

	sock = inet_connect( url );

	if( sock < 1 ) {
		return NULL;
	}

	if( url->path ) {
		snprintf( tmp_buff, sizeof(tmp_buff), req_txt, url->path,
                                        url->addr, len );
		// BIO_printf(sock, req_txt, url->path, url->addr, len);
	} else {
		snprintf( tmp_buff, sizeof(tmp_buff), req_txt, "/",
                                        url->addr, len );
		// BIO_printf(sock, req_txt, "/", url->addr, len);
	}

	// fprintf( stderr, "==== REQ HEADERS ====\n%s\n==== END REQ HEADERS\n",
	// 			tmp_buff );

	if((rv = _Write( sock, tmp_buff, strlen( tmp_buff ))) < 1 ) {
                inet_close( sock );
                return( NULL );
        }

	if((pki_buf = PKI_PRQP_REQ_mem_der ( req )) == NULL ) {
		inet_close ( sock );
		PKI_log_err("%s:%d::Can not convert object to DER.",
							__FILE__, __LINE__ );
		return( NULL );
	}

        if((rv = _Write( sock, pki_buf->data, pki_buf->size )) < 1 ) {
                inet_close( sock );
                return(NULL);
        }

	
	if( pki_buf ) PKI_MEM_free ( pki_buf );

	if((pki_buf = http_get_data_sock(sock, (ssize_t) max_size)) == NULL ) {
		PKI_log_debug( "ERROR::can not read http data.\n");
	} else {
		mem = BIO_new_mem_buf( pki_buf->data, (int) pki_buf->size );
	}

	inet_close( sock );
	
	// BIO_set_mem_buf(mem, buf, BIO_CLOSE);

	if( pki_buf ) {
		PKI_log_debug("PRQP RESP DATA ==> [%d]\n", pki_buf->size );
	} else {
		PKI_log_debug("No HTTP RESP DATA!\n");
	}

	if(( parse_http_headers( mem )) == 0 ) {
		if( pki_buf ) PKI_MEM_free ( pki_buf );
		if (mem) BIO_free (mem);
		return (NULL);
	}

	// fprintf( stderr, "BUFF=>%s\n", buf->data );

	// if((resp=(PKI_PRQP_RESP *) PEM_read_bio_PKI_PRQP_RESP(mem)) == NULL) {
	// 	fprintf(stderr, "ERROR, can not load PKI_PRQP_RESPONSE!\n");

	if((resp = d2i_PRQP_RESP_bio( mem, NULL )) == NULL ) {
		// ERR_print_errors_fp(stderr);
		ERR_print_errors_fp( stderr );

		PKI_log_err ( "Can not read PRQP Response - %s",
				ERR_error_string(ERR_get_error(), NULL ));

		if( pki_buf ) PKI_MEM_free ( pki_buf );
		if( mem ) BIO_free( mem );
		return (NULL);
	}

	if( pki_buf ) PKI_MEM_free ( pki_buf );
	if( mem ) BIO_free ( mem );

	return ( resp );
}
*/

/*

BUF_MEM *http_get ( URL *url, unsigned long max_size, char *version ) {
	BIO *in = NULL;
	BUF_MEM *buf = NULL;
	char *def_version = "1.1";

	char *get_headers[] = {
		"GET %s HTTP/%s\r\n",
		"Host: %s\r\n",
		NULL
	};

	in = http_connect( url );
	if( !in ) return NULL;

	if( version == NULL ) {
		version = def_version;
	}

	BIO_printf(in, get_headers[0], url->path, version);

	if( strncmp_nocase("1.1", version, 3) == 0 ) {
		BIO_printf( in, get_headers[1], url->addr );
	}

	BIO_printf(in, "\r\n");

	if((buf = http_get_data ( in, (ssize_t) max_size )) == NULL ) {
		// fprintf( stderr, "ERROR -- can not read http data.\n");
	}

	BIO_free_all (in);
	
	return buf;
}
*/

/*
int parse_http_headers ( BIO *in ) {

	int head_lines = 0;
	char linebuf[1024];

	head_lines = 0;
	do {
		int read_code = 0;

		memset(linebuf, '\x0', sizeof linebuf);
        	if((read_code = BIO_gets(in, linebuf, sizeof(linebuf))) < 0) {
			fprintf( stderr, "HTTP - Error (%d) retrieving data"
					" (head_lines=%d)", 
						read_code, head_lines );
			return 0;
        	}

		if ( ( head_lines == 0 ) && 
			( strncmp_nocase( &(linebuf[9]), "200", 3) != 0 )) {
				fprintf( stderr, "HTTP - Error retrieving data"
					" (%s)", linebuf );
				return 0;
		} else {
			head_lines++;
		}
	}
	while( (linebuf[0] != '\r') && (linebuf[0] != '\n') );

	return 1;

}
*/
