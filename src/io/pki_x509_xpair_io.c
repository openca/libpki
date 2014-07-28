/* PKI_X509 I/O management */

#include <libpki/pki.h>


/*! \brief Retrieve a Cross Cert Pair from a URL
 *
 * Downloads a XPAIR from a given URL (file://, http://, ldap://...)
 * in (char *) format.
 * The returned data is of type PKI_X509_XPAIR in case of success or NULL if
 * any error occurred. If multiple objects are returned from the URL, only
 * the first one is returned. Use PKI_X509_XPAIR_STACK_get() function
 * to retrieve a PKI_X509_XPAIR_STACK * object.
 */

PKI_X509_XPAIR *PKI_X509_XPAIR_get ( char *url_s, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_get ( url_s, PKI_DATATYPE_X509_XPAIR, cred, hsm );
/*
	PKI_X509_XPAIR * ret = NULL;
	URL *url = NULL;

	if( !url_s ) return (NULL);

	if((url = URL_new( url_s )) == NULL ) {
		return (NULL);
	}

	ret = PKI_X509_XPAIR_get_url ( url, cred, hsm );

	if( url ) URL_free ( url );
	return( ret );
*/
}

/*! \brief Retrieve a cross certificate pair from a URL pointer.
 *
 * Downloads a XPAIR from a given URL (file://, http://, ldap://...)
 * in (URL *) format. To generate a URL * from a char * use URL_new().
 * The returned data is of type PKI_X509_XPAIR in case of success or NULL if
 * any error occurred. If multiple objects are returned from the URL, only
 * the first one is returned. Use PKI_X509_XPAIR_STACK_get_url() function
 * to retrieve a PKI_X509_XPAIR_STACK * object.
 *
 */

PKI_X509_XPAIR *PKI_X509_XPAIR_get_url ( URL *url, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_get_url ( url, PKI_DATATYPE_X509_XPAIR, cred, hsm );
/*
	PKI_X509_XPAIR_STACK *sk = NULL;
	PKI_X509_XPAIR * ret = NULL;

	if( !url ) return (NULL);

	if((sk = PKI_X509_XPAIR_STACK_get_url(url, cred, hsm)) == NULL) {
		return (NULL);
	}

	if( PKI_STACK_X509_XPAIR_elements( sk ) >= 1 ) {
		PKI_X509_XPAIR *x = NULL;

		ret = PKI_STACK_X509_XPAIR_pop( sk );
		while ( (x = PKI_STACK_X509_XPAIR_pop ( sk )) != NULL ) {
			PKI_X509_XPAIR_free ( x );
		}
	}

	if( sk ) PKI_STACK_X509_XPAIR_free ( sk );

	return ( ret );
*/

}

/*! \brief Retrieve a stack of cross cert pair from a URL (char *).
 *
 * Downloads a stack of certificates from a given URL (file://, http://,
 * ldap://...) passed as a (char *).
 *
 * The returned data is a pointer to a PKI_X509_XPAIR_STACK data structure
 * in case of success or NULL if any error occurred.
 * If only the first object is required from the URL, use the 
 * PKI_X509_XPAIR_get_url() function instead.
 *
 */

PKI_X509_XPAIR_STACK *PKI_X509_XPAIR_STACK_get ( char *url_s, 
						PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_get ( url_s, PKI_DATATYPE_X509_XPAIR, cred, hsm);
/*
	URL *url = NULL;
	PKI_X509_XPAIR_STACK *ret = NULL;

	if( !url_s ) return (NULL);

	if((url = URL_new( url_s )) == NULL ) {
		return(NULL);
	}

	ret = PKI_X509_XPAIR_STACK_get_url ( url, cred, hsm );

	if( url ) URL_free ( url );
	return ( ret );
*/

}

/*! \brief Retrieve a stack of cross cert pair from a URL (URL *) pointer.
 *
 * Downloads a stack of XPAIR from a given URL (file://, http://,
 * ldap://...) passed as a (URL *).  To generate a (URL *) from a (char *)
 * use URL_new().
 *
 * The returned data is a pointer to a PKI_X509_XPAIR_STACK data structure
 * in case of success or NULL if any error occurred.
 * If only the first object is required from the URL, use the 
 * PKI_X509_XPAIR_get_url() function instead.
 *
 */

PKI_X509_XPAIR_STACK *PKI_X509_XPAIR_STACK_get_url ( URL *url, 
						PKI_CRED *cred, HSM *hsm ) {
	
	return PKI_X509_STACK_get_url ( url, PKI_DATATYPE_X509_XPAIR, cred, hsm );
/*
        PKI_X509_XPAIR_STACK *ret = NULL;
        PKI_X509_XPAIR_STACK *tmp_x_sk = NULL;
	PKI_MEM_STACK *mem_sk = NULL;
	PKI_X509_XPAIR *x = NULL;

	int i, count;

	if(!url) return NULL;

	if ( url->proto == URI_PROTO_ID ) {
		PKI_log_debug("PKI_X509_XPAIR_STACK_get_url()::"
				"Protocol id:// not supported for XPAIR!");
		return ( NULL );
	};

	if((mem_sk = URL_get_data_url ( url, 0 )) == NULL ) {
		return(NULL);
	}

	if((ret = PKI_STACK_X509_XPAIR_new()) == NULL ) {
		return(NULL);
	}

	count = 0;
	for( i = 0; i < PKI_STACK_MEM_elements( mem_sk ); i++ ) {
		PKI_MEM *n = NULL;

		if(( n = PKI_STACK_MEM_get_num( mem_sk, i )) == NULL ) {
			break;
		}

		if((tmp_x_sk = PKI_X509_XPAIR_STACK_get_mem(n, cred)) != NULL) {
			while ( (x = PKI_STACK_X509_XPAIR_pop( tmp_x_sk ))
								 != NULL ) {
				count++;
				if ( url->object_num > 0) {
					if( count == url->object_num)  {
					    PKI_STACK_X509_XPAIR_push( ret, x );
					}
				} else {
					PKI_STACK_X509_XPAIR_push( ret, x );
				}
			}
			PKI_STACK_X509_XPAIR_free ( tmp_x_sk );
		}
	}

	if( mem_sk ) PKI_STACK_MEM_free_all ( mem_sk );

        return ( ret );
*/
}

/*
char * memstr( char *str, char *tok, ssize_t size ) {
	int i, j, tok_size, found;

	if( !str || !tok || size < 1 ) return (NULL);

	tok_size = strlen( tok );

	found = 0;
	for( i = 0; i < size; i++ ) {
		found = 1;
		for( j=0; j < tok_size; j++ ) {
			if( str[i+j] != tok[j] ) {
				found = 0;
				break;
			}
		}
		if ( found == 1 ) return ( &str[i] );
	}

	return( NULL );
}
*/

/* --------------------------- X509_XPAIR put (write) ----------------------- */

int PKI_X509_XPAIR_put ( PKI_X509_XPAIR *x, PKI_DATA_FORMAT format, 
			char *url_s, char *mime, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_put ( x, format, url_s, mime, cred, hsm );
/*
	PKI_X509_XPAIR_STACK *sk = NULL;
	int ret = PKI_OK;

	if( !x || !url_string ) return (PKI_ERR);

	if(( sk = PKI_STACK_X509_XPAIR_new()) == NULL ) {
		return( PKI_ERR );
	}

	if( PKI_STACK_X509_XPAIR_push( sk, x ) == PKI_ERR ) {
		PKI_STACK_X509_XPAIR_free ( sk );
		return ( PKI_ERR );
	}

	ret = PKI_X509_XPAIR_STACK_put ( sk, format, url_string, cred, hsm);

	if( sk ) {
		while ((x = PKI_STACK_X509_XPAIR_pop( sk )) != NULL );

                PKI_STACK_X509_XPAIR_free( sk );
	}

	return (ret);
*/
}

PKI_MEM *PKI_X509_XPAIR_put_mem ( PKI_X509_XPAIR *x, PKI_DATA_FORMAT format,
			PKI_MEM **pki_mem, PKI_CRED *cred, HSM *hsm ) {
	return PKI_X509_put_mem ( x, format, pki_mem, cred );
}

int PKI_X509_XPAIR_STACK_put (PKI_X509_XPAIR_STACK *sk, PKI_DATA_FORMAT format, 
			char *url_s, char *mime, PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_STACK_put ( sk, format, url_s, mime, cred, hsm );

/*
	URL *url = NULL;
	int ret = PKI_OK;

	if( !sk || !url_string ) return (PKI_ERR);

	if((url = URL_new (url_string)) == NULL ) {
		return (PKI_ERR);
	}

	ret = PKI_X509_XPAIR_STACK_put_url( sk, format, url, cred, hsm );

	if( url ) URL_free ( url );

	return ( ret );
*/
	
}


int PKI_X509_XPAIR_STACK_put_url (PKI_X509_XPAIR_STACK *sk, 
				PKI_DATA_FORMAT format, URL *url, 
				char *mime, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_put_url ( sk, format, url, mime, cred, hsm );

/*
	PKI_MEM *mem = NULL;
	int idx = 0;
	int ret = 0;

	if( !sk || !url ) {
		return ( PKI_ERR );
	}

	if((idx = PKI_STACK_X509_XPAIR_elements (sk)) < 1 ) {
		return ( PKI_ERR );
	}

	if( url->proto == URI_PROTO_ID && hsm ) {
		PKI_log_debug("PKI_X509_XPAIR_put()::ERROR, proto id:// "
				"not supported for XPAIR!");
		return ( PKI_ERR );
	};

	if((mem = PKI_MEM_new_null()) == NULL ) {
		return (PKI_ERR);
	}

	if(PKI_X509_XPAIR_STACK_put_mem( sk, format, mem, 
					cred, url->object_num ) == PKI_ERR ) {
		if( mem ) PKI_MEM_free ( mem );
		return ( PKI_ERR );
	}

	ret = URL_put_data_url ( url, mem, 
			"application/pki-x509-crossCertificatePair", NULL );

	if ( mem ) PKI_MEM_free ( mem );

	return ( ret );
*/
}

/* -------------------------- X509_XPAIR mem Operations -------------------- */

PKI_X509_XPAIR_STACK *PKI_X509_XPAIR_STACK_get_mem(PKI_MEM *mem, 
							PKI_CRED *cred) { 
	return PKI_X509_STACK_get_mem ( mem, PKI_DATATYPE_X509_XPAIR, 
								cred, NULL );
/*
	PKI_X509_XPAIR * x = NULL;
	PKI_X509_XPAIR_VALUE * x_val = NULL;
	PKI_X509_XPAIR_STACK *sk = NULL;

	BUF_MEM *p = NULL;
	BIO *membio = NULL;

	char *temp = NULL;
	int cont = 1;
	long curr = 0;

	size_t mem_size = 0;
	char * mem_buf = NULL;

	if( !mem || mem->size <= 0 ) return (NULL);

	if((temp = strstr((char *) mem->data, 
				PEM_STRING_X509_XPAIR )) == NULL ) {
		mem_buf = (char *) mem->data;
		mem_size = mem->size;
	} else {
		mem_buf = temp;
		mem_size = (size_t) ((char *)mem->data - temp) + mem->size;
	}

	if((membio = BIO_new_mem_buf( mem_buf, (int) mem_size )) == NULL ) {
		return( NULL );
	}

	if(BIO_set_close(membio, BIO_NOCLOSE) != 1 ) {
		BIO_free (membio);
		return(NULL);
	}

	if((sk = PKI_STACK_X509_XPAIR_new()) == NULL ) {
		BIO_free( membio );
		return(NULL);
	}

	cont = 1;
	p = (BUF_MEM *) membio->ptr;
	curr = p->length;
	while ((cont == 1) && (p->length > 0)) {

		curr = p->length;

        	if(( x = (PKI_X509_XPAIR *) 
			PKI_X509_get_mem ( mem, PKI_DATATYPE_X509_XPAIR, 
							cred )) == NULL){

			p->length = curr;
			p->data -= curr;

        		if(( x = (PKI_X509_XPAIR *) 
				PKI_X509_get_mem (mem, PKI_DATATYPE_X509_XPAIR, cred )) == NULL){
				cont = 0;
			} else {
				PKI_STACK_X509_XPAIR_push( sk, x );
			}
		} else {
			PKI_STACK_X509_XPAIR_push( sk, x );

		}
	}

	if(membio) BIO_free( membio );
	return( sk );
*/
}

PKI_MEM * PKI_X509_XPAIR_STACK_put_mem ( PKI_X509_XPAIR_STACK *sk, 
	PKI_DATA_FORMAT format, PKI_MEM **pki_mem, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_put_mem ( sk, format, pki_mem, cred, hsm );

/*
	BIO *membio = NULL;
	BUF_MEM *buf_mem = NULL;
	int ret = PKI_OK;
	int i = 0;

	if( !sk ) return (PKI_ERR);

	if((membio = BIO_new(BIO_s_mem())) == NULL ) {
		PKI_log_err("%s:%d error\n", __FILE__, __LINE__ );
		return (PKI_ERR);
	}

	for( i = 0; i < PKI_STACK_X509_XPAIR_elements ( sk ); i++ ) {

		PKI_X509_XPAIR *xpair = NULL;

		if( ( num > 0 ) && ( i != num ) ) {
			continue;
		}

		if((xpair = PKI_STACK_X509_XPAIR_get_num( sk, i ))
							== NULL ) {
			break;
		}

		switch( format ) {
			case PKI_FORMAT_PEM:
				ret = PEM_write_bio_PKI_XPAIR( membio, 
							xpair->value );
				break;
			case PKI_FORMAT_ASN1:
				ret = i2d_PKI_XPAIR_bio( membio, xpair->value);
				break;
			case PKI_FORMAT_TXT:
				ret = PKI_XPAIR_print( membio, xpair->value);
				break;
			default:
				PKI_log_err ("%s:%d error\n", 
							__FILE__, __LINE__ );
				return(PKI_ERR);
		}

		if ( !ret ) {
			if( membio ) BIO_free_all (membio);
			return ( PKI_ERR );
		}
	}

	BIO_get_mem_ptr(membio, &buf_mem);

	if( buf_mem ) {
		PKI_MEM_add( pki_mem, buf_mem->data, (size_t) buf_mem->length );
	}

	if( membio ) BIO_free_all ( membio );

	return ( PKI_OK );
*/
}

int PKI_XPAIR_print( BIO *bio, PKI_XPAIR *xp_val ) {

	PKI_X509_CERT *x_tmp = NULL;

	if ( !bio || !xp_val ) return ( PKI_ERR );

	BIO_printf(bio, "\nCross Certificate Pair:\n");

	BIO_printf(bio, "  Forward Certificate:\n" );
	if (( x_tmp = PKI_X509_new_dup_value ( PKI_DATATYPE_X509_CERT, 
					xp_val->forward, NULL )) != NULL ) {

		BIO_printf(bio, "    Serial=%s\n", 
			PKI_X509_CERT_get_parsed ( x_tmp, 
				PKI_X509_DATA_SERIAL ));
		BIO_printf(bio, "    Subject=%s\n", 
			PKI_X509_CERT_get_parsed ( x_tmp, 
				PKI_X509_DATA_SUBJECT ));
		BIO_printf(bio, "    Issuer=%s\n", 
			PKI_X509_CERT_get_parsed ( x_tmp, 
				PKI_X509_DATA_ISSUER ));
		x_tmp->cb->to_pem ( (PKI_IO *) bio, (void *) xp_val->forward );
		PKI_X509_free ( x_tmp );
	} else {
		BIO_printf(bio, "     No forward certificate present.\n\n");
	}

	BIO_printf(bio, "  Reverse Certificate:\n" );
	if (( x_tmp = PKI_X509_new_dup_value ( PKI_DATATYPE_X509_CERT,
					xp_val->reverse, NULL )) != NULL ) {
		BIO_printf(bio, "    Serial=%s\n", 
			PKI_X509_CERT_get_parsed ( x_tmp, 
				PKI_X509_DATA_SERIAL ));
		BIO_printf(bio, "    Subject=%s\n", 
			PKI_X509_CERT_get_parsed ( x_tmp, 
				PKI_X509_DATA_SUBJECT ));
		BIO_printf(bio, "    Issuer=%s\n", 
			PKI_X509_CERT_get_parsed ( x_tmp, 
				PKI_X509_DATA_ISSUER ));
		x_tmp->cb->to_pem ( (PKI_IO *) bio, (void *) xp_val->reverse );
		PKI_X509_free ( x_tmp );
	} else {
		BIO_printf(bio, "     No reverse certificate present.\n\n");
	}

	return ( PKI_OK );
}
