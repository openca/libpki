/* PKI_X509_PKCS7 I/O management */

#include <libpki/pki.h>

PKI_X509_PKCS7 *PKI_X509_PKCS7_get ( char *url_s, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_get ( url_s, PKI_DATATYPE_X509_PKCS7, cred, hsm );
/*
	PKI_X509_PKCS7_STACK *r_sk = NULL;
	PKI_X509_PKCS7 *tmp_r = NULL;
	PKI_X509_PKCS7 *ret = NULL;

	if( !url_s ) return (NULL);

	if((r_sk = PKI_X509_PKCS7_STACK_get( url_s, cred, hsm )) == NULL ) {
		return(NULL);
	}

	if( PKI_STACK_PKCS7_elements( r_sk ) >= 1 ) {
		ret = PKI_STACK_PKCS7_pop( r_sk );
	}

	while( (tmp_r = PKI_STACK_PKCS7_pop( r_sk )) != NULL ) {
		PKI_X509_PKCS7_free ( tmp_r );
	}

	return( ret );
*/
}

PKI_X509_PKCS7 *PKI_X509_PKCS7_get_url ( URL *url, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_get_url ( url, PKI_DATATYPE_X509_PKCS7, cred, hsm );
/*
	PKI_X509_PKCS7_STACK *r_sk = NULL;
	PKI_X509_PKCS7 *tmp_r = NULL;
	PKI_X509_PKCS7 *ret = NULL;

	if( !url ) return (NULL);

	if((r_sk = PKI_X509_PKCS7_STACK_get_url( url, cred, hsm )) == NULL ) {
		return(NULL);
	}

	if( PKI_STACK_PKCS7_elements( r_sk ) >= 1 ) {
		ret = PKI_STACK_PKCS7_pop( r_sk );
	}

	while( (tmp_r = PKI_STACK_PKCS7_pop( r_sk )) != NULL ) {
		PKI_X509_PKCS7_free ( tmp_r );
	}

	return (ret);
*/
}

PKI_X509_PKCS7 * PKI_X509_PKCS7_get_mem ( PKI_MEM *mem, PKI_CRED *cred ) {
	return PKI_X509_get_mem ( mem, PKI_DATATYPE_X509_PKCS7, cred, NULL );
}

PKI_X509_PKCS7_STACK *PKI_X509_PKCS7_STACK_get (char *url_s, 
						PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_STACK_get ( url_s, PKI_DATATYPE_X509_PKCS7, cred, hsm);
/*
	URL *url = NULL;
	PKI_X509_PKCS7_STACK *ret_sk = NULL;

	if( !url_s ) return (NULL);

	if((url = URL_new(url_s)) == NULL ) {
		return (NULL);
	}

	ret_sk = PKI_X509_PKCS7_STACK_get_url ( url, cred, hsm );
	
	URL_free( url );

	return( ret_sk );
*/
}

PKI_X509_PKCS7_STACK *PKI_X509_PKCS7_STACK_get_url ( URL *url,
					PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_get_url (url, PKI_DATATYPE_X509_PKCS7, cred, hsm);
/*
	PKI_X509_PKCS7_STACK *ret = NULL;
	PKI_X509_PKCS7_STACK *tmp_x_sk = NULL;
	PKI_MEM_STACK *mem_sk = NULL;
	PKI_X509_PKCS7 *x = NULL;

	int i = 0, count = 1;

	if( !url ) return (NULL);

        if ( url->proto == URI_PROTO_ID ) {
		PKI_log_debug("PKI_X509_PKCS7_STACK_get_url()::"
                                "Protocol id:// not supported!");
		return ( NULL );
        };

	if((mem_sk = URL_get_data_url ( url, 0 )) == NULL ) {
                return(NULL);
        }

        if((ret = PKI_STACK_PKCS7_new()) == NULL ) {
                return(NULL);
        }

	count = 0;
	for( i = 0; i < PKI_STACK_MEM_elements( mem_sk ); i++ ) {
                PKI_MEM *n = NULL;

                if(( n = PKI_STACK_MEM_get_num( mem_sk, i )) == NULL ) {
                        break;
                }

                if((tmp_x_sk = PKI_X509_PKCS7_STACK_get_mem(n, cred)) != NULL ) {
                        while ( (x = PKI_STACK_PKCS7_pop( tmp_x_sk ))
                                                                 != NULL ) {
				count++;
				if( url->object_num > 0 ) { 
					if (url->object_num == count )  {
                                	     PKI_STACK_PKCS7_push( ret, x );
					}
				} else {
                                	PKI_STACK_PKCS7_push( ret, x );
				}
                        }
                        PKI_STACK_PKCS7_free ( tmp_x_sk );
                }
        }

        if( mem_sk ) PKI_STACK_MEM_free_all ( mem_sk );

        return ( ret );
*/
}

PKI_X509_PKCS7_STACK *PKI_X509_PKCS7_STACK_get_mem( PKI_MEM *mem, 
							PKI_CRED *cred) {

	return PKI_X509_STACK_get_mem ( mem, PKI_DATATYPE_X509_PKCS7, 
							cred, NULL );
/*

	PKI_X509_PKCS7 * x = NULL;
	PKI_X509_PKCS7_STACK *sk = NULL;

	BUF_MEM *p = NULL;
	BIO *membio = NULL;

	char *temp = NULL;
	int cont = 1;
	long curr = 0;

	size_t mem_size = 0;
	char * mem_buf = NULL;

	if( !mem || mem->size <= 0 ) return (NULL);

	if((temp = strstr((char *) mem->data, 
				PKI_X509_PKCS7_BEGIN_ARMOUR )) == NULL ) {
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

	if((sk = PKI_STACK_PKCS7_new()) == NULL ) {
		BIO_free( membio );
		return(NULL);
	}

	cont = 1;
	p = (BUF_MEM *) membio->ptr;
	curr = p->length;
	while ((cont == 1) && (p->length > 0)) {

		curr = p->length;

        	if(( x = (PKI_X509_PKCS7 *) 
			PEM_read_bio_PKCS7(membio,NULL,NULL,NULL)) == NULL){

			p->length = curr;
			p->data -= curr;

			if((x=(PKI_X509_PKCS7 *) d2i_PKCS7_bio(membio,NULL)) == NULL ) {
				cont = 0;
			} else {
				PKI_STACK_PKCS7_push( sk, x );
			}
		} else {
			PKI_STACK_PKCS7_push( sk, x );

		}
	}

	if(membio) BIO_free( membio );
	return( sk );
	*/
}

/* ---------------------------- PKCS7 put operations ------------------ */

int PKI_X509_PKCS7_put (PKI_X509_PKCS7 *p7, PKI_DATA_FORMAT format, 
			char *url_s, char *mime, PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_put ( p7, format, url_s, mime, cred, hsm );

/*
	PKI_X509_PKCS7_STACK *sk = NULL;
	int ret = PKI_OK;

	if( !p7 || !url_s ) return (PKI_ERR);

	if(( sk = PKI_STACK_PKCS7_new()) == NULL ) return (PKI_ERR);

	if(PKI_STACK_PKCS7_push( sk, p7 ) == PKI_ERR ) {
		PKI_STACK_PKCS7_free( sk );
		return (PKI_ERR);
	}

	ret = PKI_X509_PKCS7_STACK_put ( sk, format, url_s, cred, hsm );

	if( sk ) {
		PKI_X509_PKCS7 *tmp_r = NULL;
		while((tmp_r = PKI_STACK_PKCS7_pop ( sk )) != NULL ) {
			PKI_STACK_PKCS7_free (sk);
		}
	}

	return (ret);
*/
}

int PKI_X509_PKCS7_put_url(PKI_X509_PKCS7 *p7, PKI_DATA_FORMAT format, 
			URL *url, char *mime, PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_put_url ( p7, format, url, mime, cred, hsm );

/*
	PKI_X509_PKCS7_STACK *sk = NULL;
	int ret = PKI_OK;

	if( !p7 || !url ) return (PKI_ERR);

	if(( sk = PKI_STACK_PKCS7_new()) == NULL ) return (PKI_ERR);

	if(PKI_STACK_PKCS7_push( sk, p7 ) == PKI_ERR ) {
		PKI_STACK_PKCS7_free( sk );
		return (PKI_ERR);
	}

	ret = PKI_X509_PKCS7_STACK_put_url( sk, format, url, cred, hsm );
	if( sk ) {
		PKI_X509_PKCS7 *tmp_r = NULL;
		while( ( tmp_r = PKI_STACK_PKCS7_pop ( sk )) != NULL ) {
			PKI_STACK_PKCS7_free (sk);
		}
	}

	return( ret );
*/
}


PKI_MEM *PKI_X509_PKCS7_put_mem ( PKI_X509_PKCS7 *p7, PKI_DATA_FORMAT format,
			PKI_MEM **pki_mem, PKI_CRED *cred, HSM *hsm ) {

	PKI_log_debug("B64_DEBUG");
	return PKI_X509_put_mem ( p7, format, pki_mem, cred );
}

int PKI_X509_PKCS7_STACK_put (PKI_X509_PKCS7_STACK *sk, PKI_DATA_FORMAT format, 
			char *url_s, char *mime, PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_STACK_put ( sk, format, url_s, mime, cred, hsm );

/*
	int ret = PKI_OK;
	URL *url = NULL;

	if(!sk || !url_s ) return( PKI_ERR );

	if(PKI_STACK_PKCS7_elements(sk) < 1 ) return (PKI_ERR);

	if((url = URL_new(url_s)) == NULL ) {
		return(PKI_ERR);
	}

	ret = PKI_X509_PKCS7_STACK_put_url( sk, format, url, cred, hsm );

	URL_free ( url );

	return (ret);
*/

}

int PKI_X509_PKCS7_STACK_put_url (PKI_X509_PKCS7_STACK *sk, 
			PKI_DATA_FORMAT format, URL *url, char *mime,
					 PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_put_url ( sk, format, url, mime, cred, hsm );

/*
	PKI_MEM *mem = NULL;
	int idx = 0;
	int ret = 0;

	if( !sk || !url ) {
		return ( PKI_ERR );
	}

	if((idx = PKI_STACK_PKCS7_elements (sk)) < 1 ) {
		return ( PKI_ERR );
	}

	if( url->proto == URI_PROTO_ID ) {
		PKI_log_debug("PKI_X509_PKCS7_STACK_put_url()::Proto ID is not "
			"supported!");
		return ( PKI_ERR );
	};

	if((mem = PKI_MEM_new_null()) == NULL ) {
		return (PKI_ERR);
	}

	if(PKI_X509_PKCS7_STACK_put_mem( sk, format, mem, cred, url->object_num )
							 == PKI_ERR ) {
		if( mem ) PKI_MEM_free ( mem );
		return ( PKI_ERR );
	}

	ret = URL_put_data_url ( url, mem, "application/pki-x509-p7", NULL );

	if ( mem ) PKI_MEM_free ( mem );

	return ( ret );
*/

}

PKI_MEM * PKI_X509_PKCS7_STACK_put_mem ( PKI_X509_PKCS7_STACK *sk, 
		PKI_DATA_FORMAT format, PKI_MEM **pki_mem, PKI_CRED *cred, 
			HSM *hsm ) {

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

	for( i = 0; i < PKI_STACK_PKCS7_elements ( sk ); i++ ) {

		PKI_X509_PKCS7 *curr_p7 = NULL;

		if((num > 0 ) && ( i != num )) {
			continue;
		}

		if((curr_p7= PKI_STACK_PKCS7_get_num( sk, i ))
							== NULL ) {
			break;
		}

		switch( format ) {
			case PKI_FORMAT_PEM:
				ret = PEM_write_bio_PKCS7 ( membio, 
							(PKCS7 *) curr_p7);
				break;
			case PKI_FORMAT_ASN1:
				ret = i2d_PKCS7_bio( membio, 
							(PKCS7 *) curr_p7);
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


/*
PKI_X509_PKCS7_STACK *PKI_X509_PKCS7_STACK_get_file ( URL *url ) {

        PKI_X509_PKCS7 *p7= NULL;
        BIO *in = NULL;
        PKI_X509_PKCS7_STACK *r_sk = NULL;

	if( !url || !url->addr ) return NULL;

        if ((in=BIO_new_file( url->addr, "r")) == NULL) {
                return(NULL);
        }

        if((r_sk = PKI_STACK_PKCS7_new()) == NULL ) {
                return(NULL);
        }

	while(( p7 = (PKI_X509_PKCS7 *) PEM_read_bio_PKCS7(in, 
					NULL, NULL, NULL)) == NULL ) {
		PKI_STACK_PKCS7_push(r_sk, p7);
	}

	if( PKI_STACK_PKCS7_elements( r_sk ) < 1 ) {
		while(( p7 = (PKI_X509_PKCS7 *) d2i_X509_bio(in, NULL)) 
								== NULL ) {
			PKI_STACK_PKCS7_push(r_sk, p7);
		}
	}

	if( PKI_STACK_PKCS7_elements(r_sk) == 0 ) {
		PKI_STACK_PKCS7_free (r_sk );
		return NULL;
	}
        return r_sk;
}

int PKI_X509_PKCS7_STACK_export_file( PKI_X509_PKCS7_STACK *sk, int format, 
								URL *url ) {
	BIO *out = NULL;
	PKI_X509_PKCS7 *p7 = NULL;

	int ret = PKI_OK;
	int i = 0;

	if( !sk ) return (PKI_ERR);

	if((out = BIO_new(BIO_s_file())) == NULL ) {
		PKI_log_debug("%s:%d Memory error!", __FILE__, __LINE__ );
		return (PKI_ERR);
	}

	if( !url || !url->addr ) {
		 ret = BIO_set_fp(out,stdout,BIO_NOCLOSE);
	} else {
		ret = (int ) BIO_write_filename( out, url->addr);
	}

	if( ret == 0 ) {
		BIO_free_all( out );
		return( PKI_ERR );
	}

	ret = PKI_OK;

	for( i=0; i < PKI_STACK_PKCS7_elements( sk ); i++ ) {
		if((p7 = PKI_STACK_PKCS7_get_num( sk, i )) == NULL) {
			break;
		}

		switch( format ) {
			case PKI_FORMAT_PEM:
				ret = PEM_write_bio_PKCS7( out, 
							(PKCS7 *)p7);
				break;
			case PKI_FORMAT_ASN1:
				ret = i2d_PKCS7_bio( out, (PKCS7 *) p7);
			default:
				PKI_log_err ("%s:%d Format not recognized", 
							__FILE__, __LINE__ );
				ret = PKI_ERR;
				break;
		}
	}

	if( out ) BIO_free_all (out);

	return(ret);
}
*/
