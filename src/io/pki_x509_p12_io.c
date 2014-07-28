/* PKI_X509_PKCS12 I/O management */

#include <libpki/pki.h>

/* --------------------------- General I/O functions --------------------- */

PKI_X509_PKCS12 *PKI_X509_PKCS12_get ( char *url_s, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_get ( url_s, PKI_DATATYPE_X509_PKCS12, cred, hsm );
/*

	PKI_X509_PKCS12_STACK *r_sk = NULL;
	PKI_X509_PKCS12 *tmp_r = NULL;
	PKI_X509_PKCS12 *ret = NULL;

	if( !url_s ) return (NULL);

	if((r_sk = PKI_X509_PKCS12_STACK_get( url_s, cred, hsm )) == NULL ) {
		return(NULL);
	}

	if( PKI_STACK_PKCS12_elements( r_sk ) >= 1 ) {
		ret = PKI_STACK_PKCS12_pop( r_sk );
	}

	while( (tmp_r = PKI_STACK_PKCS12_pop( r_sk )) != NULL ) {
		PKI_X509_PKCS12_free ( tmp_r );
	}

	return( ret );
*/

}

PKI_X509_PKCS12 *PKI_X509_PKCS12_get_url ( URL *url, PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_get_url ( url, PKI_DATATYPE_X509_PKCS12, cred, hsm );
/*
	PKI_X509_PKCS12_STACK *r_sk = NULL;
	PKI_X509_PKCS12 *tmp_r = NULL;
	PKI_X509_PKCS12 *ret = NULL;

	if( !url ) return (NULL);

	if((r_sk = PKI_X509_PKCS12_STACK_get_url( url, cred, hsm )) == NULL ) {
		return(NULL);
	}

	if( PKI_STACK_PKCS12_elements( r_sk ) >= 1 ) {
		ret = PKI_STACK_PKCS12_pop( r_sk );
	}

	while( (tmp_r = PKI_STACK_PKCS12_pop( r_sk )) != NULL ) {
		PKI_X509_PKCS12_free ( tmp_r );
	}

	return (ret);
*/
}

PKI_X509_PKCS12 *PKI_X509_PKCS12_get_mem ( PKI_MEM *mem, PKI_CRED *cred ) {
	PKI_X509_PKCS12 *tmp_p12 = NULL;

	tmp_p12 = PKI_X509_get_mem ( mem, PKI_DATATYPE_X509_PKCS12, cred, NULL);

	if ( PKI_X509_PKCS12_verify_cred ( tmp_p12, cred ) == PKI_ERR ) {
		PKI_log_debug("Wrong Credentials provided!");
		PKI_X509_PKCS12_free ( tmp_p12 );
		return NULL;
	}

	return tmp_p12;
}

PKI_X509_PKCS12_STACK *PKI_X509_PKCS12_STACK_get (char *url_s, 
						PKI_CRED *cred, HSM *hsm) {
	return PKI_X509_STACK_get ( url_s, PKI_DATATYPE_X509_PKCS12, cred, hsm);
/*
	URL *url = NULL;
	PKI_X509_PKCS12_STACK *ret_sk = NULL;

	if( !url_s ) return (NULL);

	if((url = URL_new(url_s)) == NULL ) {
		return (NULL);
	}

	ret_sk = PKI_X509_PKCS12_STACK_get_url ( url, cred, hsm );
	
	URL_free( url );

	return( ret_sk );
*/
}

PKI_X509_PKCS12_STACK *PKI_X509_PKCS12_STACK_get_url ( URL *url, 
						PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_get_url(url, PKI_DATATYPE_X509_PKCS12, cred,hsm);
/*
	PKI_X509_PKCS12_STACK *ret = NULL;
	PKI_X509_PKCS12_STACK *tmp_x_sk = NULL;
	PKI_MEM_STACK *mem_sk = NULL;
	PKI_X509_PKCS12 *x = NULL;

	int i = 0, count = 1;

	// PKI_log_debug("PKI_X509_PKCS12_STACK_get_url::start()");

	if( !url ) return (NULL);

        if ( url->proto == URI_PROTO_ID ) {
		PKI_log_debug("PKI_X509_PKCS12_STACK_get_url()::"
                                "Protocol id:// not supported!");
		return ( NULL );
        };

	if((mem_sk = URL_get_data_url ( url, 0 )) == NULL ) {
		PKI_log_debug("PKI_X509_PKCS12_STACK_get_url()::"
				"ERROR::Can not load URL data!");
                return(NULL);
        }

	// PKI_log_debug("PKI_X509_PKCS12_STACK_get_url()::Loaded %d URL data",
	// 		PKI_STACK_MEM_elements( mem_sk ));

        if((ret = PKI_STACK_PKCS12_new()) == NULL ) {
		PKI_log_debug("%s:%d::Memory Error", __FILE__, __LINE__ );
		if (mem_sk) PKI_STACK_MEM_free_all (mem_sk);
                return(NULL);
        }

	count = 0;
	for( i = 0; i < PKI_STACK_MEM_elements( mem_sk ); i++ ) {
                PKI_MEM *n = NULL;

                if(( n = PKI_STACK_MEM_get_num( mem_sk, i )) == NULL ) {
                        break;
                }

                if((tmp_x_sk = PKI_X509_PKCS12_STACK_get_mem(n, cred)) != NULL ) {
                        while ( (x = PKI_STACK_PKCS12_pop( tmp_x_sk ))
                                                                 != NULL ) {
				count++;
				if( url->object_num > 0 ) { 
					if (url->object_num == count )  {
                                	     PKI_STACK_PKCS12_push( ret, x );
					}
				} else {
                                	PKI_STACK_PKCS12_push( ret, x );
				}
                        }
                        PKI_STACK_PKCS12_free ( tmp_x_sk );
                }
        }

        if( mem_sk ) PKI_STACK_MEM_free_all ( mem_sk );

        return ( ret );
*/
}

PKI_X509_PKCS12_STACK *PKI_X509_PKCS12_STACK_get_mem ( PKI_MEM *mem, 
							PKI_CRED *cred) {

	PKI_X509_PKCS12_STACK *tmp_sk = NULL;
	PKI_X509_PKCS12_STACK *ret_sk = NULL;
	PKI_X509_PKCS12 *tmp_p12 = NULL;

	/* We need to get the internal format first and then perform some
	   additional operations, i.e. verify the creds if present */

	if(( tmp_sk = PKI_X509_STACK_get_mem ( mem, 
			PKI_DATATYPE_X509_PKCS12, cred, NULL)) == NULL ) {
		return NULL;
	}
	
	if((ret_sk = PKI_STACK_X509_PKCS12_new()) == NULL ) {
		return NULL;
	}

	while ((tmp_p12 = PKI_STACK_X509_PKCS12_pop ( tmp_sk )) != NULL ) {
		/* Let's add only the ones that we can decrypt */
		if ( PKI_X509_PKCS12_verify_cred ( tmp_p12, cred ) == PKI_OK ) {
			PKI_STACK_X509_PKCS12_push( ret_sk, tmp_p12 );
		} else {
			PKI_X509_PKCS12_free ( tmp_p12 );
		}
	}

	PKI_STACK_X509_PKCS12_free ( ret_sk );

	return ret_sk;

/*
	PKI_X509_PKCS12 * x = NULL;
	PKI_X509_PKCS12_STACK *sk = NULL;

	BUF_MEM *p = NULL;
	BIO *membio = NULL;

	char *temp = NULL;
	int cont = 1;
	long curr = 0;

	size_t mem_size = 0;
	char * mem_buf = NULL;

	if( !mem || mem->size <= 0 ) return (NULL);

	if((temp = strstr((char *) mem->data, 
				PKI_X509_PKCS12_BEGIN_ARMOUR )) == NULL ) {
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

	if((sk = PKI_STACK_PKCS12_new()) == NULL ) {
		BIO_free( membio );
		return(NULL);
	}

	cont = 1;
	p = (BUF_MEM *) membio->ptr;
	curr = p->length;
	while ((cont == 1) && (p->length > 0)) {

		curr = p->length;

        	if(( x = (PKI_X509_PKCS12 *) PEM_read_bio_PKCS12( membio)) == NULL) {

			p->length = curr;
			p->data -= curr;

			if((x=(PKI_X509_PKCS12 *) d2i_PKCS12_bio(membio,NULL)) == NULL ) {
				cont = 0;
			} else {
				int macVerified = PKI_ERR;
			        if(!cred || !cred->password ) {
					 if( PKCS12_verify_mac(x->value, NULL, 0) ) {
						macVerified = PKI_OK;
					}
				} else if (PKCS12_verify_mac(x->value, 
							cred->password, -1)) {
						macVerified = PKI_OK;
        			}

				if( macVerified == PKI_OK ) {
					PKI_STACK_PKCS12_push( sk, x );
				}
			}
		} else {
			PKI_STACK_PKCS12_push( sk, x );
		}
	}

	if( PKI_STACK_PKCS12_elements( sk ) <= 0 ) {
		PKI_STACK_PKCS12_free_all ( sk );
		sk = NULL;
	}
	if(membio) BIO_free( membio );
	return( sk );
*/
}

/* ---------------------------- PKCS12 put operations ------------------ */

int PKI_X509_PKCS12_put (PKI_X509_PKCS12 *p12, PKI_DATA_FORMAT format, 
			char *url_s, char *mime, PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_put ( p12, format, url_s, mime, cred, hsm );

/*
	PKI_X509_PKCS12_STACK *sk = NULL;
	int ret = PKI_OK;

	if( !p12 || !url_s ) return (PKI_ERR);

	if(( sk = PKI_STACK_PKCS12_new()) == NULL ) return (PKI_ERR);

	if(PKI_STACK_PKCS12_push( sk, p12 ) == PKI_ERR ) {
		PKI_STACK_PKCS12_free( sk );
		return (PKI_ERR);
	}

	ret = PKI_X509_PKCS12_STACK_put ( sk, format, url_s, cred, hsm );

	if( sk ) {
		PKI_X509_PKCS12 *tmp_r = NULL;
		while((tmp_r = PKI_STACK_PKCS12_pop ( sk )) != NULL ) {
			PKI_STACK_PKCS12_free (sk);
		}
	}

	return (ret);
*/
}

int PKI_X509_PKCS12_put_url(PKI_X509_PKCS12 *p12, PKI_DATA_FORMAT format, 
			URL *url, char *mime, PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_put_url ( p12, format, url, mime, cred, hsm );
/*

	PKI_X509_PKCS12_STACK *sk = NULL;
	int ret = PKI_OK;

	if( !p12 || !url ) return (PKI_ERR);

	if(( sk = PKI_STACK_PKCS12_new()) == NULL ) return (PKI_ERR);

	if(PKI_STACK_PKCS12_push( sk, p12 ) == PKI_ERR ) {
		PKI_STACK_PKCS12_free( sk );
		return (PKI_ERR);
	}

	ret = PKI_X509_PKCS12_STACK_put_url( sk, format, url, cred, hsm );
	if( sk ) {
		PKI_X509_PKCS12 *tmp_r = NULL;
		while( ( tmp_r = PKI_STACK_PKCS12_pop ( sk )) != NULL ) {
			PKI_STACK_PKCS12_free (sk);
		}
	}

	return( ret );
*/
}


int PKI_X509_PKCS12_STACK_put ( PKI_X509_PKCS12_STACK *sk, 
		PKI_DATA_FORMAT format, char *url_s, char *mime, 
			PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_put ( sk, format, url_s, mime, cred, hsm );

/*
	int ret = PKI_OK;
	URL *url = NULL;

	if(!sk || !url_s ) return( PKI_ERR );

	if(PKI_STACK_PKCS12_elements(sk) < 1 ) return (PKI_ERR);

	if((url = URL_new(url_s)) == NULL ) {
		return(PKI_ERR);
	}

	ret = PKI_X509_PKCS12_STACK_put_url( sk, format, url, cred, hsm );

	URL_free ( url );

	return (ret);
*/

}

int PKI_X509_PKCS12_STACK_put_url (PKI_X509_PKCS12_STACK *sk, 
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

	if((idx = PKI_STACK_PKCS12_elements (sk)) < 1 ) {
		return ( PKI_ERR );
	}

	if( url->proto == URI_PROTO_ID ) {
		PKI_log_debug("PKI_X509_PKCS12_STACK_put_url()::Proto ID is not "
			"supported!");
		return ( PKI_ERR );
	};

	if((mem = PKI_MEM_new_null()) == NULL ) {
		return (PKI_ERR);
	}

	if(PKI_X509_PKCS12_STACK_put_mem( sk, format, mem, cred, url->object_num )
							 == PKI_ERR ) {
		if( mem ) PKI_MEM_free ( mem );
		return ( PKI_ERR );
	}

	ret = URL_put_data_url ( url, mem, "application/pki-x509-p12", NULL );

	if ( mem ) PKI_MEM_free ( mem );

	return ( ret );
*/

}


PKI_MEM *PKI_X509_PKCS12_STACK_put_mem ( PKI_X509_PKCS12_STACK *sk, 
			PKI_DATA_FORMAT format, PKI_MEM **pki_mem, 
				PKI_CRED *cred, HSM *hsm ) {

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

	for( i = 0; i < PKI_STACK_PKCS12_elements ( sk ); i++ ) {

		PKI_X509_PKCS12 *curr_p12 = NULL;

		if((num > 0 ) && ( i != num )) {
			continue;
		}

		if((curr_p12= PKI_STACK_PKCS12_get_num( sk, i ))
							== NULL ) {
			break;
		}

		switch( format ) {
			case PKI_DATA_FORMAT_PEM:
				ret = PEM_write_bio_PKCS12 ( membio, 
							(PKCS12 *) curr_p12);
				break;
			case PKI_DATA_FORMAT_ASN1:
				ret = i2d_PKCS12_bio( membio, 
							(PKCS12 *) curr_p12);
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


/*! \brief Puts a PKI_X509_PKCS12 in a PKI_MEM structure */

PKI_MEM *PKI_X509_PKCS12_put_mem ( PKI_X509_PKCS12 *p12, 
			PKI_DATA_FORMAT format, PKI_MEM **pki_mem, 
				PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_put_mem ( p12, format, pki_mem, cred );

/*
	PKI_MEM *pki_mem = NULL;

	BIO *bio = NULL;
	int ret = 0;

	if( !p12 ) return ( NULL );

	if((bio = BIO_new(BIO_s_mem())) == NULL ) {
		return NULL;
	}

	switch( format ) {
		case PKI_FORMAT_PEM:
			ret = PEM_write_bio_PKCS12 ( bio, (PKCS12 *) p12);
			break;
		case PKI_FORMAT_ASN1:
			ret = i2d_PKCS12_bio( bio, (PKCS12 *) p12);
			break;
		default:
			PKI_log_err ("%s:%d error\n", __FILE__, __LINE__ );
			return(PKI_ERR);
	}

	if((pki_mem = PKI_MEM_new_bio ( bio )) == NULL ) {
		PKI_log_err("PKI_X509_PKCS12_put_mem()::Memory Error");
	}

	if( bio ) BIO_free_all ( bio );

	return pki_mem;
*/
}


/*
 * PKCS12 File Operations
 */

/*
PKI_X509_PKCS12_STACK *PKI_X509_PKCS12_STACK_get_file ( URL *url ) {

        PKI_X509_PKCS12 *p12= NULL;
        BIO *in = NULL;
        PKI_X509_PKCS12_STACK *r_sk = NULL;

	if( !url || !url->addr ) return NULL;

        if ((in=BIO_new_file( url->addr, "r")) == NULL) {
                return(NULL);
        }

        if((r_sk = PKI_STACK_PKCS12_new()) == NULL ) {
                return(NULL);
        }

	while(( p12 = (PKI_X509_PKCS12 *) PEM_read_bio_PKCS12(in )) == NULL ) {
		PKI_STACK_PKCS12_push(r_sk, p12);
	}

	if( PKI_STACK_PKCS12_elements( r_sk ) < 1 ) {
		while(( p12 = (PKI_X509_PKCS12 *) d2i_X509_bio(in, NULL)) 
								== NULL ) {
			PKI_STACK_PKCS12_push(r_sk, p12);
		}
	}

	if( PKI_STACK_PKCS12_elements(r_sk) == 0 ) {
		PKI_STACK_PKCS12_free (r_sk );
		return NULL;
	}
        return r_sk;
}

int PKI_X509_PKCS12_STACK_export_file( PKI_X509_PKCS12_STACK *sk, int format, 
								URL *url ) {
	BIO *out = NULL;
	PKI_X509_PKCS12 *p12 = NULL;

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

	for( i=0; i < PKI_STACK_PKCS12_elements( sk ); i++ ) {
		if((p12 = PKI_STACK_PKCS12_get_num( sk, i )) == NULL) {
			break;
		}

		switch( format ) {
			case PKI_FORMAT_PEM:
				ret = PEM_write_bio_PKCS12( out, 
							(PKCS12 *)p12);
				break;
			case PKI_FORMAT_ASN1:
				ret = i2d_PKCS12_bio( out, (PKCS12 *) p12);
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
