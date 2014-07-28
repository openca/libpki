/* PKI_X509_OCSP_RESP I/O management */

#include <libpki/pki.h>

PKI_X509_OCSP_RESP *PKI_X509_OCSP_RESP_get(char *url_s,PKI_CRED *cred,HSM *hsm){

	return PKI_X509_get ( url_s, PKI_DATATYPE_X509_OCSP_RESP, cred, hsm );

/*
	PKI_X509_OCSP_RESP_STACK *r_sk = NULL;
	PKI_X509_OCSP_RESP *tmp_r = NULL;
	PKI_X509_OCSP_RESP *ret = NULL;

	if( !url_s ) return (NULL);

	if((r_sk = PKI_X509_OCSP_RESP_STACK_get( url_s, cred, hsm )) == NULL ) {
		return(NULL);
	}

	if( PKI_STACK_OCSP_RESP_elements( r_sk ) >= 1 ) {
		ret = PKI_STACK_OCSP_RESP_pop( r_sk );
	}

	while( (tmp_r = PKI_STACK_OCSP_RESP_pop( r_sk )) != NULL ) {
		PKI_X509_OCSP_RESP_free ( tmp_r );
	}

	return( ret );
*/
}

PKI_X509_OCSP_RESP *PKI_X509_OCSP_RESP_get_url (URL *url, PKI_CRED *cred, 
								HSM *hsm ) {

	return PKI_X509_get_url ( url, PKI_DATATYPE_X509_OCSP_RESP, cred, hsm);
/*
	PKI_X509_OCSP_RESP_STACK *r_sk = NULL;
	PKI_X509_OCSP_RESP *tmp_r = NULL;
	PKI_X509_OCSP_RESP *ret = NULL;

	if( !url ) return (NULL);

	if((r_sk = PKI_X509_OCSP_RESP_STACK_get_url( url, cred, hsm )) == NULL ) {
		return(NULL);
	}

	if( PKI_STACK_OCSP_RESP_elements( r_sk ) >= 1 ) {
		ret = PKI_STACK_OCSP_RESP_pop( r_sk );
	}

	while( (tmp_r = PKI_STACK_OCSP_RESP_pop( r_sk )) != NULL ) {
		PKI_X509_OCSP_RESP_free ( tmp_r );
	}

	return (ret);
*/
}

PKI_X509_OCSP_RESP *PKI_X509_OCSP_RESP_get_mem ( PKI_MEM *mem, PKI_CRED *cred ){
	return PKI_X509_get_mem ( mem, PKI_DATATYPE_X509_OCSP_RESP, cred, NULL);
}

PKI_X509_OCSP_RESP_STACK *PKI_X509_OCSP_RESP_STACK_get (char *url_s, 
						PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_STACK_get(url_s, PKI_DATATYPE_X509_OCSP_RESP, cred,hsm);

/*
	URL *url = NULL;
	PKI_X509_OCSP_RESP_STACK *ret_sk = NULL;

	if( !url_s ) return (NULL);

	if((url = URL_new(url_s)) == NULL ) {
		return (NULL);
	}

	ret_sk = PKI_X509_OCSP_RESP_STACK_get_url ( url, cred, hsm );
	
	URL_free( url );

	return( ret_sk );
*/
}

PKI_X509_OCSP_RESP_STACK *PKI_X509_OCSP_RESP_STACK_get_url ( URL *url, 
						PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_get_url ( url, PKI_DATATYPE_X509_OCSP_RESP,
							cred, hsm );
/*
	PKI_X509_OCSP_RESP_STACK *ret = NULL;
	PKI_X509_OCSP_RESP_STACK *tmp_x_sk = NULL;
	PKI_MEM_STACK *mem_sk = NULL;
	PKI_X509_OCSP_RESP *x = NULL;

	int i = 0, count = 1;

	if( !url ) return (NULL);

        if ( url->proto == URI_PROTO_ID ) {
		PKI_log_err("ERROR::Protocol id:// not supported with "
							"OCSP REQs");
		return NULL;
        };

	if((mem_sk = URL_get_data_url ( url, 0 )) == NULL ) {
                return(NULL);
        }

        if((ret = PKI_STACK_OCSP_RESP_new()) == NULL ) {
                return(NULL);
        }

	count = 0;
	for( i = 0; i < PKI_STACK_MEM_elements( mem_sk ); i++ ) {
                PKI_MEM *n = NULL;

                if(( n = PKI_STACK_MEM_get_num( mem_sk, i )) == NULL ) {
                        break;
                }

                if((tmp_x_sk = PKI_X509_OCSP_RESP_STACK_get_mem(n, cred)) != NULL ) {
                        while ( (x = PKI_STACK_OCSP_RESP_pop( tmp_x_sk ))
                                                                 != NULL ) {
				count++;
				if( url->object_num > 0 ) { 
					if (url->object_num == count )  {
                                	     PKI_STACK_OCSP_RESP_push( ret, x );
					}
				} else {
                                	PKI_STACK_OCSP_RESP_push( ret, x );
				}
                        }
                        PKI_STACK_OCSP_RESP_free ( tmp_x_sk );
                }
        }

        if( mem_sk ) PKI_STACK_MEM_free_all ( mem_sk );

        return ( ret );
*/
}

PKI_X509_OCSP_RESP_STACK *PKI_X509_OCSP_RESP_STACK_get_mem ( PKI_MEM *mem,
							PKI_CRED *cred ) {
	return PKI_X509_STACK_get_mem ( mem, PKI_DATATYPE_X509_OCSP_RESP, 
								cred, NULL );
}


/* ---------------------------- OCSP_REQ put operations ------------------ */

int PKI_X509_OCSP_RESP_put (PKI_X509_OCSP_RESP *r, PKI_DATA_FORMAT format, 
			char *url_s, char *mime, PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_put ( r, format, url_s, mime, cred, hsm );

/*
	PKI_X509_OCSP_RESP_STACK *sk = NULL;
	int ret = PKI_OK;

	if( !r || !url_s ) return (PKI_ERR);

	if(( sk = PKI_STACK_OCSP_RESP_new()) == NULL ) return (PKI_ERR);

	if(PKI_STACK_OCSP_RESP_push( sk, r ) == PKI_ERR ) {
		PKI_STACK_OCSP_RESP_free( sk );
		return (PKI_ERR);
	}

	ret = PKI_X509_OCSP_RESP_STACK_put ( sk, format, url_s, cred, hsm );

	if( sk ) {
		PKI_X509_OCSP_RESP *tmp_r = NULL;
		while((tmp_r = PKI_STACK_OCSP_RESP_pop ( sk )) != NULL ) {
			PKI_STACK_OCSP_RESP_free (sk);
		}
	}

	return (ret);
*/
}

int PKI_X509_OCSP_RESP_put_url(PKI_X509_OCSP_RESP *r, PKI_DATA_FORMAT format, 
			URL *url, char *mime, PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_put_url ( r, format, url, mime, cred, hsm );
/*
	PKI_X509_OCSP_RESP_STACK *sk = NULL;
	int ret = PKI_OK;

	if( !r || !url ) return (PKI_ERR);

	if(( sk = PKI_STACK_OCSP_RESP_new()) == NULL ) return (PKI_ERR);

	if(PKI_STACK_OCSP_RESP_push( sk, r ) == PKI_ERR ) {
		PKI_STACK_OCSP_RESP_free( sk );
		return (PKI_ERR);
	}

	ret = PKI_X509_OCSP_RESP_STACK_put_url( sk, format, url, cred, hsm );
	if( sk ) {
		PKI_X509_OCSP_RESP *tmp_r = NULL;
		while( ( tmp_r = PKI_STACK_OCSP_RESP_pop ( sk )) != NULL ) {
			PKI_STACK_OCSP_RESP_free (sk);
		}
	}

	return( ret );
*/
}

PKI_MEM *PKI_X509_OCSP_RESP_put_mem(PKI_X509_OCSP_RESP *r, 
			PKI_DATA_FORMAT format, PKI_MEM **pki_mem, 
				PKI_CRED *cred, HSM *hsm) {
	return PKI_X509_put_mem (r, format, pki_mem, cred );
}

int PKI_X509_OCSP_RESP_STACK_put ( PKI_X509_OCSP_RESP_STACK *sk, 
			PKI_DATA_FORMAT format, char *url_s, char *mime,
				PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_STACK_put( sk, format, url_s, mime, cred, hsm );

/*
	int ret = PKI_OK;
	URL *url = NULL;

	if(!sk || !url_s ) return( PKI_ERR );

	if(PKI_STACK_OCSP_RESP_elements(sk) < 1 ) return (PKI_ERR);

	if((url = URL_new(url_s)) == NULL ) {
		return(PKI_ERR);
	}

	ret = PKI_X509_OCSP_RESP_STACK_put_url( sk, format, url, cred, hsm );

	URL_free ( url );

	return (ret);
*/

}

int PKI_X509_OCSP_RESP_STACK_put_url (PKI_X509_OCSP_RESP_STACK *sk, 
				PKI_DATA_FORMAT format, URL *url, char *mime,
					PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_put_url (sk, format, url, mime, cred, hsm );
/*
	PKI_MEM *mem = NULL;
	int idx = 0;
	int ret = 0;

	if( !sk || !url ) {
		return ( PKI_ERR );
	}

	if((idx = PKI_STACK_OCSP_RESP_elements (sk)) < 1 ) {
		return ( PKI_ERR );
	}

	if( url->proto == URI_PROTO_ID && hsm ) {
		return ( PKI_ERR );
	};

	if((mem = PKI_MEM_new_null()) == NULL ) {
		return (PKI_ERR);
	}

	if(PKI_X509_OCSP_RESP_STACK_put_mem( sk, format, mem, cred, url->object_num )
							 == PKI_ERR ) {
		if( mem ) PKI_MEM_free ( mem );
		return ( PKI_ERR );
	}

	ret = URL_put_data_url ( url, mem, "application/pki-x509-r", NULL );

	if ( mem ) PKI_MEM_free ( mem );

	return ( ret );
*/

}


PKI_MEM *PKI_X509_OCSP_RESP_STACK_put_mem ( PKI_X509_OCSP_RESP_STACK *sk, 
		PKI_DATA_FORMAT format, PKI_MEM **pki_mem, 
			PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_put_mem (sk, format, pki_mem, cred, hsm );
/*
	BIO *membio = NULL;
	BUF_MEM *buf_mem = NULL;
	int ret = PKI_OK;
	int i = 0;

	if( !sk ) return (PKI_ERR);

	if((membio = BIO_new(BIO_s_mem())) == NULL ) {
		return (PKI_ERR);
	}

	for( i = 0; i < PKI_STACK_OCSP_RESP_elements ( sk ); i++ ) {

		PKI_X509_OCSP_RESP *curr_r = NULL;
		PKI_OCSP_RESP *r_val = NULL;

		if((num > 0 ) && ( i != num )) {
			continue;
		}

		if((curr_r= PKI_STACK_OCSP_RESP_get_num( sk, i )) == NULL ) {
			break;
		}

		r_val = curr_r->value;

		switch( format ) {
			case PKI_FORMAT_PEM:
				ret = curr_r->cb->to_pem ( membio, r_val->resp);
				break;
			case PKI_FORMAT_ASN1:
				ret = curr_r->cb->to_der ( membio, r_val->resp);
				break;
			default:
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
 * OCSP_REQ File Operations
 */

/*
PKI_X509_OCSP_RESP_STACK *PKI_X509_OCSP_RESP_STACK_get_file ( URL *url ) {

        PKI_X509_OCSP_RESP *r= NULL;
        BIO *in = NULL;
        PKI_X509_OCSP_RESP_STACK *r_sk = NULL;

	PKI_OCSP_RESP *r_val = NULL;
	PKI_X509_OCSP_RESP_VALUE *x_tmp = NULL;

	const PKI_X509_CALLBACKS *cb = &PKI_X509_OCSP_RESP_CALLBACKS;

	if( !url || !url->addr ) return NULL;

        if ((in=BIO_new_file( url->addr, "r")) == NULL) {
                return(NULL);
        }

        if((r_sk = PKI_STACK_OCSP_RESP_new()) == NULL ) {
                return(NULL);
        }

	while(( x_tmp = cb->read_pem (in, NULL, 
						NULL, NULL)) != NULL) {
		if((r = PKI_X509_OCSP_RESP_new()) == NULL ) {
			continue;
		}

		r_val = r->value;

		if( r_val->resp ) {
			if( r_val->resp ) r->cb->free ( r_val->resp );
		}

		r_val->resp = x_tmp;
		PKI_STACK_OCSP_RESP_push(r_sk, r);
	}

	if( PKI_STACK_OCSP_RESP_elements( r_sk ) < 1 ) {
		while(( x_tmp = cb->read_der (in, NULL)) != NULL ) {
			if((r = PKI_X509_OCSP_RESP_new()) == NULL ) {
				continue;
			}

			r_val = r->value;

			if( r_val->resp ) {
				if( r_val->resp ) r->cb->free ( r_val->resp );
			}

			r_val->resp = x_tmp;
			PKI_STACK_OCSP_RESP_push(r_sk, r);
		}
	}

	if( PKI_STACK_OCSP_RESP_elements(r_sk) <= 0 ) {
		PKI_STACK_OCSP_RESP_free ( r_sk );
		return NULL;
	}
        return r_sk;
}

int PKI_X509_OCSP_RESP_STACK_export_file( PKI_X509_OCSP_RESP_STACK *sk, 
						int format, URL *url ) {
	BIO *out = NULL;
	PKI_X509_OCSP_RESP *r = NULL;
	PKI_OCSP_RESP *r_val = NULL;

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

	for( i=0; i < PKI_STACK_OCSP_RESP_elements( sk ); i++ ) {
		if((r = PKI_STACK_OCSP_RESP_get_num( sk, i )) == NULL) {
			break;
		}

		r_val = r->value;
		switch( format ) {
			case PKI_FORMAT_PEM:
				ret = r->cb->to_pem ( out, r_val->resp );
				break;
			case PKI_FORMAT_ASN1:
				ret = r->cb->to_der ( out, r_val->resp);
			default:
				ret = PKI_ERR;
				break;
		}
	}

	if( out ) BIO_free_all (out);

	return(ret);
}
*/
