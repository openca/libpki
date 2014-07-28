/* PKI_X509 I/O management */

#include <libpki/pki.h>

/*! \brief Retrieve a CRL from a URL
 *
 * Downloads a CRL from a given URL (file://, http://, ldap://...)
 * in (char *) format.
 * The returned data is of type PKI_X509_CRL in case of success or NULL if
 * any error occurred. If multiple objects are returned from the URL, only
 * the first one is returned. Use PKI_X509_CRL_STACK_get() function
 * to retrieve a PKI_X509_CERT_STACK * object.
 *
 */

PKI_X509_CRL *PKI_X509_CRL_get ( char *url_s, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_get ( url_s, PKI_DATATYPE_X509_CRL, cred, hsm );
/*
	PKI_X509_CRL * ret = NULL;
	URL *url = NULL;

	if( !url_s ) return (NULL);

	if((url = URL_new( url_s )) == NULL ) {
		return (NULL);
	}

	ret = PKI_X509_CRL_get_url ( url, cred, hsm );

	if ( url ) URL_free ( url );

	return( ret );
*/

}

/*! \brief Retrieve a CRL from a URL pointer.
 *
 * Downloads a CRL from a given URL (file://, http://, ldap://...)
 * in (URL *) format. To generate a URL * from a char * use URL_new().
 * The returned data is of type PKI_X509_CRL * in case of success or NULL if
 * any error occurred. If multiple objects are returned from the URL, only
 * the first one is returned. Use PKI_X509_CRL_get_url() function
 * to retrieve a PKI_X509_CRL_STACK * object.
 *
 */

PKI_X509_CRL *PKI_X509_CRL_get_url ( URL *url, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_get_url ( url, PKI_DATATYPE_X509_CRL, cred, hsm );
/*
	PKI_X509_CRL_STACK *sk = NULL;
	PKI_X509_CRL * ret = NULL;

	if( !url ) return (NULL);

	if((sk = PKI_X509_CRL_STACK_get_url ( url, cred, hsm )) == NULL ) {
		return (NULL);
	}

	if( PKI_STACK_X509_CRL_elements( sk ) >= 1 ) {
		ret = PKI_STACK_X509_CRL_pop( sk );
	}

	if( sk ) PKI_STACK_X509_CRL_free ( sk );

	return ( ret );
*/
}

PKI_X509_CRL * PKI_X509_CRL_get_mem ( PKI_MEM *mem, PKI_CRED *cred, HSM *hsm ) {
	return PKI_X509_get_mem ( mem, PKI_DATATYPE_X509_CRL, cred, NULL );
}

/*! \brief Retrieve a stack of CRLs from a URL (char *).
 *
 * Downloads a stack of CRLs from a given URL (file://, http://,
 * ldap://...) passed as a (char *).
 *
 * The returned data is a pointer to a PKI_X509_CRL_STACK data structure
 * in case of success or NULL if any error occurred.
 * If only the first object is required from the URL, use the 
 * PKI_X509_CRL_get_url() function instead.
 *
 */

PKI_X509_CRL_STACK *PKI_X509_CRL_STACK_get (char *url_s, PKI_CRED *cred, 
								HSM *hsm) {

	return PKI_X509_STACK_get ( url_s, PKI_DATATYPE_X509_CRL, cred, hsm );
/*
	URL *url = NULL;
	PKI_X509_CRL_STACK *ret = NULL;

	if( !url_s ) return (NULL);

	if((url = URL_new( url_s )) == NULL ) {
		return(NULL);
	}

	ret = PKI_X509_CRL_STACK_get_url ( url, cred, hsm );

	if ( url ) URL_free ( url );

	return ( ret );
*/
}

/*! \brief Retrieve a stack of CRLs from a URL (URL *) pointer.
 *
 * Downloads a stack of CRLs from a given URL (file://, http://,
 * ldap://...) passed as a (URL *).  To generate a (URL *) from a (char *)
 * use URL_new().
 *
 * The returned data is a pointer to a PKI_X509_CRL_STACK data structure
 * in case of success or NULL if any error occurred.
 * If only the first object is required from the URL, use the 
 * PKI_X509_CRL_get_url() function instead.
 *
 */

PKI_X509_CRL_STACK *PKI_X509_CRL_STACK_get_url ( URL *url, PKI_CRED *cred,
								HSM *hsm ) {
	
	return PKI_X509_STACK_get_url ( url, PKI_DATATYPE_X509_CRL, cred, hsm );
/*
        PKI_X509_CRL_STACK *ret = NULL;
	PKI_MEM_STACK *mem_sk = NULL;
	PKI_X509_CRL_STACK *tmp_sk = NULL;
	PKI_X509_CRL *x = NULL;

	int i, count;

	if(!url) return NULL;

	if( url->proto == URI_PROTO_ID ) {
		PKI_log_debug("ERROR, missing code (check %s:%d)",
					__FILE__, __LINE__ );
		return NULL;
	}

	if((mem_sk = URL_get_data_url ( url, 0 )) == NULL ) {
		return(NULL);
	}

	if((ret = PKI_STACK_X509_CRL_new()) == NULL ) {
		return(NULL);
	}

	count = 0;
	for( i = 0; i < PKI_STACK_MEM_elements( mem_sk ); i++ ) {
		PKI_MEM *n = NULL;

		if(( n = PKI_STACK_MEM_get_num( mem_sk, i )) == NULL ) {
			break;
		}

		if((tmp_sk = PKI_X509_CRL_STACK_get_mem(n,cred)) != NULL ) {
			while((x = PKI_STACK_X509_CRL_pop( tmp_sk )) != NULL ) {
				count++;

				if(url->object_num > 0 ) {
					if (count == url->object_num ) {
					     PKI_STACK_X509_CRL_push ( ret, x );
					}
				} else {
					PKI_STACK_X509_CRL_push ( ret, x );
				}
			}
			PKI_STACK_X509_CRL_free( tmp_sk );
		}
	}

        return (ret);
*/
}

PKI_X509_CRL_STACK *PKI_X509_CRL_STACK_get_mem( PKI_MEM *mem, PKI_CRED *cred ) {

	return PKI_X509_STACK_get_mem (mem, PKI_DATATYPE_X509_CRL, cred, NULL );
/*
	PKI_X509_CRL * x = NULL;
	PKI_X509_CRL_STACK *sk = NULL;
	BIO *membio = NULL;
	BUF_MEM *p = NULL;

	long curr = 0;
	int cont = 1;

	if( !mem || mem->size <= 0 ) return (NULL);

	if((membio = BIO_new_mem_buf( mem->data, (int) mem->size )) == NULL ) {
		return( NULL );
	}

	if(BIO_set_close(membio, BIO_NOCLOSE) != 1 ) {
		BIO_free ( membio );
		return( NULL );
	}

	if((sk = PKI_STACK_X509_CRL_new()) == NULL ) {
		BIO_free ( membio );
		return(NULL);
	}


	cont = 1;
	p = (BUF_MEM *) membio->ptr;
	curr = p->length;
	while ((cont == 1) && (p->length > 0)) {

		curr = p->length;

        	if(( x = (PKI_X509_CRL *) 
			PEM_read_bio_X509_CRL(membio,NULL,NULL,NULL)) == NULL){

			p->length = curr;
			p->data -= curr;

			if((x=(PKI_X509_CRL *) d2i_X509_CRL_bio(membio,NULL)) == NULL ) {
				cont = 0;
			} else {
				PKI_STACK_X509_CRL_push( sk, x );
			}
		} else {
			PKI_STACK_X509_CRL_push( sk, x );

		}
	}

	if(membio) BIO_free( membio );

	return( sk );
*/
}

int PKI_X509_CRL_put ( PKI_X509_CRL *crl, PKI_DATA_FORMAT format, char *url_s,
				PKI_CRED *cred, HSM *hsm ) {
	return PKI_X509_put ( crl, format, url_s, NULL, cred, hsm );
}

int PKI_X509_CRL_put_url ( PKI_X509_CRL *crl, PKI_DATA_FORMAT format,
				URL *url, PKI_CRED *cred, HSM *hsm ) {
	return PKI_X509_put_url ( crl, format, url, NULL, cred, hsm );
}

PKI_MEM *PKI_X509_CRL_put_mem ( PKI_X509_CRL *crl, PKI_DATA_FORMAT format,
				PKI_MEM **mem, PKI_CRED *cred, HSM *hsm ) {
	return PKI_X509_put_mem ( crl, format, mem, cred );
}

int PKI_X509_CRL_STACK_put ( PKI_X509_CRL_STACK *sk, PKI_DATA_FORMAT format,
			char *url_s, PKI_CRED *cred, HSM *hsm ) {
	return PKI_X509_STACK_put ( sk, format, url_s, NULL, cred, hsm );
}

int PKI_X509_CRL_STACK_put_url ( PKI_X509_CRL_STACK *sk, PKI_DATA_FORMAT format,
			URL *url, PKI_CRED *cred, HSM *hsm ) {
	return PKI_X509_STACK_put_url ( sk, format, url, NULL, cred, hsm );
}

PKI_MEM *PKI_X509_CRL_STACK_put_mem (PKI_X509_CRL_STACK *sk, 
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

	for( i = 0; i < PKI_STACK_X509_CRL_elements ( sk ); i++ ) {

		PKI_X509_CRL *curr_crl = NULL;

		if( ( num > 0 ) && ( i != num ) ) {
			continue;
		}

		if((curr_crl = PKI_STACK_X509_CRL_get_num( sk, i ))
							== NULL ) {
			break;
		}

		switch( format ) {
			case PKI_FORMAT_PEM:
				ret = PEM_write_bio_X509_CRL( membio, 
						(X509_CRL *) curr_crl);
				break;
			case PKI_FORMAT_ASN1:
				ret = i2d_X509_CRL_bio( membio, 
						(X509_CRL *) curr_crl);
				break;
			case PKI_FORMAT_TXT:
				ret = X509_CRL_print( membio, 
						(X509_CRL *) curr_crl);
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
int PKI_X509_CERT_write ( PKI_X509_CERT *x, int format, char *url_string ) {

	PKI_X509_CERT_STACK *sk = NULL;
	int ret = PKI_OK;

	if( !x || !url_string ) return (PKI_ERR);

	if(( sk = PKI_STACK_X509_CERT_new()) == NULL ) {
		return( PKI_ERR );
	}

	if( PKI_STACK_X509_CERT_push( sk, x ) == PKI_ERR ) {
		ret = PKI_ERR;
	} else {
		ret = PKI_X509_CERT_STACK_write( sk, format, url_string);
	}

	if( sk ) {
		// PKI_X509_CERT *tmp_x = NULL;

		while((x = PKI_STACK_X509_CERT_pop( sk )) != NULL ) {
			PKI_STACK_X509_CERT_free( sk );
		}
	}

	return (ret);

}

int PKI_X509_CERT_STACK_write (PKI_X509_CERT_STACK *sk, int format, 
							char *url_string) {

	URL *url = NULL;

	if( !sk || !url_string ) return (PKI_ERR);

	if((url = URL_new (url_string)) == NULL ) {
		return (PKI_ERR);
	}

	return (PKI_X509_CERT_STACK_write_url( sk, format, url ));
	
}


int PKI_X509_CERT_STACK_write_url (PKI_X509_CERT_STACK *sk, int format, 
								URL *url ) {

	if( !sk || !url ) return (PKI_ERR);

	switch( url->proto ) {
		case URI_PROTO_FILE:
			return PKI_X509_CERT_STACK_write_file( sk, format, 
							url->addr);
			break;
	}

	return( PKI_ERR );
}


int PKI_X509_CERT_chain_write(PKI_X509_CERT_STACK *sk,int format,char *url_s) {

	URL *url = NULL;
	int ret = PKI_OK;

	if( !sk || !url_s ) return (PKI_ERR);

	if((url = URL_new (url_s)) == NULL ) {
		return (PKI_ERR);
	}

	ret = PKI_X509_CERT_chain_write_url( sk, format, url );

	if( url ) URL_free (url);

	return(ret);
}

int PKI_X509_CERT_chain_write_url(PKI_X509_CERT_STACK *sk,int format,URL *url) {

	if( !sk || !url ) return (PKI_ERR);

	switch( url->proto ) {
		case URI_PROTO_FILE:
			return PKI_X509_CERT_STACK_write_file( sk, format, 
								url->addr);
			break;
	}

	return( PKI_ERR );
}


PKI_X509_CERT_STACK *PKI_X509_CERT_STACK_get_file ( URL *url ) {

        PKI_X509_CERT *x = NULL;
        BIO *in = NULL;
        PKI_X509_CERT_STACK *x_sk = NULL;

	if( !url || !url->addr ) return NULL;

        if ((in=BIO_new_file( url->addr, "r")) == NULL) {
                return(NULL);
        }

        if((x_sk = PKI_STACK_X509_CERT_new()) == NULL ) {
                return(NULL);
        }

	while(( x = (PKI_X509_CERT *) PEM_read_bio_X509(in, NULL, NULL, NULL)) 
								== NULL ) {
		PKI_STACK_X509_CERT_push(x_sk, x);
	}

	if( PKI_STACK_X509_CERT_elements( x_sk ) < 1 ) {
		while(( x = (PKI_X509_CERT *) d2i_X509_bio(in, NULL)) == NULL ) {
			PKI_STACK_X509_CERT_push(x_sk, x);
		}
	}

	if( PKI_STACK_X509_CERT_elements(x_sk) == 0 ) {
		PKI_STACK_X509_CERT_free (x_sk );
		return NULL;
	}
        return x_sk;
}

int PKI_X509_CERT_write_file ( PKI_X509_CERT *x, int format, char *file ) {

	BIO *out = NULL;
	int ret = PKI_OK;

	if( !x ) return (PKI_ERR);

	if((out = BIO_new(BIO_s_file())) == NULL ) {
		printf("%s:%d error\n", __FILE__, __LINE__ );
		return (PKI_ERR);
	}

	if( !file ) {
		 BIO_set_fp(out,stdout,BIO_NOCLOSE);
	} else {
		ret = BIO_write_filename( out, file);
		if( ret == 0 ) {
			if( out ) BIO_free_all (out);
			return (PKI_ERR);
		}
	}

	switch( format ) {
		case PKI_FORMAT_PEM:
			ret = PEM_write_bio_X509( out, (X509 *) x);
			break;
		case PKI_FORMAT_ASN1:
			ret = i2d_X509_bio( out, (X509 *) x);
			break;
		default:
			printf("%s:%d error\n", __FILE__, __LINE__ );
			return(PKI_ERR);
	}

	if( out ) BIO_free_all (out);

	if( ret == 0 ) 
		return (PKI_ERR);
	else
		return(PKI_OK);

}

int PKI_X509_CERT_STACK_write_file(PKI_X509_CERT_STACK *sk, int format, 
								char *file){

	BIO *out = NULL;
	int ret = PKI_OK;
	int i = 0;

	if( !sk ) return (PKI_ERR);

	if((out = BIO_new(BIO_s_file())) == NULL ) {
		printf("%s:%d error\n", __FILE__, __LINE__ );
		return (PKI_ERR);
	}

	if( !file ) {
		 BIO_set_fp(out,stdout,BIO_NOCLOSE);
	} else {
		ret = BIO_write_filename( out, file);
		if( ret == 0 ) {
			if( out ) BIO_free_all (out);
			return (PKI_ERR);
		}
	}

	for( i = 0; i < PKI_STACK_X509_CERT_elements ( sk ); i++ ) {
		PKI_X509_CERT *curr_cert = NULL;

		if((curr_cert = PKI_STACK_X509_CERT_get_num( sk, i ))
							== NULL ) {
			break;
		}

		switch( format ) {
			case PKI_FORMAT_PEM:
				ret = PEM_write_bio_X509( out, 
							(X509 *) curr_cert);
				break;
			case PKI_FORMAT_ASN1:
				ret = i2d_X509_bio( out, (X509 *) curr_cert);
				break;
			default:
				printf("%s:%d error\n", __FILE__, __LINE__ );
				return(PKI_ERR);
		}
	}

	if( out ) BIO_free_all (out);

	if( ret == 0 ) 
		return (PKI_ERR);
	else
		return(PKI_OK);

}

*/
