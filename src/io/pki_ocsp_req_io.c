/* PKI_X509_OCSP_REQ I/O management */

#include <libpki/pki.h>

PKI_X509_OCSP_REQ *PKI_X509_OCSP_REQ_get ( char *url_s, 
					PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm ) {
	return PKI_X509_get ( url_s, PKI_DATATYPE_X509_OCSP_REQ, format, cred, hsm );

/*
	PKI_X509_OCSP_REQ_STACK *r_sk = NULL;
	PKI_X509_OCSP_REQ *tmp_r = NULL;
	PKI_X509_OCSP_REQ *ret = NULL;

	if( !url_s ) return (NULL);

	if((r_sk = PKI_X509_OCSP_REQ_STACK_get( url_s, cred, hsm )) == NULL ) {
		return(NULL);
	}

	if( PKI_STACK_OCSP_REQ_elements( r_sk ) >= 1 ) {
		ret = PKI_STACK_OCSP_REQ_pop( r_sk );
	}

	while( (tmp_r = PKI_STACK_OCSP_REQ_pop( r_sk )) != NULL ) {
		PKI_X509_OCSP_REQ_free ( tmp_r );
	}

	return( ret );
*/
}

PKI_X509_OCSP_REQ *PKI_X509_OCSP_REQ_get_url ( URL *url, 
						PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_get_url ( url, PKI_DATATYPE_X509_OCSP_REQ, format, cred, hsm );
/*
	PKI_X509_OCSP_REQ_STACK *r_sk = NULL;
	PKI_X509_OCSP_REQ *tmp_r = NULL;
	PKI_X509_OCSP_REQ *ret = NULL;

	if( !url ) return (NULL);

	if((r_sk = PKI_X509_OCSP_REQ_STACK_get_url( url, cred, hsm )) == NULL ) {
		return(NULL);
	}

	if( PKI_STACK_OCSP_REQ_elements( r_sk ) >= 1 ) {
		ret = PKI_STACK_OCSP_REQ_pop( r_sk );
	}

	while( (tmp_r = PKI_STACK_OCSP_REQ_pop( r_sk )) != NULL ) {
		PKI_X509_OCSP_REQ_free ( tmp_r );
	}

	return (ret);
*/
}

PKI_X509_OCSP_REQ *PKI_X509_OCSP_REQ_get_mem ( PKI_MEM *mem, 
						PKI_DATA_FORMAT format, PKI_CRED *cred ) {
	return PKI_X509_get_mem ( mem, PKI_DATATYPE_X509_OCSP_REQ, format, cred, NULL);
}


PKI_X509_OCSP_REQ_STACK *PKI_X509_OCSP_REQ_STACK_get (char *url_s, 
						PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_STACK_get (url_s, PKI_DATATYPE_X509_OCSP_REQ, format, cred, hsm);
/*
	URL *url = NULL;
	PKI_X509_OCSP_REQ_STACK *ret_sk = NULL;

	if( !url_s ) return (NULL);

	if((url = URL_new(url_s)) == NULL ) {
		return (NULL);
	}

	ret_sk = PKI_X509_OCSP_REQ_STACK_get_url ( url, cred, hsm );
	
	URL_free( url );

	return( ret_sk );
*/
}

PKI_X509_OCSP_REQ_STACK *PKI_X509_OCSP_REQ_STACK_get_url ( URL *url, 
						PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_get_url (url, PKI_DATATYPE_X509_OCSP_REQ,
							format, cred, hsm );
/*
	PKI_X509_OCSP_REQ_STACK *ret = NULL;
	PKI_X509_OCSP_REQ_STACK *tmp_x_sk = NULL;
	PKI_MEM_STACK *mem_sk = NULL;
	PKI_X509_OCSP_REQ *x = NULL;

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

        if((ret = PKI_STACK_OCSP_REQ_new()) == NULL ) {
                return(NULL);
        }

	count = 0;
	for( i = 0; i < PKI_STACK_MEM_elements( mem_sk ); i++ ) {
                PKI_MEM *n = NULL;

                if(( n = PKI_STACK_MEM_get_num( mem_sk, i )) == NULL ) {
                        break;
                }

                if((tmp_x_sk = PKI_X509_OCSP_REQ_STACK_get_mem(n, cred)) != NULL ) {
                        while ( (x = PKI_STACK_OCSP_REQ_pop( tmp_x_sk ))
                                                                 != NULL ) {
				count++;
				if( url->object_num > 0 ) { 
					if (url->object_num == count )  {
                                	     PKI_STACK_OCSP_REQ_push( ret, x );
					}
				} else {
                                	PKI_STACK_OCSP_REQ_push( ret, x );
				}
                        }
                        PKI_STACK_OCSP_REQ_free ( tmp_x_sk );
                }
        }

        if( mem_sk ) PKI_STACK_MEM_free_all ( mem_sk );

        return ( ret );
*/
}

PKI_X509_OCSP_REQ_STACK *PKI_X509_OCSP_REQ_STACK_get_mem( PKI_MEM *mem, 
							PKI_DATA_FORMAT format, PKI_CRED *cred) {

	return PKI_X509_STACK_get_mem (mem, PKI_DATATYPE_X509_OCSP_REQ, 
							format, cred, NULL );
/*
	PKI_X509_OCSP_REQ * x = NULL;
	PKI_X509_OCSP_REQ_VALUE *x_val = NULL;
	PKI_X509_OCSP_REQ_STACK *sk = NULL;

	BUF_MEM *p = NULL;
	PKI_IO *membio = NULL;

	char *temp = NULL;
	int cont = 1;
	long curr = 0;

	size_t mem_size = 0;
	char * mem_buf = NULL;

	if( !mem || mem->size <= 0 ) return (NULL);

	if((temp = strstr((char *) mem->data, 
				PKI_X509_OCSP_REQ_BEGIN_ARMOUR )) == NULL ) {
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

	if((sk = PKI_STACK_OCSP_REQ_new()) == NULL ) {
		BIO_free( membio );
		return(NULL);
	}

	cont = 1;
	p = (BUF_MEM *) membio->ptr;
	curr = p->length;
	while ((cont == 1) && (p->length > 0)) {

		curr = p->length;

        	if(( x_val =  PEM_read_bio_OCSP_REQ(membio, NULL, 
						NULL, NULL)) == NULL){

			p->length = curr;
			p->data -= curr;

			if((x_val = d2i_OCSP_REQUEST_bio ( membio, 
							NULL)) == NULL ) {
				cont = 0;
			}
		}

		if ( x_val ) {
			if((x = PKI_X509_new ( PKI_DATATYPE_X509_OCSP_REQ)) != NULL ) {
				x->value = x_val;
				PKI_STACK_OCSP_REQ_push ( sk, x );
			}
		}
	}

	if(membio) BIO_free( membio );
	return( sk );
*/
}

/* ---------------------------- OCSP_REQ put operations ------------------ */

int PKI_X509_OCSP_REQ_put (PKI_X509_OCSP_REQ *req, PKI_DATA_FORMAT format, 
			char *url_s, char *mime, PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_put ( req, format, url_s, mime, cred, hsm );
}

int PKI_X509_OCSP_REQ_put_url(PKI_X509_OCSP_REQ *req, PKI_DATA_FORMAT format, 
			URL *url, char *mime, PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_put_url ( req, format, url, mime, cred, hsm );
}

PKI_MEM *PKI_X509_OCSP_REQ_put_mem ( PKI_X509_OCSP_REQ *req,
			PKI_DATA_FORMAT format, PKI_MEM **pki_mem,
				PKI_CRED *cred, HSM *hsm ) {
	return PKI_X509_put_mem ( req, format, pki_mem, cred );
}


int PKI_X509_OCSP_REQ_STACK_put ( PKI_X509_OCSP_REQ_STACK *sk, 
			PKI_DATA_FORMAT format, char *url_s, char *mime,
				PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_STACK_put ( sk, format, url_s, mime, cred, hsm );

}

int PKI_X509_OCSP_REQ_STACK_put_url (PKI_X509_OCSP_REQ_STACK *sk, 
			PKI_DATA_FORMAT format, URL *url, char *mime,
				PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_put_url ( sk, format, url, mime, cred, hsm );
}

PKI_MEM * PKI_X509_OCSP_REQ_STACK_put_mem ( PKI_X509_OCSP_REQ_STACK *sk, 
			PKI_DATA_FORMAT format, PKI_MEM **pki_mem, 
				PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_put_mem ( sk, format, pki_mem, cred, hsm );
}

