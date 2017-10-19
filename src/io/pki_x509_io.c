/* PKI_X509 I/O management */

#include <libpki/pki.h>

/*! \brief Returns the PKI_X509_XXX_VALUE * from the passed URL */

void *PKI_get_value ( char *url_s, PKI_DATATYPE type, 
					PKI_CRED *cred, HSM *hsm ) {

	PKI_X509 *x_obj = NULL;
	void *ret = NULL;

	if( !url_s ) return NULL;

	if((x_obj = PKI_X509_get ( url_s, type, cred, hsm )) == NULL ) {
		return NULL;
	}

	ret = PKI_X509_dup_value ( x_obj );

	PKI_X509_free ( x_obj );

	return ( ret );
}

/*! \brief Retrieve an X509 object from a URL
 *
 * Downloads an X509 object from a given URL (file://, http://, ldap://...)
 * in (char *) format.
 * The returned data is of type PKI_X509 in case of success or NULL if
 * any error occurred. If multiple objects are returned from the URL, only
 * the first one is returned. Use PKI_X509_STACK_get() function
 * to retrieve a PKI_X509_STACK * object.
 *
 */

PKI_X509 *PKI_X509_get ( char *url_s, PKI_DATATYPE type, 
					PKI_CRED *cred, HSM *hsm ) {

	PKI_X509 * ret = NULL;
	URL *url = NULL;

	if( !url_s ) return (NULL);

	if((url = URL_new( url_s )) == NULL ) {
		return (NULL);
	}

	ret = PKI_X509_get_url ( url, type, cred, hsm );

	if( url ) URL_free ( url );
	return( ret );

}

/*! \brief Retrieve an X509 object from a URL pointer.
 *
 * Downloads a certificate from a given URL (file://, http://, ldap://...)
 * in (URL *) format. To generate a URL * from a char * use URL_new().
 * The returned data is of type PKI_X509 in case of success or NULL if
 * any error occurred. If multiple objects are returned from the URL, only
 * the first one is returned. Use PKI_X509_STACK_get_url() function
 * to retrieve a PKI_X509_STACK * object.
 *
 */

PKI_X509 *PKI_X509_get_url ( URL *url, PKI_DATATYPE type, 
					PKI_CRED *cred, HSM *hsm ) {

	PKI_X509_STACK *sk = NULL;
	PKI_X509 * ret = NULL;
	PKI_X509 * x = NULL;

	// Checks the pased argument
	if (!url) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return (NULL);
	}

	// Gets the stack of PKI_X509 from the provided URL
	if ((sk = PKI_X509_STACK_get_url(url, type, cred, hsm)) == NULL) {
		return (NULL);
	}
 
	// Assign the first element to ret and discards the others
	while ((x = PKI_STACK_X509_pop(sk)) != NULL) {
		if (ret == NULL) ret = x;
		else PKI_X509_free(x);
	}

	/*
	if( PKI_STACK_X509_elements( sk ) >= 1 ) {
		PKI_X509 *x = NULL;

		ret = PKI_STACK_X509_pop( sk );
		while ( (x = PKI_STACK_X509_pop ( sk )) != NULL ) {
			PKI_X509_free ( x );
		}
	}
	*/

	// Free the stack data structure
	if (sk) PKI_STACK_X509_free_all(sk);

	// Returns the first element from the stack
	return ret;

}

/*! \brief Retrieve a stack of X509 objects from a URL (char *).
 *
 * Downloads a stack of X509 objects from a given URL (file://, http://,
 * ldap://...) passed as a (char *).
 *
 * The returned data is a pointer to a PKI_X509_STACK data structure
 * in case of success or NULL if any error occurred.
 * If only the first object is required from the URL, use the 
 * PKI_X509_get_url() function instead.
 *
 */

PKI_X509_STACK *PKI_X509_STACK_get ( char *url_s, PKI_DATATYPE type, 
						PKI_CRED *cred, HSM *hsm ) {

	URL *url = NULL;
	PKI_X509_STACK *ret = NULL;

	if( !url_s ) return (NULL);

	if((url = URL_new( url_s )) == NULL ) {
		return(NULL);
	}

	ret = PKI_X509_STACK_get_url ( url, type, cred, hsm );

	if( url ) URL_free ( url );
	return ( ret );
}

/*! \brief Retrieve a stack of X509 objects from a URL (URL *) pointer.
 *
 * Downloads a stack of certificates from a given URL (file://, http://,
 * ldap://...) passed as a (URL *).  To generate a (URL *) from a (char *)
 * use URL_new().
 *
 * The returned data is a pointer to a PKI_X509_STACK data structure
 * in case of success or NULL if any error occurred.
 * If only the first object is required from the URL, use the 
 * PKI_X509_get_url() function instead.
 *
 */

PKI_X509_STACK *PKI_X509_STACK_get_url ( URL *url, PKI_DATATYPE type,
						PKI_CRED *cred, HSM *hsm ) {
	
	PKI_X509_STACK *ret = NULL;
	PKI_X509_STACK *tmp_x_sk = NULL;
	PKI_MEM_STACK *mem_sk = NULL;
	PKI_X509_CERT *x = NULL;
	PKI_MEM * el = NULL;

	PKI_SSL *ssl = NULL;

	int i, j, count;

	PKI_DATATYPE x509_types[] = {
		PKI_DATATYPE_PUBKEY,
		PKI_DATATYPE_PRIVKEY,
		PKI_DATATYPE_X509_KEYPAIR,
		PKI_DATATYPE_X509_REQ,
		PKI_DATATYPE_X509_CERT,
		PKI_DATATYPE_X509_CRL,
		PKI_DATATYPE_X509_PKCS7,
		PKI_DATATYPE_X509_PKCS12,
		PKI_DATATYPE_X509_OCSP_REQ,
		PKI_DATATYPE_X509_OCSP_RESP,
		PKI_DATATYPE_X509_PRQP_REQ,
		PKI_DATATYPE_X509_PRQP_RESP,
		PKI_DATATYPE_X509_CMS_MSG,
		PKI_DATATYPE_X509_CA,
		PKI_DATATYPE_X509_TRUSTED,
		PKI_DATATYPE_X509_OTHER
	};

	int x509_types_len = sizeof( x509_types ) / sizeof (int);

	if(!url) return NULL;

	if ( url->proto == URI_PROTO_ID ) {
		if( !hsm ) {
			PKI_log_debug("PKI_X509_STACK_get_url()::"
				"Protocol id:// used but no HSM!");
			return ( NULL );
		}
		return ( HSM_X509_STACK_get_url ( type, url, cred, hsm ));
	}

	if (cred) {
		ssl = (PKI_SSL *) cred->ssl;
		if ( !url->usr && cred->username ) {
			url->usr = strdup ( cred->username );
		}

		if ( !url->pwd && cred->password ) {
			url->pwd = strdup ( cred->password );
		}
	}

	if ((mem_sk = URL_get_data_url(url, 60, 0, ssl)) == NULL) {
		return(NULL);
	}

	if((ret = PKI_STACK_X509_new()) == NULL ) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		PKI_STACK_MEM_free_all(mem_sk);
		return(NULL);
	}


	count = 0;
	for( i = 0; i < PKI_STACK_MEM_elements( mem_sk ); i++ ) {

		PKI_MEM *n = NULL;

		// Gets the i-th PKI_MEM from the stack of elements
		if(( n = PKI_STACK_MEM_get_num( mem_sk, i )) == NULL ) {
			break;
		}

		if ( type == PKI_DATATYPE_ANY ) {

			// Tries any supported data types
			for ( j = 0; j < x509_types_len; j++ ) {
				PKI_DATATYPE curr_type;

				curr_type = x509_types[j];

				if((tmp_x_sk = PKI_X509_STACK_get_mem(n, curr_type, 
									cred, hsm)) != NULL) {
					while ( (x = PKI_STACK_X509_pop( tmp_x_sk )) != NULL ) {
						count++;
						if ( url->object_num > 0) {
							if( count == url->object_num)  {
							    PKI_STACK_X509_push( ret, x );
							} else {
							    PKI_X509_free(x);
							}
						} else {
							PKI_STACK_X509_push( ret, x );
						}
					}
					PKI_STACK_X509_free_all ( tmp_x_sk );
				}
			}

		} else {

			// Use the passed 'type' to parse the data
			if((tmp_x_sk = PKI_X509_STACK_get_mem(n, type, 
								cred, hsm)) != NULL) {

				// Process (remove) next element from the inner stack
				while ( (x = PKI_STACK_X509_pop( tmp_x_sk )) != NULL ) {

					count++;

					if ( url->object_num > 0) {
						// We check if the object_number is the one
						// we were seeking
						if( count == url->object_num)  {

						    // Push the value to the return stack
						    PKI_STACK_X509_push( ret, x );

						} else {

						    // Free the memory for the value since
						    // it is not the one we were looking for
						    PKI_X509_free(x);
						}
					} else {

						// If no specific object_number was set,
						// let's push the value to the return stack
						PKI_STACK_X509_push( ret, x );
					}
				}

				// No more values to analyze, let's free all
				// the remaining memory
				PKI_STACK_X509_free_all ( tmp_x_sk );
			}
		}
	}


	// If we have a 'mem_sk' stack
	if (mem_sk) {

		// Free memory for all the PKI_MEM elements
		while ((el = PKI_STACK_MEM_pop(mem_sk)) != NULL) {
			PKI_MEM_free(el);
		}
		// Free the stack itself
		PKI_STACK_MEM_free_all ( mem_sk );
	}

	// Return the objects' stack
	return ret;
}

/* --------------------------- X509_CERT put (write) ----------------------- */

/*! \brief Puts a PKI_X509 object into the passed url (string) */

int PKI_X509_put ( PKI_X509 *x, PKI_DATA_FORMAT format, char *url_string, 
			const char *mime, PKI_CRED *cred, HSM *hsm ) {

	PKI_X509_STACK *sk = NULL;
	int ret = PKI_OK;

	if( !x || !url_string ) return (PKI_ERR);

	if(( sk = PKI_STACK_X509_new()) == NULL ) {
		return( PKI_ERR );
	}

	if( PKI_STACK_X509_push( sk, x ) == PKI_ERR ) {
		PKI_STACK_X509_free ( sk );
		return ( PKI_ERR );
	}

	ret = PKI_X509_STACK_put(sk, format, url_string, mime, cred, hsm);

	if (sk) {
		/* We just need to pop the cert - not free the mem! */
		while ((x = PKI_STACK_X509_pop( sk )) != NULL ) { /* Nop */ };

		/* Let's free the list itself */
                PKI_STACK_X509_free( sk );
	}

	return (ret);

}

/*! \brief Put a PKI_X509 object to the specified URL */

int PKI_X509_put_url ( PKI_X509 *x, PKI_DATA_FORMAT format, URL *url, 
			const char *mime, PKI_CRED *cred, HSM *hsm ) {

	PKI_X509_STACK *sk = NULL;
	int ret = PKI_OK;

	if( !x || !url ) return (PKI_ERR);

	if(( sk = PKI_STACK_X509_new()) == NULL ) {
		return( PKI_ERR );
	}

	if( PKI_STACK_X509_push( sk, x ) == PKI_ERR ) {
		PKI_STACK_X509_free ( sk );
		return ( PKI_ERR );
	}

	ret = PKI_X509_STACK_put_url(sk, format, url, mime, cred, hsm);

	if( sk ) {
		/* We just need to pop the cert - not free the mem! */
		while ((x = PKI_STACK_X509_pop( sk )) != NULL ) { /* NoP */ };

		/* Let's free the list itself */
                PKI_STACK_X509_free( sk );
	}

	return (ret);
}

/*! \brief Writes the PKI_X509_XXX_VALUE to the passed url */

int PKI_X509_put_value ( void *x, PKI_DATATYPE type, PKI_DATA_FORMAT format,
		char *url_string, const char *mime, PKI_CRED *cred, HSM *hsm ) {

	PKI_X509 *x_obj = NULL;
	int ret = PKI_OK;

	if ( !x || !url_string ) return PKI_ERR;

	if(( x_obj = PKI_X509_new ( type, hsm )) == NULL ) {
		return PKI_ERR;
	}

	x_obj->value = x;

	ret = PKI_X509_put ( x_obj, format, url_string, mime, cred, hsm );

	x_obj->value = NULL;

	PKI_X509_free ( x_obj );

	return ret;
}

/*! \brief Puts a stack of PKI_X509 objects to the url passed as a string */

int PKI_X509_STACK_put (PKI_X509_STACK *sk, PKI_DATA_FORMAT format, 
		char *url_string, const char *mime, PKI_CRED *cred, HSM *hsm) {

	URL *url = NULL;
	int ret = PKI_OK;

	if( !sk || !url_string ) return (PKI_ERR);

	if((url = URL_new (url_string)) == NULL ) {
		return (PKI_ERR);
	}

	ret = PKI_X509_STACK_put_url( sk, format, url, mime, cred, hsm );

	if( url ) URL_free ( url );

	return ( ret );
	
}

/*! \brief Puts a stack of PKI_X509 objects to a specified URL */

int PKI_X509_STACK_put_url (PKI_X509_STACK *sk, PKI_DATA_FORMAT format, 
		URL *url, const char *mime, PKI_CRED *cred, HSM *hsm) {

	PKI_MEM *mem = NULL;
	PKI_X509 *x_obj = NULL;
	PKI_SSL *ssl = NULL;

	int idx = 0;
	int ret = 0;

	if( !sk || !url ) {
		return ( PKI_ERR );
	}

	if((idx = PKI_STACK_X509_elements (sk)) < 1 ) {
		return ( PKI_ERR );
	}

	if( url->proto == URI_PROTO_ID && hsm ) {
		return ( HSM_X509_STACK_put_url ( sk, url, cred, hsm ));
	};

	/* Now that we know the HSM is off the hook, we save it into a
	   PKI_MEM structure and then we 'put' it via the general function */
	/*
	if((mem = PKI_MEM_new_null()) == NULL ) {
		return (PKI_ERR);
	}
	*/

	if(PKI_X509_STACK_put_mem( sk, format, &mem, cred, hsm ) == NULL ) {
		if( mem ) PKI_MEM_free ( mem );
		return ( PKI_ERR );
	}

	/* Lets get the type of X509 objects we have on the stack */
	if((x_obj = PKI_STACK_X509_get_num ( sk, 0 )) != NULL ) {
		mime = PKI_X509_get_mimetype ( x_obj->type );
	} else {
		mime = PKI_X509_get_mimetype ( PKI_DATATYPE_UNKNOWN );
	}

	if ( cred ) {
		ssl = (PKI_SSL *) cred->ssl;
		if ( !url->usr && cred->username ) {
			url->usr = strdup ( cred->username );
		}

		if ( !url->pwd && cred->password ) {
			url->pwd = strdup ( cred->password );
		}
	}

	ret = URL_put_data_url ( url, mem, (char *) mime, NULL, 60, 0, ssl );

	if ( mem ) PKI_MEM_free ( mem );

	return ( ret );
}


