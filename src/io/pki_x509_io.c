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

	// Checks we have at least one element, otherwise we return null
	if (PKI_STACK_X509_elements(sk) <= 0) {
			// Free the memory for the Stack
			PKI_STACK_X509_free(sk);
			// Returns
			return NULL;
	}
 
	// Gets the first element as the one to keep
	ret = PKI_STACK_X509_pop(sk);

	// Free all the other elements in the stack
	PKI_STACK_X509_free_all(sk);

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
		// Return Stack of X509

	PKI_X509_STACK *tmp_x_sk = NULL;
		// Stack of X509 returned from the URL

	PKI_MEM_STACK *mem_sk = NULL;
	PKI_MEM * tmp_mem = NULL;

	PKI_X509_CERT *x = NULL;

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

	// Checks for the use of the ID protocol (for HSM/Hardware)
	if ( url->proto == URI_PROTO_ID ) {

		// If there is no associated HSM, that is an error
		if( !hsm ) {
			PKI_log_err("Protocol id:// used but no HSM!");
			return NULL ;
		}

		// Returns the stack of returned items (ID Protocol)
		return ( HSM_X509_STACK_get_url ( type, url, cred, hsm ));
	}

	// If Credentials are to be used
	if (cred) {

		// Gets the Credentials from the SSL
		ssl = (PKI_SSL *) cred->ssl;

		// Checks for Username in the URL itself
		if (!url->usr && cred->username) url->usr = strdup(cred->username);

		// Checks for the Password in the URL itself
		if (!url->pwd && cred->password) url->pwd = strdup(cred->password);

	}

	// Gets the Stack of PKI_MEM structure from the URL
	if ((mem_sk = URL_get_data_url(url, 60, 0, ssl)) == NULL) {

		// Reports the Error
		PKI_ERROR(PKI_ERR_POINTER_NULL, 
			"No data returned from URL [%s]", url->url_s);

		// Nothing more to do
		return NULL;
	}

	// Allocates a new stack of X509 structures
	if ((ret = PKI_STACK_X509_new()) == NULL ) {

		// Reports the error
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC,
			"Can not allocate PKI_STACK_X509");

		// Free all memory
		PKI_STACK_MEM_free_all(mem_sk);

		// Nothing more to do
		return NULL;
	}

	// Resets the counter
	count = 0;

	// Cycles through the PKI_MEM from the returned 'mem_sk'
	for (i = 0; i < PKI_STACK_MEM_elements(mem_sk); i++ ) {

		PKI_MEM *mem_data = NULL;

		// Gets the i-th PKI_MEM from the stack of elements
		if ((n = PKI_STACK_MEM_get_num( mem_sk, i)) == NULL) {

			// Reports the Error
			PKI_ERROR(PKI_ERR_POINTER_NULL, 
				"Can not retrieve object from PKI_MEM stack [%d of %d]",
				i, PKI_STACK_MEM_elements(mem_sk));

			// Go to the next item
			continue;
		}

		// If no Datatype is specified, let's try to load any of the
		// supported X509 types (X509_types array)
		if ( type == PKI_DATATYPE_ANY ) {

			// Cycle through all the types
			for (j = 0; j < x509_types_len; j++) {

				PKI_DATATYPE curr_type;
					// Tracks the current type

				curr_type = x509_types[j];
					// Gets the current type from the array

				// Retrieves the Stack of PKI_MEM structure from the stack
				if((tmp_x_sk = PKI_X509_STACK_get_mem(mem_data,
													  curr_type, 
													  cred,
													  hsm)) != NULL) {

					// For each of the returned objects (if any) we get
					// the next PKI_X509 generic structure
					while ( (x = PKI_STACK_X509_pop( tmp_x_sk )) != NULL ) {

						// Updates the counter
						count++;

						// Checks if the URL specifies an object number
						if (url->object_num > 0) {

							// Adds only object with the same number
							if (count == url->object_num)  {
								// Pushes the PKI_MEM to the returned stack
							    PKI_STACK_X509_push(ret, x);
							} else {
								// Free the Memory
							    PKI_X509_free(x);
							}

						} else {

							// No object number was specified, let's add
							// every PKI_MEM we get from the stack
							PKI_STACK_X509_push( ret, x );
						}
					}

					// Free the memory associated with the Stack
					PKI_STACK_X509_free_all ( tmp_x_sk );
				}
			}

		} else {

			// Here we have a specific datatype we are looking for so we
			// do not have to cycle through all the supported datatypes
			if ((tmp_x_sk = PKI_X509_STACK_get_mem(mem_data,
												   type, 
												   cred,
												   hsm)) != NULL) {

				// Processes (removes) next element from the inner stack
				while ((x = PKI_STACK_X509_pop(tmp_x_sk)) != NULL ) {

					// Updates the counter
					count++;

					// Checks if an object number was specified in the URL
					if (url->object_num > 0) {

						// If a number was provided, check the counter is
						// reflecting the right object number
						if (count == url->object_num)  {
						    // Push the selected value to the return stack
						    PKI_STACK_X509_push(ret, x);
						} else {
						    // Free the memory for the value since
						    // it is not the one we were looking for
						    PKI_X509_free(x);
						}

					} else {

						// No specific object number was provided in the
						// URL, therefore let's add all objects to the
						// return stack
						PKI_STACK_X509_push( ret, x );
					}
				}

				// Nothing more to do with the stack, let's free it
				PKI_STACK_X509_free_all ( tmp_x_sk );
			}
		}
	}


	// Checks if we have memory to free
	if (mem_sk) {

		// Free all the elements from the Stack of PKI_MEM
		while ((tmp_mem = PKI_STACK_MEM_pop(mem_sk)) != NULL) {
			// Free the memory for the node
			PKI_MEM_free(tmp_mem);
		}

		// Free the stack itself
		PKI_STACK_MEM_free_all(mem_sk);
	}

	// Returns the Stack of PKI_X509 structures
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

		// We just need to pop the cert - not free the mem!
		while ((x = PKI_STACK_X509_pop(sk)) != NULL);

		// Let's free the list itself
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
		// We just need to pop the cert - not free the mem
		while ((x = PKI_STACK_X509_pop( sk )) != NULL);

		// Let's free the list itself
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


