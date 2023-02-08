/* PKI_X509 object management */

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <libpki/pki.h>
#include <sys/utsname.h>

#include "internal/x509_data_st.h"
#include <libpki/openssl/data_st.h>

PKI_X509_REQ * PKI_X509_REQ_new_null ( void ) {
	return (PKI_X509_REQ *) PKI_X509_new ( PKI_DATATYPE_X509_REQ, NULL );
}

void PKI_X509_REQ_free_void( void *x ) {
	if( x ) PKI_X509_free( (PKI_X509 *) x );

	return;
}

/*! \brief Frees the memory associated with a Certifcate Request object */

void PKI_X509_REQ_free( PKI_X509_REQ *x ) {

	if( x ) PKI_X509_free ( x );

	/* Return success -- 1 */
	return;
}

/*! \brief Generates a signed Certificate Request Object */

PKI_X509_REQ *PKI_X509_REQ_new(const PKI_X509_KEYPAIR * k, 
			       			   const char             * subj_s,
                               const PKI_X509_PROFILE * req_cnf,
			       			   const PKI_CONFIG       * oids,
                               const PKI_DIGEST_ALG   * digest, 
			       			   HSM 					  * hsm ) {

	PKI_X509_REQ *req = NULL;
	PKI_X509_REQ_VALUE *val = NULL;
	PKI_X509_KEYPAIR_VALUE *kVal = NULL;

	int rv = PKI_OK;
	PKI_SCHEME_ID scheme = PKI_SCHEME_UNKNOWN;

	PKI_X509_NAME *subj = NULL;

	/* We need at least the private key for the request */
	if( !k || !k->value ) {
		PKI_log_debug("ERROR, no key for PKI_X509_REQ_new()!");
		return (NULL);
	}
	kVal = (EVP_PKEY *) PKI_X509_get_value(k);

	// Let's set the digest for the right signature scheme */
	// Open Quantum Safe Algos do not offer Digests, we are now
	// more permissive with the digest
	if( !digest ) {
		// Gets the default algorithm
		if ((digest = PKI_DIGEST_ALG_get_by_key( k )) == NULL) {
			PKI_DEBUG("No Default Digest is recommended for the PKEY algorithm");
		}
	}

	// Debug Info
	if (digest) {
		PKI_DEBUG("Selected Hashing Algorithm is %s (EVP_md_null() ? = %s)", 
			OBJ_nid2sn(EVP_MD_nid(digest)), digest == PKI_DIGEST_ALG_NULL ? "Yes" : "No");
	} else {
		PKI_DEBUG("NO Hashing Algorithm is selected");
	}

	/* This has to be fixed, to work on every option */
	if( subj_s ) {
		subj = PKI_X509_NAME_new ( subj_s );
	} else if ( req_cnf ) {
		char *tmp_s = NULL;

		if(( tmp_s = PKI_CONFIG_get_value( req_cnf, "/profile/subject/dn")) != NULL ) {
			subj_s = tmp_s;

			// PKI_log_debug("Subject DN found => %s", tmp_s);
			subj = PKI_X509_NAME_new ( tmp_s );
		} else {
			// PKI_log_debug("Subject DN .. NOT found!");
			subj = PKI_X509_NAME_new( "" );
		};
	} else {
		struct utsname myself;
		char tmp_name[1024];

		if (uname(&myself) < 0) {
			subj = PKI_X509_NAME_new( "" );
		} else {
			sprintf( tmp_name, "CN=%s", myself.nodename );
			subj = PKI_X509_NAME_new( tmp_name );
		}
	};

	if( !subj ) {
		PKI_ERROR(PKI_ERR_X509_CERT_CREATE_SUBJECT, subj_s );
		goto err;
	}

	if (( req = PKI_X509_REQ_new_null()) == NULL ) {
		PKI_ERROR(PKI_ERR_OBJECT_CREATE, NULL );
		goto err;
	}

	/* Generate the request */
	if((val = req->cb->create()) == NULL ) {
		PKI_ERROR(PKI_ERR_OBJECT_CREATE, NULL );
		goto err;
		return ( NULL );
	}

	req->value = val;

	/* Now we need the PKI_REQ */
	if( req_cnf != NULL ) {

		PKI_TOKEN * tk = NULL;
		PKI_KEYPARAMS *kParams = NULL;

		char *tmp_s = NULL;

		if(( tmp_s = PKI_X509_PROFILE_get_value( req_cnf, 
				"/profile/keyParams/algorithm")) != NULL ) {
			PKI_X509_ALGOR_VALUE *myAlg = NULL;
			const PKI_DIGEST_ALG *dgst;

			if((myAlg = PKI_X509_ALGOR_VALUE_get_by_name( tmp_s )) != NULL ) {
				scheme = PKI_X509_ALGOR_VALUE_get_scheme ( myAlg );
				if((dgst = PKI_X509_ALGOR_VALUE_get_digest( myAlg )) != NULL ) {
					digest = (PKI_DIGEST_ALG *)dgst;
				};
			};
			PKI_Free ( tmp_s );
		};

		if (( tk = PKI_TOKEN_new_null()) == NULL ) {
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "PKI_TOKEN");
			PKI_X509_REQ_free ( req );
			return NULL;
		}

		PKI_TOKEN_set_keypair(tk, (PKI_X509_KEYPAIR *) k);
		PKI_TOKEN_set_req(tk, (PKI_X509_REQ *)req);

		/* Add Request Extensions */
		rv = PKI_X509_EXTENSIONS_req_add_profile( req_cnf, 
				oids, req, tk );

		tk->keypair = NULL;
		tk->req = NULL;
		PKI_TOKEN_free ( tk );

		if ( rv == PKI_ERR ) {
			PKI_log_err("Can not add extensions to request");
			// PKI_X509_REQ_free (req);
			// return NULL;
		}

		if( scheme == PKI_SCHEME_UNKNOWN ) {
			scheme = PKI_X509_KEYPAIR_get_scheme ( k );
		};

		kParams = PKI_KEYPARAMS_new(scheme, req_cnf);
		if( kParams ) {
			/* Sets the point compression */
			switch ( kParams->scheme ) {
#ifdef ENABLE_ECDSA
				case PKI_SCHEME_ECDSA:
    				if ( kParams->ec.form != PKI_EC_KEY_FORM_UNKNOWN ) {
# if OPENSSL_VERSION_NUMBER > 0x1010000fL
    					EC_KEY_set_conv_form(EVP_PKEY_get0_EC_KEY(kVal),
							     (point_conversion_form_t)kParams->ec.form);
# else
    					EC_KEY_set_conv_form(kVal->pkey.ec, (point_conversion_form_t)kParams->ec.form);
# endif
    				};
					break;
#endif

#ifdef ENABLE_OQS
				case PKI_SCHEME_FALCON:
				case PKI_SCHEME_DILITHIUM:
				case PKI_SCHEME_DILITHIUMX3:

#ifdef ENABLE_COMPOSITE
				case PKI_SCHEME_COMPOSITE:
				case PKI_SCHEME_COMPOSITE_DILITHIUM3_RSA:
				case PKI_SCHEME_COMPOSITE_DILITHIUM3_ED25519:
				case PKI_SCHEME_COMPOSITE_FALCON512_RSA:

# ifdef ENABLE_ECDSA
				case PKI_SCHEME_COMPOSITE_FALCON512_P256:
				case PKI_SCHEME_COMPOSITE_DILITHIUM3_P256:
				case PKI_SCHEME_COMPOSITE_DILITHIUM5_BRAINPOOL384:
				case PKI_SCHEME_COMPOSITE_DILITHIUM3_BRAINPOOL256:
				case PKI_SCHEME_COMPOSITE_DILITHIUM5_P384:
				case PKI_SCHEME_COMPOSITE_DILITHIUM5_ED448:
				case PKI_SCHEME_COMPOSITE_DILITHIUM5_FALCON1024_P521:
# endif
				case PKI_SCHEME_COMPOSITE_DILITHIUM5_FALCON1024_RSA:
#endif

#endif

#ifdef ENABLE_COMBINED
#endif
				case PKI_SCHEME_RSA:
				case PKI_SCHEME_DSA:
					break;

				default:
					// Nothing to do
					PKI_ERROR(PKI_ERR_GENERAL, "Signing Scheme Uknown %d!", kParams->scheme);
					break;
			};
		};
	};

	/* Set the version number */
	if (!X509_REQ_set_version( (X509_REQ *) val, 2L)) {
		PKI_ERROR(PKI_ERR_X509_REQ_CREATE_VERSION, NULL);
		goto err;
	}

	/* Set the pubkey */
	if (!X509_REQ_set_pubkey( (X509_REQ *) val, kVal )) {
		PKI_ERROR(PKI_ERR_X509_REQ_CREATE_PUBKEY, NULL);
		goto err;
	};

	// Sets the Subject
	if (!X509_REQ_set_subject_name((X509_REQ *)val, (X509_NAME *)subj)) {
		if(subj) X509_NAME_free((X509_NAME *) subj);
		PKI_ERROR(PKI_ERR_X509_REQ_CREATE_SUBJECT, subj_s);
		goto err;
	};

	// Signs the Request
	rv = PKI_X509_sign(req, digest, k);
	if (rv != PKI_OK ) {
		/* Error Signing the request */
		PKI_log_debug("REQ::ERROR %d signing the Request [%s]", rv,
			ERR_error_string( ERR_get_error(), NULL ));
		goto err;
	}

	/* Return the requested PKI_X509_REQ structure */
	return req;

err:
	if (req) PKI_X509_REQ_free(req);

	return (NULL);
}

/*! \brief Adds an extension to a Certificate Request */

int PKI_X509_REQ_add_extension(PKI_X509_REQ * x, PKI_X509_EXTENSION * ext) {

	STACK_OF(X509_EXTENSION) *sk = NULL;
		// Stack of Crypto-Layer Extensions

	PKI_X509_REQ_VALUE *val = NULL;
		// Crypto Layer REQ pointer
		
	int *nid_list = NULL;
	int i = -1;

	// Input Checks
	if (!x || !x->value || !ext || !ext->value.ptr ) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	// Gets the Internal Value
	val = x->value;

	// Gets the crypto-layer stack of extensions
	if ((sk = X509_REQ_get_extensions(val)) == NULL) {
		// If none is available, let's build one
		if ((sk = sk_X509_EXTENSION_new_null()) == NULL ) {
			return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		}
	}

	// Pushes the crypto-layer extension to the stack
	if (!sk_X509_EXTENSION_push(sk, ext->value.x509_ext)) {
		// Error Condition
		sk_X509_EXTENSION_free ( sk );
		return PKI_ERROR(PKI_ERR_GENERAL, "Cannot Add Extension to the request's stack");
	}

	// Gets the list of NIDs
	nid_list = X509_REQ_get_extension_nids();
	for ( i = 0; ; i++ ) {

		PKI_ID nid = -1;
		
		// Retrieves the i-th NID
		if((nid = nid_list[i]) == NID_undef ) {
			break;
		};

		// Removes the attribute
		PKI_X509_REQ_delete_attribute(x, nid_list[i]);
	}

	// Let's now add all the extensions
	if( !X509_REQ_add_extensions(val, sk))  {
		// Error Condition
		sk_X509_EXTENSION_free(sk);
		return PKI_ERROR(PKI_ERR_GENERAL, "Cannot add the set of extensions to the request");
	}

	// Free the Stack of Extensions
	sk_X509_EXTENSION_free ( sk );

	// All Done
	return PKI_OK;

	/*
	if((sk = sk_X509_EXTENSION_new_null()) == NULL ) 
						return (PKI_ERR);

	sk_X509_EXTENSION_push( sk, ext->value );

	if( !X509_REQ_add_extensions((X509_REQ *)x->value, sk )) 
						return (PKI_ERR);

	if( sk ) sk_X509_EXTENSION_pop_free ( sk, X509_EXTENSION_free );

	return (PKI_OK);
	*/
}


/*! \brief Adds a stack of extensions to a Certificate Request */

int PKI_X509_REQ_add_extension_stack(PKI_X509_REQ 			  * x, 
									 PKI_X509_EXTENSION_STACK * sk_ext) {

	STACK_OF(X509_EXTENSION) *sk = NULL;
		// Crypto layer stack of extensions

	int i = 0;

	// Input Checks
	if (!x || !x->value || !sk_ext) {
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
	}

	// Generates a new Crypto-Layer Stack of extensions
	if((sk = sk_X509_EXTENSION_new_null()) == NULL ) {
		return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
	}

	// Cycles through the LibPKI's stack of extensions and
	// adds them to the crypto-layer's stack
	for( i = 0; i < PKI_STACK_X509_EXTENSION_elements(sk_ext); i++ ) {

		PKI_X509_EXTENSION *tmp_e = NULL;
			// LibPKI extensions' pointer
		
		// Retrieves the i-th LibPKI extension
		tmp_e = PKI_STACK_X509_EXTENSION_get_num(sk_ext, i);

		// Checks for errors
		if (!tmp_e) {
			// Free the crypto-layer stack
			while (sk && sk_X509_EXTENSION_num(sk) > 0) {
				sk_X509_EXTENSION_pop_free(sk, X509_EXTENSION_free);
			} sk_X509_EXTENSION_free(sk);
			// Error Condition
			return PKI_ERROR(PKI_ERR_GENERAL, "Cannot retrieve the i-th extension from the stack");
		}

		// Pushes the extension to the crypto layer's stack
		sk_X509_EXTENSION_push(sk, tmp_e->value.x509_ext);
	}

	// Let's now add all the extensions at once
	if (!X509_REQ_add_extensions((X509_REQ *)x->value, sk)) {
		// Free the crypto-layer stack
		while (sk && sk_X509_EXTENSION_num(sk) > 0) {
			sk_X509_EXTENSION_pop_free(sk, X509_EXTENSION_free);
		} sk_X509_EXTENSION_free(sk);
		// Error Condition
		return PKI_ERROR(PKI_ERR_GENERAL, "Cannot Add the Stack of Crypto-Layer Extensions to the request");
	}

	// Free Allocated Memory
	while (sk && sk_X509_EXTENSION_num(sk) > 0) {
		sk_X509_EXTENSION_pop_free(sk, X509_EXTENSION_free);
	} sk_X509_EXTENSION_free(sk);

	// All Done
	return PKI_OK;
}

/*! \brief Returns the size of the public key in the Certificate Request
 */

int PKI_X509_REQ_get_keysize(const PKI_X509_REQ *x) {

	int keysize = 0;
	PKI_X509_KEYPAIR_VALUE *pkey = NULL;

	if( !x || !x->value ) return (0);

	if(( pkey = (PKI_X509_KEYPAIR_VALUE *) PKI_X509_REQ_get_data(x, 
				PKI_X509_DATA_KEYPAIR_VALUE)) == NULL ) {
		return (0);
	}

	keysize = EVP_PKEY_size ( (EVP_PKEY *) pkey );

	return keysize;
}

/*! \brief Returns an attribute of the Certificate Request */

const void * PKI_X509_REQ_get_data(const PKI_X509_REQ * req, 
				   PKI_X509_DATA        type ) {
	
	void *ret = NULL;
	LIBPKI_X509_REQ *tmp_x = NULL;

	if( !req || !req->value ) return (NULL);

	tmp_x = req->value;

	switch( type ) {
		case PKI_X509_DATA_SUBJECT:
			ret = (void *) X509_REQ_get_subject_name((X509_REQ *)tmp_x);
			break;
		case PKI_X509_DATA_PUBKEY:
		case PKI_X509_DATA_KEYPAIR_VALUE:
			ret = (void *)X509_REQ_get_pubkey((X509_REQ *)tmp_x);
			break;
		case PKI_X509_DATA_SIGNATURE:
			ret = (void *) tmp_x->signature;
			break;
		case PKI_X509_DATA_ALGORITHM:
		case PKI_X509_DATA_SIGNATURE_ALG1:
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
			ret = &(tmp_x->sig_alg);
#else
			ret = tmp_x->sig_alg;
#endif
			break;
		case PKI_X509_DATA_SIGNATURE_ALG2:
			break;
/*
		// This shall be replaced with a dedicated
		// function because this violates the memory
		// contract (const for the returned item)
		// PKI_X509_get_tbs_asn1();
		case PKI_X509_DATA_TBS_MEM_ASN1:
			if((mem = PKI_MEM_new_null()) == NULL ) 
				break;
			mem->size = (size_t) ASN1_item_i2d ( (void *) tmp_x->req_info, 
				&(mem->data), &X509_REQ_INFO_it );
			ret = mem;
			break;
*/
		default:
			return( NULL );
	}

	return (ret);
}

/*! \brief Returns a char * representation of the data present in the
 *         request
 */

const char * PKI_X509_REQ_get_parsed(const PKI_X509_REQ *req,
		                     PKI_X509_DATA type ) {

	const char *ret = NULL;

	const PKI_X509_KEYPAIR_VALUE *pkey = NULL;
	PKI_X509_KEYPAIR *k = NULL;

	if( !req || !req->value ) return ( NULL );

	switch ( type ) {
		case PKI_X509_DATA_SERIAL:
			ret = PKI_INTEGER_get_parsed((PKI_INTEGER *)
				PKI_X509_REQ_get_data ( req, type ));
			break;
		case PKI_X509_DATA_SUBJECT:
		case PKI_X509_DATA_ISSUER:
			ret = PKI_X509_NAME_get_parsed((PKI_X509_NAME*)
				PKI_X509_REQ_get_data ( req, type));
			break;
		case PKI_X509_DATA_NOTBEFORE:
		case PKI_X509_DATA_NOTAFTER:
			ret = PKI_TIME_get_parsed((PKI_TIME *)
				PKI_X509_REQ_get_data ( req, type ));
			break;
		case PKI_X509_DATA_ALGORITHM:
			ret = PKI_X509_ALGOR_VALUE_get_parsed((PKI_X509_ALGOR_VALUE *)
				PKI_X509_REQ_get_data(req, type));
			break;
		case PKI_X509_DATA_PUBKEY:
		case PKI_X509_DATA_KEYPAIR_VALUE:
			if((pkey = PKI_X509_REQ_get_data(req, type)) != NULL) {
				k = PKI_X509_new_dup_value ( 
					PKI_DATATYPE_X509_KEYPAIR, pkey, NULL );
				ret = PKI_X509_KEYPAIR_get_parsed( k );
				PKI_X509_KEYPAIR_free ( k );
			}
			break;
		case PKI_X509_DATA_SIGNATURE:
			ret = PKI_X509_SIGNATURE_get_parsed(
				(PKI_X509_SIGNATURE *) 
					PKI_X509_REQ_get_data ( req, type ));
			break;
		default:
			return ( NULL );
	}

	return ( ret );
}

/*! \brief Prints the requested data from the request to the file descriptor
 * 	   passed as an argument
 */

int PKI_X509_REQ_print_parsed(const PKI_X509_REQ *req, 
			      PKI_X509_DATA type,
			      int fd ) {

	const char *str = NULL;
	int ret = PKI_OK;

	if( !req ) return ( PKI_ERR );

	if((str = PKI_X509_REQ_get_parsed ( req, type )) == NULL ) {
		return ( PKI_ERR );
	} else {
		if( fd == 0 ) fd = 2;
		if( write( fd, str, strlen(str)) == -1 ) {
			ret = PKI_ERR;
		}
		PKI_Free( (char *) str );
	}

	return ( ret );
}

/*------------------------------- ATTRIBUTES --------------------------------- */

/*! Adds an Attribute to a PKI_X509_REQ */

int PKI_X509_REQ_add_attribute ( PKI_X509_REQ *req, PKI_X509_ATTRIBUTE *attr ) {

	PKI_X509_REQ_VALUE *val = NULL;

	if ( !req || !req->value || !attr ) return PKI_ERR;

	val = req->value;
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
	if (val->req_info != NULL) {
		return PKI_STACK_X509_ATTRIBUTE_add(val->req_info->attributes, attr);
	} else {
		return PKI_ERR;
	}
#else
	return PKI_STACK_X509_ATTRIBUTE_add(val->req_info.attributes, attr);
#endif

}

/*! \brief Deletes an attribute by using its PKI_ID */

int PKI_X509_REQ_delete_attribute ( PKI_X509_REQ *req, PKI_ID id ) {

	int ret = PKI_OK;
	PKI_X509_REQ_VALUE *val = NULL;

	if ( !req || !req->value ) return PKI_ERR;

	val = req->value;

#if OPENSSL_VERSION_NUMBER > 0x1010000fL
	if (!val->req_info.attributes) {
		ret = PKI_ERROR(PKI_ERR_PARAM_NULL, "No Attributes present");
	} else {
		ret = PKI_STACK_X509_ATTRIBUTE_delete(val->req_info.attributes, id );
	}
#else
	if (!val->req_info || !val->req_info->attributes) {
		ret = PKI_ERROR(PKI_ERR_PARAM_NULL, "No Attributes present");
	} else {
		ret = PKI_STACK_X509_ATTRIBUTE_delete(val->req_info->attributes, id);
	}
#endif

	return ret;
}

/*! \brief Deletes an attribute by using its number (position) */

int PKI_X509_REQ_delete_attribute_by_num ( PKI_X509_REQ *req, int pos ) {

	int ret = PKI_ERR;
	PKI_X509_REQ_VALUE *val = NULL;

	if ( !req || !req->value ) return PKI_ERR;

	val = req->value;

#if OPENSSL_VERSION_NUMBER > 0x1010000fL
	if (val->req_info.attributes != NULL) {
		ret = PKI_STACK_X509_ATTRIBUTE_delete_by_num(
				val->req_info.attributes, pos);
	}
#else
	if (val->req_info && val->req_info->attributes) {
		ret = PKI_STACK_X509_ATTRIBUTE_delete_by_num(
				val->req_info->attributes, pos);
	}
#endif

	return ret;
}

/*! \brief Deletes an attribute by using its name */

int PKI_X509_REQ_delete_attribute_by_name ( PKI_X509_REQ *req, char *name ) {

	int ret = PKI_ERR;
	PKI_X509_REQ_VALUE *val = NULL;

	if (!req || !req->value || !name) return PKI_ERR;
	val = req->value;

#if OPENSSL_VERSION_NUMBER > 0x1010000fL
	if (val->req_info.attributes != NULL) {
		ret = PKI_STACK_X509_ATTRIBUTE_delete_by_name(
				val->req_info.attributes, name);
	}
#else
	if (val->req_info && val->req_info->attributes) {
		ret = PKI_STACK_X509_ATTRIBUTE_delete_by_name(
				val->req_info->attributes, name);
	}
#endif

	return ret;
}

/*! \brief Clears the stack of attributes from a PKI_X509_REQ */

int PKI_X509_REQ_clear_attributes ( PKI_X509_REQ *req ) {

	int ret = PKI_ERR;
	PKI_X509_REQ_VALUE *val = NULL;
	PKI_X509_ATTRIBUTE *attr = NULL;

	if (!req || !req->value) return PKI_ERR;

	val = req->value;


#if OPENSSL_VERSION_NUMBER > 0x1010000fL
	if (val->req_info.attributes != NULL) {
		while ((attr = PKI_STACK_X509_ATTRIBUTE_pop (
				val->req_info.attributes )) != NULL) {
			PKI_X509_ATTRIBUTE_free(attr);
		}
		ret = PKI_OK;
	}
#else
	if (val->req_info && val->req_info->attributes) {
		while ((attr = PKI_STACK_X509_ATTRIBUTE_pop (
				val->req_info->attributes )) != NULL) {
			PKI_X509_ATTRIBUTE_free ( attr );
		}
		ret = PKI_OK;
	}
#endif

	return ret;
}

/*! \brief Gets the number of attributes present in a PKI_X509_REQ */

int PKI_X509_REQ_get_attributes_num(const PKI_X509_REQ *req) {

	int ret = 0;
	PKI_X509_REQ_VALUE *val = NULL;

	// Input Checks
	if ( !req || !req->value ) return PKI_ERR;

	// Retrieve the internal value
	val = req->value;

	// If Attributes are present, get the number
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
	if (val->req_info.attributes) {
		ret = PKI_STACK_X509_ATTRIBUTE_elements(val->req_info.attributes);
	}
#else
	// If Attribtues are present, get the number
	if (val->req_info && val->req_info->attributes) {
		ret = PKI_STACK_X509_ATTRIBUTE_elements(val->req_info->attributes);
	}
#endif

	// Return the retrieved number
	return ret;
}

/*! \brief Returns an attribute from a PKI_X509_REQ by its number (position) */

const PKI_X509_ATTRIBUTE *PKI_X509_REQ_get_attribute_by_num(const PKI_X509_REQ * req, 
							    int                  num) {

	const PKI_X509_ATTRIBUTE * ret = NULL;
		// Return Value

	PKI_X509_REQ_VALUE *val = NULL;
		// Pointer to the request value

	// Input Checks
	if ( !req || !req->value ) return NULL;

	// Gets the internal pointer
	val = req->value;

#if OPENSSL_VERSION_NUMBER > 0x1010000fL
	// Gets the attribute 'num'
	ret = PKI_STACK_X509_ATTRIBUTE_get_by_num(val->req_info.attributes, num);
#else
	// Checks for the info structure to be there
	if (val->req_info != NULL) {
		// Gets the attribute by 'num'
		ret = PKI_STACK_X509_ATTRIBUTE_get_by_num(val->req_info->attributes,num);
	}
#endif

	// Returns the Attribute or NULL
	return ret;

}

/*! \brief Returns an attribute from a PKI_X509_REQ by its type (PKI_ID) */

const PKI_X509_ATTRIBUTE *PKI_X509_REQ_get_attribute(const PKI_X509_REQ *req,
						     PKI_ID type ) {

	const PKI_X509_ATTRIBUTE * ret = NULL;
		// Return Value

	PKI_X509_REQ_VALUE *val = NULL;
		// Pointer to the Internal Value

	// Input check
	if ( !req || !req->value ) return NULL;

	// Gets the internal value
	val = req->value;

#if OPENSSL_VERSION_NUMBER > 0x1010000fL
	// If we have a valid attributes structure
	if (val->req_info.attributes != NULL) {
		// Gets the Attributes
		ret = PKI_STACK_X509_ATTRIBUTE_get( val->req_info.attributes, type);
	}
#else
	// If we have a valid req_info structure
	if (val->req_info != NULL && val->req_info->attributes != NULL) {
		// Gets the Attribute
		ret = PKI_STACK_X509_ATTRIBUTE_get(val->req_info->attributes, type);
	}
#endif

	return ret;
}

/*! \brief Returns an attribute from a PKI_X509_REQ by its name */

const PKI_X509_ATTRIBUTE *PKI_X509_REQ_get_attribute_by_name(
					const PKI_X509_REQ *req, 
					const char * name ) {

	const PKI_X509_ATTRIBUTE * ret = NULL;
		// Return Pointer for the attribute

	PKI_X509_REQ_VALUE *val = NULL;
		// Pointer to the internal value

	// Input Checks
	if (!req || !req->value || !name) return NULL;

	// Gets the Internal Value
	val = req->value;

#if OPENSSL_VERSION_NUMBER > 0x1010000fL
	// If we have a valid attributes structure...
	if (val->req_info.attributes) {
		// ... get the attribute pointer by name
		ret = PKI_STACK_X509_ATTRIBUTE_get_by_name(
			val->req_info.attributes, name);
	}
#else
	// If we have a valid req_info and attributes structure...
	if (val->req_info && val->req_info->attributes) {
		// ... get the pointer to the attribute
		ret = PKI_STACK_X509_ATTRIBUTE_get_by_name(
			val->req_info->attributes, name);
	}
#endif
	// Returns the attribute pointer or NULL
	return ret;
}

/* ---------------------------- X509 REQ Extensions --------------------------- */

int PKI_X509_REQ_get_extension_by_num(const PKI_X509_REQ *req,
				      int num ) {

	PKI_log_debug("%s:%d::Code still missing!",__FILE__, __LINE__ );
	return ( PKI_ERR );
}

int PKI_X509_REQ_get_extension_by_oid(const PKI_X509_REQ *req, 
				      const PKI_OID *oid ) {

	PKI_log_debug("%s:%d::Code still missing!",__FILE__, __LINE__ );
	return ( PKI_ERR );
}

int PKI_X509_REQ_get_extension_by_name(const PKI_X509_REQ *req,
				       const char * name ) {
	PKI_log_debug("%s:%d::Code still missing!",__FILE__, __LINE__ );
	return ( PKI_ERR );
}

