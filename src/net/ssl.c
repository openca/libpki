/* OpenCA libpki package
* (c) 2000-2007 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#include <libpki/pki.h>

#define BUFF_MAX_SIZE	2048

/* Static Function - used only internally */
static int __ssl_find_trusted(X509_STORE_CTX      *ctx, 
	                            PKI_X509_CERT_VALUE *x ) {
	int i = 0;
	int idx = 0;
	int trusted_certs_num = 0;

	int ctx_err = X509_V_OK;

	int ret = PKI_ERR;

	SSL *ssl = NULL;
	PKI_SSL *pki_ssl = NULL;

	PKI_X509_CERT *curr_cert = NULL;

	// Retrieves the store CTX context
	if((ssl = X509_STORE_CTX_get_ex_data(ctx, 
			SSL_get_ex_data_X509_STORE_CTX_idx())) == 0 ) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Can not retrieve trust store context");
		return PKI_ERR;
	}

	// Retrieves the SSL context extra data
	if ((pki_ssl = SSL_get_ex_data(ssl, idx)) == 0 ) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Can not retrieve SSL/TLS context");
		return PKI_ERR;
	}

	// Process current certificate
	curr_cert = PKI_X509_new_dup_value(PKI_DATATYPE_X509_CERT, x, 0);
	if (curr_cert == 0) return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, 0);

	// Gets the number of trusted certificates
	trusted_certs_num = PKI_STACK_X509_CERT_elements(pki_ssl->trusted_certs);

	// Check if a certificate is among the trusted ones
	for (i = 0; i < trusted_certs_num; i++){

		PKI_X509_CERT *issuer = NULL;
		PKI_X509_CERT_VALUE *issuer_val = NULL;

		issuer = PKI_STACK_X509_CERT_get_num(pki_ssl->trusted_certs, i);
		issuer_val = PKI_X509_get_value(issuer);
		
		// Checks if the peer certificate is the i-th trusted ones
		if (X509_cmp(issuer_val, x) == 0) {
			/* The certificate is present among the trusted ones */
			PKI_log_debug("Same Certificate Found in Chain!");
			ret = PKI_OK;
			break;
		}

		// Checks if the peer certificate was issued by the i-th trusted one
		if((ctx_err = X509_check_issued(issuer_val, x)) == X509_V_OK ) {
			/* The cert has been issued by a trusted one */
			PKI_log_debug("__ssl_find_trusted()-> Found Issuer");
			ret = PKI_OK;
			break;
		}
	}

	if ( ret == PKI_OK ) {
		ctx->error = X509_V_OK;
	}

	PKI_log_debug("__ssl_find_trusted()-> Return code is %d", ret );
	PKI_X509_free ( curr_cert );

	return ret;
}

static int __ssl_verify_cb ( int code, X509_STORE_CTX *ctx) {

	PKI_X509_CERT_VALUE *err_cert = NULL;
	PKI_X509_CERT *x = NULL;
	SSL *ssl = NULL;
	PKI_SSL *pki_ssl = NULL;
	PKI_STACK *sk = NULL;

	int err = 0;
	int depth = 0;
	int idx = 0;
	int ret = 0;

	err_cert = X509_STORE_CTX_get_current_cert( ctx );
	err      = X509_STORE_CTX_get_error( ctx );
	depth    = X509_STORE_CTX_get_error_depth ( ctx );

	// Gets the extra data from the SSL context
	ssl = X509_STORE_CTX_get_ex_data(ctx, 
			      SSL_get_ex_data_X509_STORE_CTX_idx());
	if (ssl == 0) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, 0);
		return 0;
	}

	// Gets the PKI extra data
	pki_ssl = SSL_get_ex_data(ssl, idx);
	if (pki_ssl == 0) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, 0);
		return 0;
	}

	if(( x = PKI_X509_new_dup_value ( PKI_DATATYPE_X509_CERT, 
						err_cert, NULL )) == NULL ) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, 0);
		return 0;
	}

	if ( 0 ) {
	if ( PKI_X509_CERT_is_selfsigned ( x ) == PKI_ERR ) {
		if ( (PKI_SSL_check_verify ( pki_ssl, 
					PKI_SSL_VERIFY_CRL) == PKI_OK ) ||
		 		(PKI_SSL_check_verify( pki_ssl, 
					PKI_SSL_VERIFY_CRL_REQUIRE ) == PKI_OK)) {
			
			// Check for PRQP support
			if ( PKI_SSL_check_verify ( pki_ssl,
				PKI_SSL_VERIFY_ENABLE_PRQP ) == PKI_OK ) {
				// PKI_X509_CERT_VALUE *issVal = NULL;
				// PKI_X509_CERT *caCert = NULL;

				sk = PKI_get_ca_service_sk( x, 
					"crlDistributionPoints", NULL);
			}

			if ( sk == NULL ) {
				if ( (sk = PKI_X509_CERT_get_cdp ( x )) == NULL ) {
					PKI_log_debug ("NO CDP in cert %d", depth);
				}
			}

			if ( (!sk) && ( PKI_SSL_check_verify ( pki_ssl, 
					PKI_SSL_VERIFY_CRL_REQUIRE ) == PKI_OK) ) {
				PKI_log_debug( "Required CRL check failed");
				ctx->error = X509_V_ERR_UNABLE_TO_GET_CRL;
			} else {
				int i = 0;

				for ( i=0; i < PKI_STACK_elements ( sk ); i++ ) {
					PKI_log_debug( "[%d] CDP num [%d] => "
						"%s", depth, 
						PKI_STACK_get_num( sk, i ));
				}
			}
		}
	}
	}

	if (code == 1) ctx->error = X509_V_OK;

	/*
	if( 1 ) {
		char *tmp = NULL;

		PKI_log_debug("[%d] SSL Verify (%d::%s)",
		 	depth, X509_STORE_CTX_get_error( ctx ),
			X509_verify_cert_error_string(err));

		if((tmp = PKI_X509_CERT_get_parsed ( x, 
					PKI_X509_DATA_SUBJECT)) != NULL ){
			PKI_log_debug("    Subject = %s", tmp );
			PKI_Free ( tmp );
		}

		if ((tmp = PKI_X509_CERT_get_parsed ( x, 
					PKI_X509_DATA_ISSUER)) != NULL ) {
			PKI_log_debug("    Issuer  = %s", tmp);
			PKI_Free ( tmp );
		}

	}
	*/

	switch ( err ) {
		/* Cert Validity */
		case X509_V_ERR_CERT_NOT_YET_VALID:
		case X509_V_ERR_CERT_HAS_EXPIRED:
		case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
			PKI_log_debug("Certificate Validity Error (%d::%s)",
				depth, X509_verify_cert_error_string(err));
			break;

		/* Revocation Related */
		case X509_V_ERR_CERT_REVOKED:
			PKI_log_debug("[%d] Certificate is Revoked", depth);
			break;

		/* Certificate Availability */
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
			if ( pki_ssl->auth != 0 ) {
				pki_ssl->verify_ok = PKI_ERR;
			};
			ret = 1;
			break;

		/* CRL Related */
		case X509_V_ERR_UNABLE_TO_GET_CRL:
			PKI_log_debug("[%d] Unable to get CRL", depth);
			if (PKI_SSL_check_verify ( pki_ssl, 
							PKI_SSL_VERIFY_CRL ) == PKI_ERR ) {
				ret = 1;
			}
			break;

		case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
		case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
		case X509_V_ERR_CRL_NOT_YET_VALID:
		case X509_V_ERR_CRL_HAS_EXPIRED:
			PKI_log_debug("[%d] CRL Validity Error", depth);
			if (PKI_SSL_check_verify ( pki_ssl, 
							PKI_SSL_VERIFY_CRL ) == PKI_ERR ) {
				ret = 1;
			}
			break;

#ifdef X509_V_ERR_CRL_PATH_VALIDATION_ERROR
		case X509_V_ERR_CRL_PATH_VALIDATION_ERROR:
			PKI_log_debug("[%d] CRL Path Validation Error", depth);
			break;
#endif
		case X509_V_ERR_KEYUSAGE_NO_CRL_SIGN:
		case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
		case X509_V_ERR_CRL_SIGNATURE_FAILURE:
			PKI_log_debug("[%d] CRL Signature Error", depth);
			break;

#ifdef X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION
		case X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION:
			PKI_log_debug("[%d] CRL unhandled critical ext", depth);
			break;
#endif
		case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
			PKI_log_debug("[%d] Unable to get CRL Issuer", depth);
			break;
			
		/* Certificate Format */
		case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
		case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
		case X509_V_ERR_CERT_SIGNATURE_FAILURE:
		case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
			PKI_log_debug("Certificate Signature Error (%d::%s)",
				depth, X509_verify_cert_error_string(err));
			break;

		/* Library Specific */
		case X509_V_ERR_OUT_OF_MEM:
			PKI_log_debug("Memory Error");
			break;
		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
			if ( pki_ssl->flags & 
					PKI_SSL_VERIFY_NO_SELFSIGNED) {
				PKI_log_debug("Self Signed Certificate in "
					"Chain [level %d]", depth );
			} else {
				ret = 1;
			}
			break;

		/* Certificate Chain */
		case X509_V_ERR_INVALID_CA:
			PKI_log_debug("Invalid CA [%d::%s]",
				depth, X509_verify_cert_error_string(err));
			break;
		case X509_V_ERR_CERT_CHAIN_TOO_LONG:
		case X509_V_ERR_PATH_LENGTH_EXCEEDED:
			PKI_log_debug("Certificate Path Len Error [%d::%s]",
				depth, X509_verify_cert_error_string(err));
			break;

		/* Extensions Related */
		case X509_V_ERR_INVALID_PURPOSE:
			PKI_log_debug("Invalid Purpose Error [%d::%s]",
				depth, X509_verify_cert_error_string(err));
			break;
		case X509_V_ERR_CERT_UNTRUSTED:
			PKI_log_debug("Certificate Not Trusted [%d::%s]",
				depth, X509_verify_cert_error_string(err));
			if (pki_ssl->auth != 0) {
				PKI_log_debug("Cert not trusted, Ignored");
				pki_ssl->verify_ok = PKI_ERR;
				ret = 1;
			};
			break;

		case X509_V_ERR_CERT_REJECTED:
			PKI_log_debug("Certificate rejected [%d::%s]",
				depth, X509_verify_cert_error_string(err));
			break;
		case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
			PKI_log_debug("Certificate Issuer Mismatch [%d::%s]",
				depth, X509_verify_cert_error_string(err));
			break;
		case X509_V_ERR_AKID_SKID_MISMATCH:
		case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
			PKI_log_debug("Certificate AKID/SKID Error [%d::%s]",
				depth, X509_verify_cert_error_string(err));
			break;
		case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
#ifdef X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION
		case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
#endif
		case X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE:
#ifdef X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE
		case X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE:
#endif
		case X509_V_ERR_INVALID_EXTENSION:
			PKI_log_debug("Certificate Extension Error [%d::%s]",
				depth, X509_verify_cert_error_string(err));
			break;

		case X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED:
		case X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED:
			PKI_log_debug("Proxy Certificate Error [%d::%s]",
				depth, X509_verify_cert_error_string(err));
			break;

		case X509_V_ERR_INVALID_POLICY_EXTENSION:
		case X509_V_ERR_NO_EXPLICIT_POLICY:
			PKI_log_debug("Certificate Policy Error [%d::%s]",
				depth, X509_verify_cert_error_string(err));
			break;

#ifdef X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE
		case X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE:
#ifdef X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX
		case X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX:
#endif
			PKI_log_debug("Certificate Constraint Error [%d::%s]",
				depth, X509_verify_cert_error_string(err));
			break;
#endif

#ifdef X509_V_ERR_UNSUPPORTED_NAME_SYNTAX
		case X509_V_ERR_UNSUPPORTED_NAME_SYNTAX:
			PKI_log_debug("Certificate Name Error [%d::%s]",
				depth, X509_verify_cert_error_string(err));
			break;
#endif
		/* These are supported only in 0.9.9+ - when no
		   specific code is developed, let's just default */
		/*
		case X509_V_ERR_DIFFERENT_CRL_SCOPE:
		case X509_V_ERR_UNNESTED_RESOURCE:
		case X509_V_ERR_PERMITTED_VIOLATION:
		case X509_V_ERR_EXCLUDED_VIOLATION:
		case X509_V_ERR_SUBTREE_MINMAX:
		case X509_V_ERR_INVALID_NON_CA:
		*/
		case X509_V_OK:
			/* No error */
			ret = 1;
			break;

		default:
			PKI_log_debug("General Error [%d:%s]", err,
				X509_verify_cert_error_string(err));
	}

	// Checks the flags we set for the SSL/TLS connection
	if (pki_ssl->verify_flags == PKI_SSL_VERIFY_NONE) {
		pki_ssl->auth = 0;
	}

	/* Check if we don't really care about the authentication */
	if (pki_ssl->auth == 0 || ret == 1) ret = 1;

	/* We add the Cert to the peer_chain only if we have an "ok" return
	 * code to avoid duplicates */
	if (pki_ssl->peer_chain == 0) {

		// Generates an empty stack of certs
		pki_ssl->peer_chain = PKI_STACK_X509_CERT_new();

		// If we can not allocate that, let's log the error and	
		// return '0' value
		if (pki_ssl->peer_chain == 0) {
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, 0);
			return 0;
		}
	}

	if (ret == 1) {
		// We add the certificate only if it was successfully validated
		// to avoid malformed, expired, etc. certificates
		PKI_STACK_X509_CERT_push(pki_ssl->peer_chain, 
                             PKI_X509_dup(x));
	} 

	/* Check for the verify_ok --- it should be OK in depth 0. We use
	 * this variable to keep track if at least one cert in the chain is
	 * explicitly trusted */
	if (depth              == 0 && 
	    pki_ssl->auth      != 0 && 
	    pki_ssl->verify_ok != PKI_OK) {

		PKI_X509_CERT_STACK *sk_x    = 0;
		PKI_X509_CERT       *sk_cert = 0;

		int k = 0;
		int ok = PKI_ERR;

		sk_x = pki_ssl->peer_chain;

		// Certificate Details
		fprintf(stderr, "\n ====== SERVER CERTIFICATE ==========\n");
		PKI_X509_CERT_put(x, PKI_DATA_FORMAT_TXT, "stderr", NULL, NULL, NULL);
		fprintf(stderr, "\n\n");

		if (sk_x != 0) for (k = 0; k < PKI_STACK_X509_CERT_elements(sk_x); k++) {

			// Gets the certificate from the stack
			sk_cert = PKI_STACK_X509_CERT_get_num(sk_x, k);

			// Certificate Details
			fprintf(stderr, "\n ====== PEER CHAIN CERTIFICATE - num: %d ==========\n", k);
			PKI_X509_CERT_put(sk_cert, PKI_DATA_FORMAT_TXT, "stderr", NULL, NULL, NULL);
			fprintf(stderr, "\n");

			// Checks if we can find the certificate in the list of
			// trusted certificates for the SSL/TLS connection
			ok = __ssl_find_trusted(ctx, (X509 *) sk_cert->value);

			// If we have found the certificate, let's break
			if (ok == PKI_OK) break;
		}

		if ( ok == PKI_ERR ) {
			/* No trusted certificate is present in the chain! */
			PKI_log_err("None of the peer chain certificates is "
					"trusted");
			ctx->error = X509_V_ERR_CERT_UNTRUSTED;
			ret = 0;
		} else {
			ret = 1;
		}
	}

	/* Free Allocated Memory for PKI_X509_CERT object */
	if (x) PKI_X509_CERT_free(x);

	return ret;
}

static int __pki_ssl_init_ssl  ( PKI_SSL *ssl ) {

	int	 ssl_verify_flags = 0;

	PKI_TOKEN *ssl_tk   = NULL;

	if ( !ssl || !ssl->ssl_ctx ) return PKI_ERR;

	ssl->connected = 0;

	SSL_CTX_set_options( ssl->ssl_ctx, ssl->flags );

	ssl_tk = ssl->tk;

	ssl_verify_flags = PKI_SSL_VERIFY_NONE;

	if( ssl->verify_flags & PKI_SSL_VERIFY_PEER ) {
		ssl_verify_flags |= SSL_VERIFY_PEER |
					SSL_VERIFY_CLIENT_ONCE;
	};

	if( ssl->verify_flags & PKI_SSL_VERIFY_PEER_REQUIRE ) {
		ssl_verify_flags |= SSL_VERIFY_PEER |
				SSL_VERIFY_FAIL_IF_NO_PEER_CERT | 
				SSL_VERIFY_CLIENT_ONCE;
	}

	/* Load the Server/Client cert/key if auth is set */
	if ( ssl_tk && ssl_tk->cert && ssl_tk->keypair ) {

		PKI_X509_CERT_VALUE *x = NULL;
		PKI_X509_KEYPAIR_VALUE * x_k = NULL;

		if((ssl_tk->cert != NULL ) && 
			(x = PKI_X509_get_value ( ssl_tk->cert )) != NULL )
		{
			PKI_log_debug("Using Token Certificate for Peer Auth");

			if (!SSL_CTX_use_certificate(ssl->ssl_ctx, x ))
			{
				PKI_log_err("Can not enable ssl auth (%s)",
					ERR_error_string(ERR_get_error(),NULL));
				return PKI_ERR;
			}
		}

		x_k = PKI_X509_get_value ( ssl_tk->keypair );

		if(!SSL_CTX_use_PrivateKey(ssl->ssl_ctx, x_k ))
		{
			PKI_log_err("ERROR::Can not enable ssl auth (%s)",
				ERR_error_string(ERR_get_error(), NULL ));

			return PKI_ERR;
		}
	}

	/* Now sets the trusted certificates */
	if( ssl->trusted_certs || (ssl_tk && ssl_tk->trustedCerts))
	{
		X509_STORE *store = NULL;
		unsigned long vflags = 0;

		if ((store = SSL_CTX_get_cert_store(ssl->ssl_ctx)) == NULL)
		{
			PKI_log_debug("Crypto Lib Error (%d::%s)", ERR_get_error(), 
				ERR_error_string(ERR_get_error(), NULL));
			return PKI_ERR;
		}

		//If we want CRL to be checked, enable this
		if (ssl->flags & PKI_SSL_VERIFY_CRL)
			vflags |= X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL;

		X509_STORE_set_flags( store, vflags );

		// Adds the Token CA Cert to the Trusted Certs
		if(ssl_tk && ssl_tk->cacert) X509_STORE_add_cert ( store, 
				PKI_X509_get_value(ssl_tk->cacert));

		if ( ssl->trusted_certs ) {
			int i = 0;

			for (i=0; i < PKI_STACK_X509_CERT_elements(
						ssl->trusted_certs); i++) {
				PKI_X509_CERT_VALUE *val = NULL;
				PKI_X509_CERT *x = NULL;

				x = PKI_STACK_X509_CERT_get_num( 
							ssl->trusted_certs,i);
				val = PKI_X509_get_value ( x );
				X509_STORE_add_cert ( store, val );
			}
		}

		if ( ssl_tk && ssl_tk->trustedCerts ) {
			int i = 0;

			for (i=0; i < PKI_STACK_X509_CERT_elements(
					ssl_tk->trustedCerts); i++) {
				PKI_X509_CERT_VALUE *val = NULL;
				PKI_X509_CERT *x = NULL;

				x = PKI_STACK_X509_CERT_get_num( 
						ssl_tk->trustedCerts,i);
				val = PKI_X509_get_value ( x );
				X509_STORE_add_cert ( store, val );
			}
		}
	}

	/* Clears the SSL_CTX chain certs */
	// SSL_CTX_clear_chain_certs(ssl->ssl_ctx);
	SSL_CTX_clear_extra_chain_certs(ssl->ssl_ctx);

	/* Now sets the other (not-trusted) certificates */
	if ( ssl->other_certs ) {
		int i = 0;
		for (i = 0; i < PKI_STACK_X509_CERT_elements(
						ssl->other_certs); i++) {
			PKI_X509_CERT_VALUE *val = NULL;
			PKI_X509_CERT *x = NULL;

			x = PKI_STACK_X509_CERT_get_num( 
						ssl->other_certs,i);
			val = PKI_X509_get_value ( x );
			SSL_CTX_add_extra_chain_cert(ssl->ssl_ctx, val);
			// SSL_CTX_add0_chain_cert(ssl->ssl_ctx, val);
		}
	}

	/* Now sets the other (not-trusted) certificates (from the ssl token,
	 * if any) */
	if ( ssl_tk && ssl_tk->otherCerts ) {
		int i = 0;
		for ( i = 0; i < PKI_STACK_X509_CERT_elements(
					ssl_tk->otherCerts); i++) {
			PKI_X509_CERT_VALUE *val = NULL;
			PKI_X509_CERT *x = NULL;

			x = PKI_STACK_X509_CERT_get_num( 
					ssl_tk->otherCerts,i);
			val = PKI_X509_get_value ( x );
			SSL_CTX_add_extra_chain_cert(ssl->ssl_ctx, val);
			// SSL_CTX_add0_chain_cert(ssl->ssl_ctx, val);
		}
	}

	/* Set the Verify parameters for SSL */
	SSL_CTX_set_verify( ssl->ssl_ctx, ssl_verify_flags, __ssl_verify_cb );

	/* If an old ref is present, let's remove it */
	if( ssl->ssl ) SSL_free ( ssl->ssl );

	/* Generate a new SSL object */
	if((ssl->ssl = SSL_new(ssl->ssl_ctx)) == NULL ) {
		PKI_log_debug("Can not create a new SSL object (%s:%d)",
							__FILE__, __LINE__ );
		return PKI_ERR;
	}
    
	if( ssl->servername ) {
#ifdef SSL_set_tlsext_host_name
		if(!SSL_set_tlsext_host_name( ssl->ssl, ssl->servername )) {
			PKI_log_err("ERROR::Can not set servername (%s)",
				ERR_error_string(ERR_get_error(), NULL ));
			return PKI_ERR;
		}
#else
		PKI_log_debug("Warning: TLS server name not supported by "
			"installed crypto library");
#endif
	}

	return PKI_OK;
}

int __pki_ssl_start_ssl ( PKI_SSL *ssl ) {

	int idx = -1;
	int rv  = -1;

	if (!ssl || !ssl->ssl ) 
		return PKI_ERROR(PKI_ERR_PARAM_NULL, 0);

	idx = SSL_get_ex_new_index(0, "pki_ssl index", NULL, NULL, NULL);
	if((SSL_set_ex_data(ssl->ssl, idx, ssl)) == 0 ) {
		return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, 0);
	}

	// Connect
	if((rv = SSL_connect(ssl->ssl)) < 0 ) {
		// Can not connect the SSL/TLS interface
		return PKI_ERROR(PKI_ERR_NET_SSL_CONNECT,
                     ERR_error_string(ERR_get_error(), 0));
	}

	// Sets the connected bit
	ssl->connected = 1;

	// Peer certificate processing
	if (SSL_get_peer_certificate(ssl->ssl) != 0         && 
			SSL_get_verify_result(ssl->ssl)    != X509_V_OK && 
			                    ssl->verify_ok != PKI_OK) {

		/*
		PKI_log_err ("PEER VERIFY::SSL Verify Error [%d::%s]", 
			SSL_get_verify_result(ssl->ssl),
			X509_verify_cert_error_string(SSL_get_verify_result(ssl->ssl)));
		*/

		return PKI_ERROR(PKI_ERR_NET_SSL_VERIFY, 0);
	}

	return PKI_OK;
}

/*! \brief Sets the options for a new PKI_SSL object */

PKI_SSL * PKI_SSL_new (const PKI_SSL_ALGOR *algor) {

	PKI_SSL *ret       = 0;
	PKI_SSL_ALGOR *al2 = 0;

	SSL_library_init();

	if ((ret = PKI_Malloc(sizeof( PKI_SSL ))) == 0)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, 0);
		return (NULL);
	}

	if (algor != 0) {
		ret->algor = al2;
	} else {
		ret->algor = PKI_SSL_CLIENT_ALGOR_DEFAULT;
	}

	if ((ret->ssl_ctx = SSL_CTX_new(ret->algor)) == 0) 
	{
		PKI_log_debug("Can not create a new PKI_SSL object (%s)",
				ERR_error_string(ERR_get_error(), NULL ));
		goto err;
	}

	// Enables CRL, OCSP, and PRQP (no REQUIRE)
	PKI_SSL_set_verify(ret, PKI_SSL_VERIFY_NORMAL);
	PKI_SSL_set_cipher(ret, PKI_SSL_CIPHERS_TLS1_2);
	// PKI_SSL_set_cipher(ret, "HIGH:MEDIUM:!NULL");
	PKI_SSL_set_flags(ret, PKI_SSL_FLAGS_DEFAULT);

	ret->verify_ok = PKI_OK;

	return ret;
err:

	if( ret ) PKI_Free ( ret );
	return NULL;
}

PKI_SSL *PKI_SSL_dup ( PKI_SSL *ssl ) {

	PKI_SSL *ret = NULL;

	if ( !ssl ) return NULL;

	if (( ret = PKI_SSL_new( ssl->algor )) == NULL ) {
		return NULL;
	}

	if ( ssl->trusted_certs ) {
		int i = 0;
		ret->trusted_certs = PKI_STACK_X509_CERT_new();
		for ( i = 0; i < PKI_STACK_X509_CERT_elements(ssl->trusted_certs); i++){
			PKI_STACK_X509_CERT_push ( ret->trusted_certs,
				PKI_STACK_X509_CERT_get_num ( ssl->trusted_certs, i));
		}
	}

	ret->verify_flags = ssl->verify_flags;
	ret->verify_ok = ssl->verify_ok;
	ret->flags = ssl->flags;
	ret->tk = ssl->tk;

	return ret;
}

/* --------------------------- Public Functions ------------------------ */

/*! \brief Sets the protocol for a new PKI_SSL object */

int PKI_SSL_set_algor(PKI_SSL *ssl, PKI_SSL_ALGOR *algor) {

	if( !ssl || !ssl->ssl_ctx || !algor )
		return PKI_ERROR(PKI_ERR_PARAM_NULL, 0);

	if(!SSL_CTX_set_ssl_version(ssl->ssl_ctx, algor))
		return PKI_ERROR(PKI_ERR_NET_SSL_SET_CIPHER, 0);

	return PKI_OK;
}

/*! \brief Sets the SSL connection flags */

int PKI_SSL_set_flags ( PKI_SSL *ssl, PKI_SSL_FLAGS flags ) {

	if ( !ssl ) return PKI_ERROR(PKI_ERR_PARAM_NULL, 0);

	ssl->auth = flags;

	return PKI_OK;
}

/*! \brief Sets the Chiphers to be used */

int PKI_SSL_set_cipher ( PKI_SSL *ssl, char *cipher ) {

	// Input Checks
	if ( ssl == 0 || ssl->ssl_ctx == 0 || cipher == 0)
		return PKI_ERROR(PKI_ERR_PARAM_NULL, 0);

	if (ssl->cipher != 0) PKI_Free ( ssl->cipher );

	ssl->cipher = strdup(cipher);

	if (!SSL_CTX_set_cipher_list ( ssl->ssl_ctx, cipher )) {
		PKI_log_err("Can not set ciphers (%s)",
			ERR_error_string(ERR_get_error(),NULL));
		return PKI_ERR;
	}

	return PKI_OK;
}

/*! \brief Sets the verify flags to be used when validating cert chain */

int PKI_SSL_set_verify ( PKI_SSL *ssl, PKI_SSL_VERIFY vflags ) {

	if ( !ssl ) return PKI_ERR;

	ssl->verify_flags = vflags;

	return PKI_OK;
}

/*! \brief Checks if a verify flag has been set */

int PKI_SSL_check_verify(PKI_SSL *ssl, PKI_SSL_VERIFY flag)
{
	if (!ssl) {
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
	}

	if (ssl->verify_flags & flag) return PKI_OK;

	return PKI_ERR;
}

/*! \brief Sets the underlying socket descriptor */

int PKI_SSL_set_fd ( PKI_SSL *ssl, int fd ) {

	if ( !ssl || !ssl->ssl ) {
		return PKI_ERROR(PKI_ERR_PARAM_NULL, 0);
	}

	return SSL_set_fd ( ssl->ssl, fd );
}

/*! \brief Returns the underlying socket descriptor */

int PKI_SSL_get_fd ( PKI_SSL *ssl ) {

	if ( !ssl || !ssl->ssl ) return -1;

	return SSL_get_fd ( ssl->ssl );
}

/*! \brief Initiates an SSL connection to a URL passed as a URL object */
int PKI_SSL_connect_url(PKI_SSL *ssl, URL *url, int timeout) {

	int rv = PKI_OK;
	int	ssl_socket = -1;
 
	// Input checking
	if (ssl == 0 || url == 0) {
		return PKI_ERROR(PKI_ERR_PARAM_NULL, 0);
	}

	if (( rv = __pki_ssl_init_ssl(ssl)) != PKI_OK) {
		rv = PKI_ERROR(PKI_ERR_NET_SSL_INIT, 0);
		goto err;
	}

	/* Connect the socket first */
	if ((ssl_socket = PKI_NET_open(url, timeout)) < 0) {
		/* Can not connect to the server */
		rv = PKI_ERROR(PKI_ERR_NET_OPEN, "[url = %s]", url->url_s);
		goto err;
	}

	// Starts the TLS/SSL protocol
	return PKI_SSL_start_ssl(ssl, ssl_socket);

	/*
	// Sets the FD for the socket
	if (PKI_SSL_set_fd( ssl, ssl_socket ) != PKI_OK) {
		rv PKI_ERROR(PKI_ERR_NET_SSL_SET_SOCKET, 0);
		goto err;
	}

	// Starts the SSL/TLS protocol
	if ( __pki_ssl_start_ssl( ssl ) != PKI_OK) {
		rv = PKI_ERROR(PKI_ERR_NET_SSL_START, 0);
		goto err;
	}

	// All Done, Ok.
	return PKI_OK;
	*/

err:
	if (ssl_socket > 0) close(ssl_socket);
	ssl->connected = 0;

	return rv;
}

/*! \brief Initiates an SSL connection over an already connected socket */

int PKI_SSL_start_ssl ( PKI_SSL *ssl, int fd ) {

	if (ssl == 0) return PKI_ERROR(PKI_ERR_PARAM_NULL, 0);

	if (fd <= 0) return PKI_ERROR(PKI_ERR_PARAM_TYPE, 0);

	if ( __pki_ssl_init_ssl ( ssl ) == PKI_ERR ) {
		return PKI_ERROR(PKI_ERR_NET_SSL_INIT, 0);
	}

	if (PKI_SSL_set_fd( ssl, fd ) != PKI_OK) {
		return PKI_ERROR(PKI_ERR_NET_SSL_SET_SOCKET, 0);
	}

	if ( __pki_ssl_start_ssl( ssl ) != PKI_OK) {
		return PKI_ERROR(PKI_ERR_NET_SSL_START, 0);
	}

	return PKI_OK;
}

/*! \brief Initiates an SSL connection to a URL passed as a string */

int PKI_SSL_connect ( PKI_SSL *ssl, char *url_s, int timeout ) {

	URL *url = NULL;
	int ret = PKI_OK;

	if ( !ssl || !url_s ) return PKI_ERR;

	if((url = URL_new ( url_s )) == NULL ) {
		return PKI_ERR;
	}

	if((ret = PKI_SSL_connect_url ( ssl, url, timeout )) == PKI_OK ) {
		ssl->connected = 1;
	}

	
	URL_free ( url );

	return ret;
	
}

/*! \brief Returns the Peer certificate used in a connected PKI_SSL */

struct pki_x509_st * PKI_SSL_get_peer_cert ( PKI_SSL *ssl ) {
	PKI_X509_CERT_VALUE *x = NULL;
	struct pki_x509_st * ret = NULL;

	if ( !ssl || !ssl->connected ) return PKI_ERR;

	if((x = SSL_get_peer_certificate ( ssl->ssl )) == NULL ) {
		PKI_log_err("Can not get peer certificate (%s)",
			ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	if(( ret = PKI_X509_new_dup_value( PKI_DATATYPE_X509_CERT, 
						x, NULL )) == NULL ) {
		PKI_log_debug("Memory Error");
		X509_free ( x );
		return NULL;
	}

	return ret;
	
}

/*! \brief Returns the peer certificate chain as a new PKI_X509_CERT_STACK */

PKI_X509_CERT_STACK * PKI_SSL_get_peer_chain ( PKI_SSL *ssl ) {

	// PKI_X509_CERT_STACK *ret_sk = NULL;
	// STACK_OF(X509) *sk = NULL;
	// int i = 0;

	if ( !ssl || !ssl->connected ) return PKI_ERR;

	return ssl->peer_chain;

	/*
	if(( sk = SSL_get_peer_cert_chain( ssl->ssl )) == NULL ) {
		PKI_log_err("Can not retrieve peer cert chain from SSL (%s)",
			ERR_error_string(ERR_get_error(),NULL));
		return NULL;
	}

	if((ret_sk = PKI_STACK_X509_CERT_new()) == NULL ) {
		PKI_log_err ("Memory Error");
		return NULL;
	}

	for( i = 0; i < sk_X509_num( sk ); i++ ) {
		PKI_X509_CERT_VALUE *x = NULL;
		PKI_X509_CERT *cert = NULL;

		if((x = sk_X509_value( sk, i )) == NULL ) {
			PKI_log_err ("Memory Error");
			PKI_STACK_X509_CERT_free_all ( ret_sk );
			return NULL;
		}

		cert = PKI_X509_new_dup_value ( PKI_DATATYPE_X509_CERT, 
							x, NULL );
		PKI_STACK_X509_CERT_push ( ret_sk, cert );
	}

	return ret_sk;
	*/
}

/*! \brief Returns the extension value provided in Client Hello or NULL */

const char *PKI_SSL_get_servername ( PKI_SSL *ssl ) {

	if ( !ssl || !ssl->connected ) return NULL;

#ifdef TLSEXT_NAMETYPE_host_name
	return SSL_get_servername ( ssl->ssl, TLSEXT_NAMETYPE_host_name );
#else
	return NULL;
#endif
}

/*! \brief Sets the PKI_TOKEN to be used for the SSL connection */

int PKI_SSL_set_token ( PKI_SSL *ssl, struct pki_token_st *tk ) {

	if( !ssl || !tk ) return PKI_ERR;

	if ( ssl->tk ) {
		PKI_log_debug("WARNING: Setting a new token for PKI_SSL");
	}

	ssl->tk = tk;

	return PKI_OK;
}

/*! \brief Sets the list of trusted certificates for SSL connections */

int PKI_SSL_set_trusted ( PKI_SSL *ssl, PKI_X509_CERT_STACK *sk ) {

	int i = 0;

	if ( !ssl || !sk ) {
		PKI_log_err ( "Missing PKI_SSL or PKI_X509_CERT_STACK param!");
		return PKI_ERR;
	}

	if ( ssl->trusted_certs ) {
		PKI_log_debug("WARNING: Overriding already "
					"present trusted certs in PKI_SSL");
	} else {
		ssl->trusted_certs = PKI_STACK_X509_CERT_new();
	}

	for( i = 0; i < PKI_STACK_X509_CERT_elements (sk); i++ ) {
		// PKI_log_debug("ADDING CERT #%d to trusted_certs", i );
		PKI_STACK_X509_CERT_push ( ssl->trusted_certs,
			PKI_STACK_X509_CERT_get_num (sk,i));
	}

	return PKI_OK;
}

/*! \brief Adds a certificate to the list of trusted ones for SSL connections */

int PKI_SSL_add_trusted ( PKI_SSL *ssl, PKI_X509_CERT *cert ) {

	// Input Check
	if ( !ssl || !cert ) PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// Allocates a new list if not already present
	if ((ssl->trusted_certs == NULL) &&
		(ssl->trusted_certs = PKI_STACK_X509_CERT_new()) == NULL) {
		// Failure allocating memory
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
	}

	// Adds the certificate to the list of trusted certs
	PKI_STACK_X509_CERT_push ( ssl->trusted_certs, cert);

	// All Done
	return PKI_OK;
}

/*! \brief Sets the list of untrusted certificates for SSL connections */

int PKI_SSL_set_others ( PKI_SSL *ssl, PKI_X509_CERT_STACK *sk ) {

	int i = 0;

	if ( !ssl || !sk ) {
		PKI_log_err ( "Missing PKI_SSL or PKI_X509_CERT_STACK param!");
		return PKI_ERR;
	}

	if (ssl->other_certs == NULL) {
		ssl->other_certs = PKI_STACK_X509_CERT_new();
	}

	for( i = 0; i < PKI_STACK_X509_CERT_elements (sk); i++ ) {
		PKI_STACK_X509_CERT_push ( ssl->other_certs,
			PKI_STACK_X509_CERT_get_num (sk,i));
	}

	return PKI_OK;
}

/*! \brief Adds a certificate to the list of not-trusted ones for SSL connections */

int PKI_SSL_add_other ( PKI_SSL *ssl, PKI_X509_CERT *cert ) {

	// Input Check
	if ( !ssl || !cert ) PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// Allocates a new list if not already present
	if ((ssl->other_certs == NULL) &&
		(ssl->other_certs = PKI_STACK_X509_CERT_new()) == NULL) {
		// Failure allocating memory
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
	}

	// Adds the certificate to the list of non-trusted certs
	PKI_STACK_X509_CERT_push(ssl->other_certs, cert);

	// All Done
	return PKI_OK;
}


/*! \brief Closes an SSL connection */

int PKI_SSL_close ( PKI_SSL *ssl ) {
	
	// SSL_CTX *ssl_ctx = NULL;
	// int ssl_socket = -1;

	if ( !ssl || !ssl->ssl ) return ( PKI_ERR );

	if ( ssl->connected ) {
		SSL_free ( ssl->ssl );
	}

	/*
	if((ssl_socket = SSL_get_fd ( ssl->ssl )) > 0 ) {
		close ( ssl_socket );
	};

	if (( ssl_ctx = SSL_get_SSL_CTX(ssl->ssl)) == NULL ) {
		SSL_CTX_free ( ssl_ctx );
	}

	SSL_free ( ssl->ssl );
	*/

	// PKI_Free ( ssl->ssl );
	ssl->ssl = NULL;

	ssl->connected = 0;

	return PKI_OK;
	
}

/*! \brief Frees memory associated with a PKI_SSL */

void PKI_SSL_free ( PKI_SSL *ssl ) {

	PKI_X509_CERT * cert = NULL;

	if ( !ssl ) return;

	if( ssl->ssl_ctx ) {
		SSL_CTX_set_ex_data ( ssl->ssl_ctx, 0, NULL );
		// X509_STORE_CTX_set_ex_data ( ssl->ssl_ctx, 0, NULL);
	}

	if( ssl->ssl ) {
		SSL_set_ex_data ( ssl->ssl, 0, NULL );
		SSL_free ( ssl->ssl );
	};

	if( ssl->trusted_certs ) {
		while( (cert = PKI_STACK_X509_CERT_pop (ssl->trusted_certs))
								!= NULL ) {
			PKI_X509_CERT_free ( cert );
		};

		PKI_STACK_X509_CERT_free ( ssl->trusted_certs );
	}

	if( ssl->other_certs ) {
		while( (cert = PKI_STACK_X509_CERT_pop (ssl->other_certs))
								!= NULL ) {
			PKI_X509_CERT_free ( cert );
		};
		PKI_STACK_X509_CERT_free ( ssl->other_certs );
	}

	if( ssl->peer_chain ) {
		while((cert = PKI_STACK_X509_CERT_pop (ssl->peer_chain ))
								!= NULL ) {
			PKI_X509_CERT_free ( cert );
		};
		PKI_STACK_X509_CERT_free ( ssl->peer_chain );
	}


	// if ( ssl->ssl_ctx ) X509_STORE_CTX_free ( ssl->ssl_ctx );

	PKI_Free ( ssl );

	return;
}

/*! \brief Writes data to a connected PKI_SSL */

ssize_t PKI_SSL_write ( PKI_SSL *ssl, char * buf, ssize_t size ) {

	ssize_t ret = 0;

	if (!ssl || !ssl->ssl || !ssl->connected || !buf || size <= 0)
	{
		if (!ssl || !ssl->ssl) PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

		if (!ssl->connected) PKI_log_debug("PKI_SSL not connected!");
		if (!buf) PKI_log_debug("PKI_SSL::Write::Empty Data");
		if (size <= 0) PKI_log_debug("PKI_SSL::Write::Size <=0 (%s)", size );

		return -1;
	}

	if((ret = SSL_write(ssl->ssl, buf, (int) size )) < 0)
	{
		PKI_log_err("SSL write error (%s)",
			ERR_error_string(ERR_get_error(),NULL));
	}

	return ret;
}

/*! \brief Reads data from a connected PKI_SSL */

ssize_t PKI_SSL_read(PKI_SSL *ssl, char * buf, ssize_t size)
{
	ssize_t ret = 0;

	if( !ssl || !ssl->ssl || !ssl->connected || !buf || size <= 0) 
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return -1;
	}

	if ((ret = SSL_read(ssl->ssl, buf, (int) size )) < 0)
	{
		PKI_log_err("SSL read error (%s)",
			ERR_error_string(ERR_get_error(),NULL));
	}

	return ret;
}

