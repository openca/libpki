/* src/net/pkcs11.c */
/*
 * LIBPKI - Easy PKI Library
 * by Massimiliano Pala (madwolf@openca.org)
 * OpenCA project 2007
 *
 * Copyright (c) 2007 The OpenCA Project.  All rights reserved.
 *
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <libpki/pki.h>

#ifdef HAVE_P11
	static PKCS11_CTX   *ctx   = NULL;
#endif /* HAVE_P11 */

char *pkcs11_parse_url_getval(const URL  * url,
		                      const char * keyword ) {

	char * ret = NULL;
	char * tmp_s = NULL;
	char * tmp_s2 = NULL;

	char *col = NULL;
	char *val = NULL;

	if( !url || !url->path ) return( NULL );

	tmp_s = url->path;

	while((tmp_s2 = strchr(tmp_s, '/')) != NULL ) {
		tmp_s2++;
		tmp_s = tmp_s2;
	}

	if((col = PKI_Malloc( 1024 )) == NULL ) {
		return( NULL );
	}

	if((val = PKI_Malloc( 1024 )) == NULL ) {
		PKI_Free( col );
		return (NULL);
	}

	while( sscanf(tmp_s, "(%[^=]=\"%[^\"])", col, val) > 1 ) {

		if( (strlen(col) == strlen(keyword)) && 
			(strncmp_nocase( col,keyword,(int)strlen(keyword)) ) == 0 ) {
			ret = strdup( val );
			goto end;
		}

		/* The tmp_s should point to the next token */
		tmp_s += strlen(col) + strlen(val) + 3;
	}
end:
	if( col ) PKI_Free ( col );
	if( val ) PKI_Free ( val );

	return( ret );
}

PKI_MEM_STACK *URL_get_data_pkcs11(const char * url_s,
		                           ssize_t      size ) {
	URL *url = NULL;

	if( !url_s ) return (NULL);

	if(((url = URL_new( url_s )) == NULL) ||
		url->proto != URI_PROTO_PKCS11 ) {
		PKI_log_debug ("Not a PKCS11 URL");
		return (NULL);
	}

	return URL_get_data_pkcs11_url(url, size);
}

PKI_MEM_STACK *URL_get_data_pkcs11_url(const URL * url,
		                               ssize_t     size ) {

#ifdef HAVE_P11

	PKCS11_SLOT  *slots = NULL;
	PKCS11_TOKEN *tk    = NULL;

	char *libfile = NULL;
	int num = 0;
	int i = 0;

	char * search_label = NULL;
	char * search_id = NULL;
	char * search_slot = NULL;
	char * search_slotid = NULL;

	PKI_MEM *tmp_mem = NULL;
	PKI_MEM_STACK *sk = NULL;

	if( !url ) return (NULL);

	if( ctx == NULL ) {
		if((ctx = PKCS11_CTX_new ()) == NULL ) {
			return(NULL);
		}

		PKI_log_debug("Loading %s Library", url->addr );
		if(( i = PKCS11_CTX_load(ctx, url->addr)) != 0 ) {
			PKI_log_err("Can not load library %s [err::%d]", url->addr, i);
			// ERR_print_errors_fp( stderr );
		}
	}

	if( PKCS11_enumerate_slots( ctx, &slots, &num ) == -1 ) {
		PKI_log_err ("Can not enumerate slots");
		goto err;
        };

	if(( sk = PKI_STACK_MEM_new()) == NULL ) {
		goto err;
	}

	search_slot   = pkcs11_parse_url_getval( url, "slot" );
	search_slotid = pkcs11_parse_url_getval( url, "slotid" );
	search_label  = pkcs11_parse_url_getval( url, "label" );
	search_id     = pkcs11_parse_url_getval( url, "id" );
	
	if( search_slot )
		PKI_log_debug("PKCS#11::SEARCH::SLOT =>  %s\n", search_slot);
	if( search_slotid )
		PKI_log_debug("PKCS#11::SEARCH::SLOTID =>  %s\n", search_slotid);
	if( search_label )
		PKI_log_debug("PKCS#11::SEARCH::LABEL => %s\n", search_label);
	if( search_id )
		PKI_log_debug("PKCS#11::SEARCH::ID =>    %s\n", search_id);

	for(i = 0; i < num; i++ ) {

		BIO *mem = NULL;
		BUF_MEM *mem_buf = NULL;

		PKCS11_CERT *certs = NULL;
		PKCS11_SLOT *p = NULL;
		PKCS11_CERT *x = NULL;

		PKCS11_KEY  *keyList = NULL;
		PKCS11_KEY  *key     = NULL;
		EVP_PKEY    *evp_pkey = NULL;

		int n = 0;
		int t = 0;
		int n_objs = 0;
		int p_ret = 0;
		
                p = &slots[i];

                if((!p) || ((tk = p->token) == NULL) ) {
			continue;
		}

		if( (search_slot) && ( strncmp_nocase( search_slot, 
				tk->label, strlen(search_slot) == 0) )) {
			continue;
		}

		if( (search_slotid) && ( atoi(search_slotid) != i )) {
			PKI_log_debug("PKCS11::SLOTID is %s (%d), curr is %d\n",
					search_slotid, atoi(search_slotid), i);
			continue;
		}

		if( strncmp_nocase( url->attrs, "cert", 4 ) == 0) {
			PKI_log_debug("PKCS11::CERT DATATYPE SELECTED!\n");
			if((mem = BIO_new(BIO_s_mem())) == NULL ) {
				goto err;
			}

			/* Get the list of certificates in the slot */
			p_ret = PKCS11_enumerate_certs( tk, &certs, &n_objs);

			for( n = 0; n < n_objs; n++ ) {

				/* Pointer to the current certificate */
				x = &certs[n];

				PKI_log_debug("PKCS11::CERT label=%s\n",
					x->label);
				PKI_log_debug("PKCS11::CERT id=");
				for( t = 0; t < x->id_len; t ++ ) {
					printf("%c", x->id[t] );
				} printf("\n");

				if( (search_label) &&
					(strncmp_nocase( search_label, x->label,
						strlen( search_label)) != 0 )){
					PKI_log_debug("PKCS11::LABEL does not"
						"match, SKIPPING!!!!\n");
					continue;
				}
 
				if( search_id ) {
					int stop = 0;

					for( t = 0; t < x->id_len; t ++ ) {
						if( search_id[t] != x->id[t] ) {
							stop = 1;
							break;
						}
					}

					if( stop == 1 ) { 
						PKI_log_debug("PKCS#11::ID does not"
										"match, SKIPPING!!!!\n");
						continue;
					}
				}
 
				/* Write the cert in PEM format to memory */
				p_ret = PEM_write_bio_X509( mem, x->x509 );

				/* Get the pointer to the memory buffer */
				BIO_get_mem_ptr( mem, &mem_buf );

				/* Push a PKI_MEM buffer on the stack */
				tmp_mem = PKI_MEM_new_null();
				PKI_MEM_add ( tmp_mem, mem_buf->data, 
							mem_buf->length);
				PKI_STACK_push( sk, tmp_mem );
			}

			/* Free the temp memory buffer */
			if( mem ) BIO_free( mem );

		} else if (strncmp_nocase( url->attrs, "key", 3) == 0 ) {
			char *pin = NULL;

			PKI_log_debug("PKCS#11::KEY DATATYPE SELECTED!\n");

			pin = pkcs11_parse_url_getval( url, "pin" );

			if ( (tk->loginRequired == 1) && (pin != NULL ) ) {
				p_ret = PKCS11_login ( p, 0, pin );
				PKI_log_debug("PKCS#11::LOGIN Result %d\n",
					p_ret );
        		}

			if((mem = BIO_new(BIO_s_mem())) == NULL ) {
				goto err;
			}

		        p_ret = PKCS11_enumerate_keys ( tk, &keyList, &n_objs );

			for( n = 0; n < n_objs; n++ ) {
				key = &keyList[n];

				PKI_log_debug("PKCS#11::KEY label=%s\n", key->label);
				PKI_log_debug("PKCS#11::KEY id=");
				for( t = 0; t < key->id_len; t ++ ) {
					printf("%c", key->id[t] );
				} printf("\n");

				if( (search_label) &&
					(strncmp_nocase( search_label, x->label,
						strlen( search_label)) != 0 )){

					PKI_log_debug("PKCS11::LABEL does not"
						"match, SKIPPING!!!!\n");
					continue;
				}
 
				if( search_id ) {
					int stop = 0;

					for( t = 0; t < x->id_len; t ++ ) {
						if( search_id[t] != x->id[t] ) {
							stop = 1;
							break;
						}
					}

					if( stop == 1 ) { 
						PKI_log_debug("PKCS#11::ID does not"
										"match, SKIPPING!!!!\n");
						continue;
					}
				}
 
				/* Get Private Key in OpenSSL format */
				evp_pkey = PKCS11_get_private_key( key );

				/* Write the cert in PEM format to memory */
				p_ret = PEM_write_bio_PUBKEY( mem, evp_pkey );

				/* Get the pointer to the memory buffer */
				BIO_get_mem_ptr( mem, &mem_buf );

				/* Push a PKI_MEM buffer on the stack */
				tmp_mem = PKI_MEM_new_null();
				PKI_MEM_add ( tmp_mem, mem_buf->data, 
							mem_buf->length);
				PKI_STACK_push( sk, tmp_mem );
			}

			if( mem ) BIO_free ( mem );

		} else {
			PKI_log_debug("Selected Datatype Not Supported (%s)", url->attrs);
		}
	}

err:
	if( slots ) PKCS11_release_all_slots( ctx, slots, num );

	if( libfile ) PKI_Free (libfile);

	if( search_slot ) PKI_Free ( search_slot );
	if( search_slotid ) PKI_Free ( search_slotid );
	if( search_label ) PKI_Free ( search_label );
	if( search_id ) PKI_Free ( search_id );

	return ( sk );

#else

	PKI_log_debug("PKCS#11 Support not available in this build");
	return ( NULL );

#endif
}

