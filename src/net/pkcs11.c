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

char *pkcs11_parse_url_getval ( URL * url, char *keyword ) {

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

PKI_MEM_STACK *URL_get_data_pkcs11 ( char *url_s, ssize_t size ) {
	URL *url = NULL;

	if( !url_s ) return (NULL);

	if(((url = URL_new( url_s )) == NULL) ||
		url->proto != URI_PROTO_PKCS11 ) {
		PKI_log_debug ("Not a PKCS11 URL");
		return (NULL);
	}

	return ( URL_get_data_pkcs11_url( url, size ));
}

PKI_MEM_STACK *URL_get_data_pkcs11_url ( URL *url, ssize_t size ) {

#ifdef HAVE_P11
	// PKCS11_CTX   *ctx   = NULL;
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

	/*
	if((libfile = pkcs11_parse_url_libpath ( url )) == NULL ) {
		return( NULL );
	}
	*/

	/*
	slot = pkcs11_parse_url_slot ( url );
	id = pkcs11_parse_url_id ( url );
	*/

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
		PKI_log_debug("DEBUG::PKCS11::SEARCH::SLOT =>  %s\n", search_slot);
	if( search_slotid )
		PKI_log_debug("DEBUG::PKCS11::SEARCH::SLOTID =>  %s\n", search_slotid);
	if( search_label )
		PKI_log_debug("DEBUG::PKCS11::SEARCH::LABEL => %s\n", search_label);
	if( search_id )
		PKI_log_debug("DEBUG::PKCS11::SEARCH::ID =>    %s\n", search_id);

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
					printf("DEBUG::PKCS11::ID does not"
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

			PKI_log_debug("PKCS11::KEY DATATYPE SELECTED!\n");

			pin = pkcs11_parse_url_getval( url, "pin" );

			if ( (tk->loginRequired == 1) && (pin != NULL ) ) {
				p_ret = PKCS11_login ( p, 0, pin );
				PKI_log_debug("PKCS11::LOGIN Result %d\n",
					p_ret );
        		}

			if((mem = BIO_new(BIO_s_mem())) == NULL ) {
				goto err;
			}

		        p_ret = PKCS11_enumerate_keys ( tk, &keyList, &n_objs );

			for( n = 0; n < n_objs; n++ ) {
				key = &keyList[n];

				printf("DEBUG::PKCS11::KEY label=%s\n",
					key->label);
				printf("DEBUG::PKCS11::KEY id=");
				for( t = 0; t < key->id_len; t ++ ) {
					printf("%c", key->id[t] );
				} printf("\n");

				if( (search_label) &&
					(strncmp_nocase( search_label, x->label,
						strlen( search_label)) != 0 )){
					printf("DEBUG::PKCS11::LABEL does not"
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
					printf("DEBUG::PKCS11::ID does not"
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
			printf("DEBUG::PKCS11::OTHER DATATYPE SELECTED!\n");
		}
	}

err:
	if( slots ) PKCS11_release_all_slots( ctx, slots, num );

	/*
	if( ctx ) { 
		PKCS11_CTX_unload(ctx);
		PKCS11_CTX_free(ctx);
	}
	*/

	if( libfile ) PKI_Free (libfile);

	if( search_slot ) PKI_Free ( search_slot );
	if( search_slotid ) PKI_Free ( search_slotid );
	if( search_label ) PKI_Free ( search_label );
	if( search_id ) PKI_Free ( search_id );

	return ( sk );

#else
	return ( NULL );
#endif
}


/*
int main () {

	PKCS11_CTX *ctx = NULL;
	char *libfile = NULL;
	int ret;
	int num = 0;
	int i;
	PKCS11_SLOT *slots = NULL;
	PKCS11_SLOT *p = NULL;
	PKCS11_TOKEN *token = NULL;
	char * so_pin = "1234567890";
	char * pin = NULL;

	ctx = PKCS11_CTX_new();

	libfile = prompt_pin("Enter Library Path (full): ");
	printf("Loading %s library ... ", libfile);
	ret = PKCS11_CTX_load(ctx, libfile);
	free(libfile);

	if( ret == 0 ) {
		printf("LOADED!!!\n");
	} else {
		printf("ERROR: %d\n", ret);
	}

	ret = PKCS11_enumerate_slots( ctx, &slots, &num );
	if( ret == -1 ) {
		printf("ERROR: can not enumerate slots!\n");
	} else {
		printf("N. of Found Slots: %d\n", num);
	}

	for(i=0; i < num; i++ ) {
		p = &slots[i];
		token = p->token;

		print_slot_info( p );
	}
		
	if( num > 0 ) {
		PKCS11_release_all_slots( ctx, slots, num );
	}
	PKCS11_CTX_free(ctx);

	return 0;
}

int print_token_certs ( PKCS11_SLOT *slot ) {

	PKCS11_CERT *certs = NULL;
	PKCS11_CERT *x = NULL;
	PKCS11_KEY  *key = NULL;
	PKCS11_TOKEN *tk = NULL;

	int ret = 0;
	int i = 0;
	int n = 0;
	int r = 0;
	int login = 0;
	int loginReq = 0;

	unsigned int num;

	tk = slot->token;
	if( !tk ) return (-1);

	ret = PKCS11_enumerate_certs ( tk, &certs, &num );
	if( ret == -1 ) {
		printf("     - ERROR: Can not enumerate certs!\n");
		return(-1);
	}

	loginReq = tk->loginRequired;

	for( i=0; i < num; i++ ) {
		BIO *bio = NULL;
		RSA *rsa = NULL;
		BIGNUM *bn = NULL;
		char name[1024];

		x = &certs[i];
		printf("    - Certificate [%d]:\n", i);
		printf("       - Label: %s\n", x->label );
		printf("       - Id: ");

		for(n=0;n<x->id_len;n++) {
			printf("%c", x->id[n] );
		} printf("\n");
 
		bio=BIO_new(BIO_s_file());
		BIO_set_fp(bio,stdout,BIO_NOCLOSE);
		X509_NAME_oneline(X509_get_subject_name(x->x509),
							name,sizeof name);
		BIO_printf(bio,"       - Subject: %s\n", name);
		X509_NAME_oneline(X509_get_issuer_name(x->x509),
							name,sizeof name);
		BIO_printf(bio, "       - Issuer: %s\n", name);
		BIO_free(bio);

		if ( tk->loginRequired == 1 ) {
			char * pin = NULL;
			printf("\n   Token Login Required:\n");
			if((pin = prompt_pin("\tEnter PIN: ")) != NULL){
				ret = PKCS11_login ( slot, 0, pin );
				free(pin);
				login = 1;
			} else {
				ret = -1;
			}
		}

		if( ret == -1 ) {
			printf("\tERROR: Showing only public Info\n");
		}

		key = PKCS11_find_key( x );
		if( key ) {
			EVP_PKEY *evp_key = NULL;

			printf("       - Private Key: found!\n");
			printf("          - Label: %s\n", key->label);
			printf("          - Id: ");
			for( n=0;n<key->id_len;n++){
				printf("%c", key->id[n]);
			} printf( "\n");
			printf("          - Present: %u\n", key->isPrivate);
			printf("          - Need Login: %u\n", key->needLogin);

			evp_key = PKCS11_get_private_key( key );

			if( evp_key ) {
				printf("          - PKey Loaded: yes\n");
				printf("          - PKey type: ");
				ret = PKCS11_get_key_type (key);
				switch( ret ) {
					case EVP_PKEY_RSA:
						printf("RSA\n");
						break;
					case EVP_PKEY_DSA:
						printf("DSA\n");
						break;
					case EVP_PKEY_EC:
						printf("EC\n");
						break;
					default:
						printf("Unknown\n");
				}
			} else {
				printf("          - PKey Loaded: no\n");
			}

		}
	}

	if( login ) PKCS11_logout( slot );

	return(0);
}

int print_token_keys ( PKCS11_SLOT *slot ) {

	PKCS11_CERT *x = NULL;
	PKCS11_KEY  *keyList = NULL;
	PKCS11_KEY  *key = NULL;
	PKCS11_TOKEN *tk = NULL;

	int ret = 0;
	int i = 0;
	int n = 0;
	int r = 0;
	int login = 0;

	unsigned int num;

	tk = slot->token;
	if( !tk ) return (-1);

	if ( tk->loginRequired == 1 ) {
		char * pin = NULL;
		printf("\n   Token Login Required:\n");
		if((pin = prompt_pin("\tEnter PIN: ")) != NULL){
			ret = PKCS11_login ( slot, 0, pin );
			free(pin);
			login = 1;
		} else {
			ret = -1;
		}
	}

	ret = PKCS11_enumerate_keys ( tk, &keyList, &num );

	if( ret == -1 ) {
		printf("     - ERROR: Can not enumerate certs!\n");
		return(-1);
	}

	if( ret == -1 ) {
		printf("\tERROR: Showing only public Info\n");
	}

	printf("TOKEN KEYS [%d]:\n", num);

	for( i=0; i < num; i++ ) {
		BIO *bio = NULL;
		RSA *rsa = NULL;
		BIGNUM *bn = NULL;
		EVP_PKEY *evp_key = NULL;

		key = &keyList[i];

		printf("    - Key [%d]:\n", i);
		printf("       - Label: %s\n", key->label );
		printf("       - Id: ");
		for(n=0;n<key->id_len;n++) {
			printf("%c", key->id[n] );
		} printf("\n");
		printf("          - Present: %u\n", key->isPrivate);
		printf("          - Need Login: %u\n", key->needLogin);
		evp_key = PKCS11_get_private_key( key );
		if( evp_key ) {
			printf("          - PKey Loaded: yes\n");
			printf("          - PKey type: ");
			ret = PKCS11_get_key_type (key);
			switch( ret ) {
				case EVP_PKEY_RSA:
					printf("RSA\n");
					break;
				case EVP_PKEY_DSA:
					printf("DSA\n");
					break;
				case EVP_PKEY_EC:
					printf("EC\n");
					break;
				default:
					printf("Unknown\n");
			}
			bio=BIO_new(BIO_s_file());
			BIO_set_fp(bio,stdout,BIO_NOCLOSE);

			printf("          - PKey size: %d\n",
				PKCS11_get_key_size (key)*8);

			printf("          - PKey modulus: %d\n",
				PKCS11_get_key_modulus( key, &bn ));
			BN_print(bio, bn);

			printf("          - PKey exponent: %d\n",
				PKCS11_get_key_exponent( key, &bn ));

			BN_print(bio, bn);

			rsa = EVP_PKEY_get1_RSA(evp_key);

			if( !rsa->d || !rsa->p || !rsa->q ) {
				printf("          - Exportable: NO\n" );
			} else {
				if( rsa->n && rsa->e && rsa->d && rsa->p && rsa->q ) {
					printf("          - Exportable: YES\n");
				}
			}


			// Exporting the Key 
			//
			// bio=BIO_new(BIO_s_file());
			// BIO_set_fp(bio,stdout,BIO_NOCLOSE);
			// RSA_print(bio, rsa, 0);
			// BIO_free( bio );

		} else {
			printf("          - PKey Loaded: no\n");
		}

		x = PKCS11_find_certificate( key );
		if( x ) {

			printf("       - Certificate: found!\n");
			printf("          - Label: %s\n", x->label);
			printf("          - Id: ");
			for( n=0;n<x->id_len;n++){
				printf("%c", x->id[n]);
			} printf( "\n");
		}
		bio=BIO_new(BIO_s_file());
		BIO_set_fp(bio,stdout,BIO_NOCLOSE);
		X509_print(bio, x->x509);
		BIO_free(bio);
	}

	if( login ) PKCS11_logout( slot );

	return(0);
}

int print_slot_info ( PKCS11_SLOT *slot ) {

	PKCS11_TOKEN *tk = NULL;

	printf("\nSlot (Manufacturer: %s):\n"
			" - description: %s\n - removable: %u\n",
		slot->manufacturer, slot->description, slot->removable);

	tk = slot->token;
	if ( tk ) {
		printf(" * token inserted:\n");
		printf("    - label: %s\n", tk->label );
		printf("    - manufacturer: %s\n", tk->manufacturer);
		printf("    - model: %s\n", tk->model );
		printf("    - serial: %s\n", tk->serialnr );
		printf("    - initialized %u\n", tk->initialized );
		printf("    - loginRequired: %u\n", tk->loginRequired);
		printf("    - secure login: %u\n", tk->secureLogin);
		printf("    - userPinSet: %u\n", tk->userPinSet);
		printf("    - readOnly: %u\n", tk->readOnly );
		printf("\n");

		print_token_certs ( slot );
		// print_token_keys ( slot );
	}

	return(0);
}

*/
