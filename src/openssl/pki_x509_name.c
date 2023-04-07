/* openssl/pki_x509_name.c */

#include <libpki/pki.h>

PKI_X509_NAME *PKI_X509_NAME_new_null ( void ) {

	PKI_X509_NAME *ret = NULL;

	ret = (PKI_X509_NAME *) X509_NAME_new();
	return (ret);
}

int PKI_X509_NAME_free( PKI_X509_NAME *name ) {

	if( name == NULL ) return(1);

	X509_NAME_free ( (X509_NAME *) name );

	return(1);
}

PKI_X509_NAME *PKI_X509_NAME_new (const char *name) {

	PKI_X509_NAME *ret = NULL;
	int status = 0;

	char *token = NULL;
	const char *start = NULL;
	const char *pnt = NULL;
	int  mrdn = 0;

	unsigned long ctype = MBSTRING_UTF8;

	if((ret = PKI_X509_NAME_new_null()) == NULL ) {
		PKI_log_debug("ERROR, can not create a new X509_NAME!");
		return (NULL);
	}

	start = name;
	pnt = start;
	while( ( pnt ) && (pnt < start + strlen(start)) && (status != 5) ) {
		if ( status == 0 ) {
			if( *pnt == ' ' ) {
				pnt++;
				continue;
			} else if ( (*pnt == ',') || (*pnt == '/') ||
						(*pnt == ';') ) {
				break;
			} else if ( *pnt == '+' ) {
				mrdn = -1;
				pnt++;
				start = pnt;
				continue;
			} else {
				start = pnt;
				pnt++;
				status = 1;
				continue;
			}
		} else if ( status == 1 ) {
			if( *pnt == '\\' ) {
				status = 2;
				pnt++;
				continue;
			} else if ( *pnt == '=' ) {
				pnt++;
				status = 3;
				continue;
			} else if ( (*pnt == ',') || (*pnt == '/') ||
						(*pnt == ';') ) {
				break;
			} else {
				pnt++;
				continue;
			}
		} else if ( status == 2 ) {
			pnt++;
			status = 1;
			continue;
		} else if ( status == 3 ) {
			if( *pnt == '\\' ) {
				status = 4;
				pnt++;
				continue;
			} else if ( (*pnt == ',') || (*pnt == '/') ||
					(*pnt == ';') || (*pnt == '+' ) || *(pnt+1) == 0) {

				int i, k;
				size_t len;

				char *key = NULL;
				char *val = NULL;

				const char *err;

				if ( (mrdn == 0) && (*pnt == '+')) {
					mrdn = 1;
				};

				len = (size_t) (pnt-start);
				if( *(pnt+1) == 0 ) len++;

				token = (char *) PKI_Malloc((size_t)(len+1));
				memset(token, 0, len);
				strncpy(token, start, len);
				token[len] = '\x0';
				i=0;
				for(k=0;k<len;k++) {
					if( *(token+k) != '\\' ) {
						*(token+i) = *(token+k);
					} else {
						*(token+i) = *(token+k+1);
						k++;
					}
					i++;
				}
				token[i] = 0;
				key = PKI_Malloc ( len );
				val = PKI_Malloc ( len );
				sscanf(token, "%[^=]=%[^\\]", key, val);

				if (!X509_NAME_add_entry_by_txt(
						(X509_NAME *) ret, key, (int) ctype, 
							(const unsigned char *) val, -1, -1, mrdn)) {

					PKI_ERROR(PKI_ERR_GENERAL, "Cannot Add Key (mrdn=%d) -> %s", mrdn, key);

					err = PKI_ERROR_crypto_get_errdesc();
					PKI_ERROR(PKI_ERR_GENERAL, err);

					free(token);
					free(key);
					free(val);

					return ( NULL );
				};

				free( key );
				free( val );
				free ( token );

				token = NULL;

				if( *pnt != '+' ) {
					pnt++;
				}
				mrdn = 0;

				if( *pnt != 0 ) status = 0;
				continue;
			} else {
				pnt++;
				continue;
			}
		} else if ( status == 4 ) {
			pnt++;
			status = 3;
			continue;
		}
	}

	if( status != 3 ) {
		if( ret ) PKI_X509_NAME_free (ret);
		return (NULL);
	}

	return(ret);
}

/*! \brief Returns 0 if the two names are the same, non-zero otherwise */

int PKI_X509_NAME_cmp ( const PKI_X509_NAME *a, const PKI_X509_NAME *b ) {
	if (!a || !b ) return ( -1 );

	return X509_NAME_cmp ( a, b );
}

/*! \brief Returns a pointer to a duplicate of the passed name */

PKI_X509_NAME *PKI_X509_NAME_dup ( const PKI_X509_NAME *name ) {

	if( !name ) return (NULL);

	return X509_NAME_dup ((PKI_X509_NAME *)name );
}

/*! \brief Adds a new entry to the passed PKI_X509_NAME */

PKI_X509_NAME *PKI_X509_NAME_add ( PKI_X509_NAME *name, const char *entry ) {

	char *type, *val;
	char *my_dup;
	int mrdn = 0;

	if(!name || !entry ) return NULL;
	
	if((my_dup = strdup ( entry )) == NULL ) {
		return NULL;
	}

	type = my_dup;
	if((val = strchr( type+1, '=')) == NULL ) {
		PKI_Free ( my_dup );
		return NULL;
	}

	*val = '\x0';
	val++;

	if ( *type == '+' ) {
		mrdn = -1;
		type++;
	};

	if (!X509_NAME_add_entry_by_txt( name, type, MBSTRING_UTF8,
			(unsigned char *) val, -1, -1, mrdn)) {
		PKI_Free ( my_dup );
		return NULL;
	}

	return name;
}

/*! \brief Returns a char * (utf8) representation of the name */

char *PKI_X509_NAME_get_parsed ( const PKI_X509_NAME *name ) {

	char buf[BUFF_MAX_SIZE];
		// Container for the string name

	char *ret = NULL;
		// Return value

	size_t size = 0;


	// Input check
	if(!name) return (NULL);

	// Let's zeroize the buffer
	memset(buf, 0, sizeof( buf ));

	// Load the oneline name from the X509_NAME
	X509_NAME_oneline((PKI_X509_NAME *)name, buf, sizeof buf);

	// Parse the retrieved string
	size = strlen( buf );
	if( size > 0 ) {
		int i = 0;

		PKI_MEM *mem = NULL;

		if((mem = PKI_MEM_new_null()) == NULL ) {
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			return NULL;
		}

		for ( i = 1; i < size; i++ ) {
			char c;

			c = buf[i];
			switch ( c ) {
				case '/':
					PKI_MEM_add( mem, (const unsigned char *)", ", 2 );
					break;

				case '\\':
					break;

				default:
					PKI_MEM_add( mem, (const unsigned char *)&buf[i], 1 );
			}
		}

		ret = PKI_Malloc(PKI_MEM_get_size(mem) + 1);
		memcpy(ret, PKI_MEM_get_data(mem), PKI_MEM_get_size (mem));
		ret[PKI_MEM_get_size(mem)] = '\x0';

		// Free the PKI_MEM structure
		if (mem) PKI_MEM_free(mem);
	}

	return ret;
}

/*! \brief Returns the digest of a PKI_X509_NAME */

PKI_DIGEST * PKI_X509_NAME_get_digest(const PKI_X509_NAME *name, 
				      const PKI_DIGEST_ALG *alg)
{
	ssize_t size = 0;
	unsigned int ossl_size = 0;

	PKI_DIGEST *ret = NULL;

	if ( !name ) return NULL;
	if ( !alg ) alg = PKI_DIGEST_ALG_DEFAULT;

	if ((ret = PKI_Malloc(sizeof(PKI_DIGEST))) == NULL)
	{
		PKI_log_debug ("Memory Failure");
		return NULL;
	}

	ret->algor = alg;
	size = PKI_DIGEST_get_size(alg);
	if (size <= 0 || (ret->digest = PKI_Malloc((size_t) size)) == NULL)
	{
		PKI_log_debug ("Memory Failure");
		PKI_Free ( ret );
		return NULL;
	}

	if(!X509_NAME_digest(name, alg, ret->digest, &ossl_size)) {
		PKI_log_debug ("Memory Failure");
		PKI_DIGEST_free ( ret );
		return NULL;
	}

	ret->size = (size_t) ossl_size;

	return ret;
}

/*! \brief Returns a NULL terminated list of PKI_X509_NAME_RDN from the name */

PKI_X509_NAME_RDN **PKI_X509_NAME_get_list(const PKI_X509_NAME *name, 
					   PKI_X509_NAME_TYPE filter)
{
	PKI_X509_NAME_RDN ** ret = NULL;

	char *st = NULL;
	char *pnt = NULL;

	int num = 0;
	int i   = 0;
	int cur = 0;

	size_t len = 0;

	if (!name || ((st = PKI_X509_NAME_get_parsed(name)) == NULL)) return NULL;

	pnt = st;
	while (pnt && ((pnt = strchr(pnt, '=')) != NULL))
	{
		num++;
		pnt++;
	}

	len = sizeof(PKI_X509_NAME_RDN *) * (size_t) (num + 1);
	ret = (PKI_X509_NAME_RDN **) PKI_Malloc (len);
	if (!ret)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		PKI_Free ( st );
		return NULL;
	}

	pnt = st;
	while ( (pnt ) && ( i < num ) ) {
		char type_s[256];
		char value_s[1024];

		int rv = 0;
		int my_type = 0;

		PKI_OID *oid = NULL;

		memset( type_s, 0L, sizeof(type_s));
		memset( value_s, 0L, sizeof(value_s));

		rv = sscanf( pnt, "%255[^=]=%1023[^,]", type_s, value_s );

		if (rv != 2 ) {
			PKI_log_debug("Parsing err ? (type_s, value_s)");
			break;
		}

		oid = PKI_OID_get ( type_s );
		if ( oid == NULL ) {
			my_type = PKI_X509_NAME_TYPE_UNKNOWN;
		} else {
			my_type = PKI_OID_get_id( oid );
		}

		if ( filter != PKI_X509_NAME_TYPE_NONE ) {
			if ( my_type != filter ) {
				goto next_step;
			}
		}

		ret[cur] = (PKI_X509_NAME_RDN *)
			PKI_Malloc ( sizeof( PKI_X509_NAME_RDN ));

		ret[cur]->type  = (PKI_X509_NAME_TYPE) my_type;
		ret[cur]->value = strdup( value_s );

		cur++;

next_step:
		if((pnt = strchr( pnt, ',')) == NULL ) break;

		pnt++;
		while( pnt && *pnt == ' ' ) pnt++;

		i++;
	}

	PKI_Free ( st );

	return ret;
};

/*! \brief Frees the memory associated with a PKI_X509_NAME_RDN data st */

void PKI_X509_NAME_list_free ( PKI_X509_NAME_RDN **list ) {

	PKI_X509_NAME_RDN **curr = NULL;

	if ( !list ) return;

	curr = list;
	while ( *curr ) {
		if ( (*curr)->value ) PKI_Free ( (*curr)->value );
		if ( *curr ) PKI_Free ( *curr );
		curr++;
	}
	PKI_Free ( list );
	return;
}

/*! \brief Returns the value (char *) of an RDN */

char *PKI_X509_NAME_RDN_value(PKI_X509_NAME_RDN *rdn ) {
	if (!rdn) return ( NULL);

	return rdn->value;
}

/*! \brief Returns the PKI_ID of a type of an RDN */

PKI_X509_NAME_TYPE PKI_X509_NAME_RDN_type_id ( const PKI_X509_NAME_RDN *rdn ) {
	if (!rdn ) return ( PKI_X509_NAME_TYPE_UNKNOWN );

	return rdn->type;
}

/*! \brief Returns the text representation of the type of an RDN */

const char *PKI_X509_NAME_RDN_type_text ( const PKI_X509_NAME_RDN *rdn ) {

	PKI_OID *oid = NULL;

	if (!rdn) return ( NULL );

	if (( oid = PKI_OID_new_id((int)rdn->type)) == NULL) {
		return NULL;
	}

	return OBJ_nid2sn((int)rdn->type);
}

/*! \brief Returns the description of the type of an RDN */

const char *PKI_X509_NAME_RDN_type_descr ( const PKI_X509_NAME_RDN *rdn ) {

        PKI_OID *oid = NULL;

        if (!rdn) return ( NULL );

        if ((oid = PKI_OID_new_id((int)rdn->type )) == NULL) {
          return NULL;
        }

        return PKI_OID_get_descr(oid);
}

