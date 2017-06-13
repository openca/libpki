/*
 * OpenCA Project
 * by Massimiliano Pala (madwolf@openca.org)
 * OpenCA project 1999-2008
 *
 * Copyright (c) 1999-2008 The OpenCA Project.  All rights reserved.
 *
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <libpki/pki.h>
 
#define BUFF_MAX_SIZE	2048

/*! \brief Returns a PKI_MEM_STACK object filled from a file descriptor
 *
 * This function returns a PKI_MEM_STACK object (actually filled with only
 * one object in the stack), with the data retrieved from the URL specified
 * as input. This function will accept only URL with URI_PROTOCOL_FD as
 * its protocol.
 */

typedef struct uri_protocol {
	int	num;
	char   *string;
} URI_PROTOCOL;

URI_PROTOCOL proto_list[] = {
	{ URI_PROTO_FILE, "file" },
	{ URI_PROTO_LDAP, "ldap" },
	{ URI_PROTO_HTTP, "http" },
	{ URI_PROTO_HTTPS, "https" },
	{ URI_PROTO_FTP, "ftp" },
	{ URI_PROTO_ID, "id" },
	{ URI_PROTO_FD, "fd" },
	{ URI_PROTO_MYSQL, "mysql" },
	{ URI_PROTO_PG, "pg"},
	{ URI_PROTO_PKCS11, "pkcs11" },
	{ URI_PROTO_SOCK, "sock" },
	{ URI_PROTO_SOCK, "dns" },
	{ 0, NULL }
};

/* This is required because of strange behavior of htons() and (int)
 * conversion - when treating warning as errors, it would block the
 * compilation */
#pragma GCC diagnostic ignored "-Wconversion" 
char * URL_get_local_addr ( void ) {
	struct sockaddr_in addr;
	struct sockaddr_in sa;
	socklen_t sa_len;

	char * ret = NULL;

	int s  = socket(AF_INET, SOCK_DGRAM, 0);


	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family      = AF_INET;
	inet_aton("128.0.0.1", &addr.sin_addr);

	addr.sin_port        = htons(80);

	if((connect(s, (struct sockaddr *) &addr, sizeof(addr))) != 0 ) {
		return(NULL);
	}

	sa_len = sizeof(sa);
	if((getsockname( s, (struct sockaddr *) &sa, &sa_len)) != 0 ) {
		return ( NULL );
	}

	ret = strdup( inet_ntoa(sa.sin_addr) );

	return ( ret );
}
#pragma GCC diagnostic warning "-Wconversion"

const char *URL_proto_to_string ( URI_PROTO proto ) {

	URI_PROTOCOL *pnt = NULL;

	pnt = &proto_list[0];
	while ( pnt != NULL ) {
		if( pnt->num == proto ) {
			break;
		}
		pnt++;
	}

	if (pnt == NULL ) {
		return ( NULL );
	}

	return ( (const char * ) pnt->string );
}

PKI_MEM_STACK *URL_get_data_fd( URL *url, ssize_t size ) {

	PKI_MEM_STACK * ret = NULL;
	PKI_MEM * obj = NULL;

	ssize_t file_size = 0;
	// ssize_t max_size = 0;

	char * buff = NULL;
	ssize_t buff_size = 0;

	int fd = 1;

	if (!url || url->port < 0) 
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return ( NULL );
	}

	fd = url->port;

	// if( size == 0 ) max_size = LONG_MAX - 1;

	if((ret = PKI_STACK_MEM_new()) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return( NULL );
	}

	if ((obj = PKI_MEM_new_null()) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		PKI_STACK_MEM_free(ret);
		return NULL;
	}

	if ((buff = PKI_Malloc(BUFF_MAX_SIZE)) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		PKI_STACK_MEM_free(ret);
		PKI_MEM_free (obj);
		return NULL;
	}

	do {
		buff_size = _Read(fd, buff, BUFF_MAX_SIZE);

		if (buff_size > 0 )
		{
			if ((size > 0) && (file_size + buff_size > size))
			{
				buff_size = size - file_size;
				PKI_MEM_add( obj, buff, (size_t) buff_size );
				break;
			}
			else
			{
				PKI_MEM_add( obj, buff, (size_t) buff_size );
				file_size += buff_size;
			}
		}
	} while ( buff_size > 0 );

	PKI_STACK_MEM_push( ret, obj );

	/* Now we free the buff */
	if( buff ) PKI_Free ( buff );

	return( ret );
}

/*! \brief Returns a PKI_MEM_STACK object filled from a file
 *
 * This function returns a PKI_MEM_STACK object (actually filled with only
 * one object in the stack), with the data retrieved from the URL specified
 * as input. This function will accept only URL with URI_PROTOCOL_FILE as
 * its protocol.
 */

PKI_MEM_STACK *URL_get_data_file( URL *url, ssize_t size ) {

	PKI_MEM_STACK * ret = NULL;
	PKI_MEM * obj = NULL;
	off_t file_size = 0;
	int fd = 0;

	if( !url ) return (NULL);
	if( url->proto != URI_PROTO_FILE ) return (NULL);

	if((fd = open( url->addr, O_RDONLY)) == -1 ) {
		return (NULL);
	}

	if( size == 0 ) size = LONG_MAX - 1;

	if((ret = PKI_STACK_MEM_new()) == NULL ) {
		return( NULL );
	}
	if((obj = PKI_MEM_new_null()) == NULL ) {
		PKI_STACK_MEM_free(ret);
		return ( NULL );
	}

	lseek( fd, 0, SEEK_END);
	file_size = lseek( fd, 0, SEEK_CUR);

	if( file_size > size ) file_size = size;

	lseek( fd, 0, SEEK_SET);

	PKI_MEM_grow( obj, (size_t) file_size );
	if((read( fd, obj->data, (size_t) file_size)) == -1 ) {
		/* Error ?!?!? */
		PKI_MEM_free( obj );
		PKI_STACK_MEM_free ( ret );
		ret = NULL;
	} else {
		obj->size = (size_t) file_size;
	}
	close( fd );

	PKI_STACK_MEM_push( ret, obj );

	return( ret );
}

/*!
 * \brief Returns a PKI_MEM_STACK filled with the data from the URL string
 *
 * Returns a PKI_MEM_STACK object filled with the data retrieved from
 * the URL that is passed as input. This is the most general function
 * provided by LibPKI that allows to retrieve an object from many different
 * sources.
 *
 * In case of failure NULL is returned.
 */

PKI_MEM_STACK *URL_get_data(const char *url_s, int timeout, 
				ssize_t size, PKI_SSL *ssl ) {

	URL *url = NULL;
	PKI_MEM_STACK *ret = NULL;

	if( !url_s ) return (NULL);
	if(( url = URL_new(url_s)) == NULL ) {
		return (NULL);
	}

	ret = URL_get_data_url( url, timeout, size, ssl );

	if( url ) URL_free ( url );
	return ret;
}

/*!
 * \brief Returns a PKI_MEM_STACK filled with data from the passed URL object
 *
 * Returns a PKI_MEM_STACK object filled with the data retrieved from
 * the URL that is passed as input. This function is very similar to the
 * URL_get_data (). Use this function when you already have the URL object
 * of your target data.
 *
 * In case of failure NULL is returned.
 *
 * Currently supported protocols are: URI_PROTO_FD, URI_PROTO_FILE,
 * URI_PROTO_HTTP, URI_PROTO_LDAP, URI_PROTO_MYSQL, URI_PROTO_PG,
 * URI_PROTO_PKCS11, URI_PROTO_ID.
 */

PKI_MEM_STACK *URL_get_data_url(const URL *url, int timeout, 
				ssize_t size, PKI_SSL *ssl ) {

	PKI_MEM_STACK * ret = NULL;

	if( !url ) {
		return ( NULL );
	}

	switch( url->proto ) {
		case URI_PROTO_FD:
			ret = URL_get_data_fd( url, size );
			break;
		case URI_PROTO_FILE:
			ret = URL_get_data_file( url, size );
			break;
		case URI_PROTO_HTTP:
		case URI_PROTO_HTTPS:
			PKI_HTTP_GET_data_url( url, timeout, (size_t) size,
				&ret, ssl );
			break;
#ifdef HAVE_LDAP
		case URI_PROTO_LDAP:
			ret = URL_get_data_ldap_url( url, timeout, size );
			break;
#endif
#ifdef HAVE_MYSQL
		case URI_PROTO_MYSQL:
			ret = URL_get_data_mysql_url( url, size );
			break;
#endif
#ifdef HAVE_PG
		case URI_PROTO_PG:
			ret = URL_get_data_pg_url( url, size );
			break;
#endif
#ifdef HAVE_LIBRESOLV
		case URI_PROTO_DNS:
			ret = URL_get_data_dns_url( url, size );
			break;
#endif
		case URI_PROTO_PKCS11:
			ret = URL_get_data_pkcs11_url( url, size );
			break;
		case URI_PROTO_ID:
		case URI_PROTO_FTP:
		default:
			ret = NULL;
			break;
	}

	return ( ret );
}

/*!
 * \brief Returns a PKI_MEM_STACK filled with data from a PKI_SOCKET 
 *
 * Returns a PKI_MEM_STACK object filled with the data retrieved from
 * a connected PKI_SOCKET. This function is very similar to the
 * URL_get_data (). Use this function when you already have the URL object
 * of your target data.
 *
 * In case of failure NULL is returned.
 *
 * Currently supported protocols are: URI_PROTO_FD, URI_PROTO_FILE,
 * URI_PROTO_HTTP, URI_PROTO_LDAP, URI_PROTO_MYSQL, URI_PROTO_PG,
 * URI_PROTO_PKCS11, URI_PROTO_ID.
 */

PKI_MEM_STACK *URL_get_data_socket ( PKI_SOCKET *sock, int timeout, 
				ssize_t size ) {

	PKI_MEM_STACK * ret = NULL;

	if (size < 0) size = 0;

	if( !sock || !sock->url ) return NULL;

	switch( sock->url->proto ) {
		case URI_PROTO_FD:
			// ret = URL_get_data_fd( url, size );
			break;
		case URI_PROTO_FILE:
			// ret = URL_get_data_file( url, size );
			break;
		case URI_PROTO_HTTP:
		case URI_PROTO_HTTPS:
			PKI_HTTP_GET_data_socket( sock, timeout, (size_t) size,
				&ret );
			break;
#ifdef HAVE_LDAP
		case URI_PROTO_LDAP:
			// ret = URL_get_data_ldap_url( url, timeout, size );
			break;
#endif
#ifdef HAVE_MYSQL
		case URI_PROTO_MYSQL:
			// ret = URL_get_data_mysql_url( url, size );
			break;
#endif
#ifdef HAVE_PG
		case URI_PROTO_PG:
			// ret = URL_get_data_pg_url( url, size );
			break;
#endif
		case URI_PROTO_PKCS11:
			// ret = URL_get_data_pkcs11_url( url, size );
			break;
		case URI_PROTO_ID:
		case URI_PROTO_FTP:
		case URI_PROTO_DNS:
		default:
			ret = NULL;
			break;
	}

	return ( ret );
}

/*! \brief Sends/Writes a PKI_MEM object into a URL passed as a string
 *
 * This function sends (or writes) the content of a PKI_MEM object into
 * a specific URL that is passed as a string. For a list of valid URL
 * protocols, please refer to the URL_new() function.
 *
 * In case of failure PKI_ERR is returned, otherwise PKI_OK is.
 *
 * Currently supported protocols are: URI_PROTO_FD, URI_PROTO_FILE,
 * URI_PROTO_MYSQL, URI_PROTO_PG.
 */

int URL_put_data ( char *url_s, PKI_MEM *data, char *contType, 
		PKI_MEM_STACK **ret_sk, int timeout, ssize_t max_size,
			PKI_SSL *ssl ) {

	URL *url = NULL;
	int ret = 0;

	if( !url_s || !data ) {
		return (PKI_ERR);
	}

	if(( url = URL_new(url_s)) == NULL ) {
		return (PKI_ERR);
	}

	ret = URL_put_data_url( url, data, contType, ret_sk, 
					timeout, max_size, ssl );

	if( url ) URL_free ( url );

	return( ret );
}

int URL_put_data_fd ( URL *url, PKI_MEM *data ) {

	int fd = 0;

	if( !url || !data || url->port < 1 ) return ( PKI_ERR );

	fd = url->port;

	if(_Write( fd, data->data, data->size ) < 0 ) {
		PKI_ERROR(PKI_ERR_GENERAL, strerror(errno));
		return ( PKI_ERR );
	}

	return ( PKI_OK );
}

int URL_put_data_file ( URL *url, PKI_MEM *data ) {

	int fd = 0;

	if( !url || !data || !url->addr ) return ( PKI_ERR );

	if(( fd = open( url->addr, O_RDWR|O_CREAT|O_TRUNC, 
						S_IRUSR|S_IWUSR )) == -1 ) {
		return ( PKI_ERR );
	}

	if(_Write( fd, data->data, data->size ) < 0 ) {
		close (fd);
		return ( PKI_ERR );
	}

	close ( fd );

	return ( PKI_OK );
	
}

int URL_put_data_url (URL *url, PKI_MEM *data, char *contType, 
		PKI_MEM_STACK **ret_sk, int timeout, ssize_t max_size,
			PKI_SSL *ssl ) {

	int ret = PKI_OK;

	if (max_size < 0) max_size = 0;

	if( !url || !data ) {
		return ( PKI_ERR );
	}

	switch( url->proto ) {
		case URI_PROTO_FD:
			ret = URL_put_data_fd( url, data );
			break;
		case URI_PROTO_FILE:
			ret = URL_put_data_file( url, data );
			break;
		case URI_PROTO_HTTP:
		case URI_PROTO_HTTPS:
		 	ret = PKI_HTTP_POST_data_url (url, (char *) data->data,
				(size_t) data->size, contType, timeout, 
					(size_t) max_size, ret_sk, ssl );
			break;
		// case URI_PROTO_LDAP:
		// 	ret = URL_put_data_ldap_url( url );
		// 	break;
#ifdef HAVE_MYSQL
		case URI_PROTO_MYSQL:
			ret = URL_put_data_mysql_url( url, data );
			break;
#endif
#ifdef HAVE_PG
		case URI_PROTO_PG:
			ret = URL_put_data_pg_url( url, data );
			break;
#endif
		// case URI_PROTO_PKCS11:
		// 	ret = URL_put_data_pkcs11_url( url, size );
		// 	break;
		case URI_PROTO_FTP:
		case URI_PROTO_DNS:
		default:
			ret = PKI_ERR;
			break;
	}

	return ( ret );
}


int URL_put_data_socket (PKI_SOCKET *sock, PKI_MEM *data, char *contType, 
		PKI_MEM_STACK **ret_sk, int timeout, ssize_t max_size ) {

	int ret = PKI_OK;

	if (max_size < 0) max_size = 0;

	if( !sock || !sock->url ) {
		return ( PKI_ERR );
	}

	switch( sock->url->proto ) {
		case URI_PROTO_FD:
			// ret = URL_put_data_fd( url, data );
			break;
		case URI_PROTO_FILE:
			// ret = URL_put_data_file( url, data );
			break;
		case URI_PROTO_HTTP:
		case URI_PROTO_HTTPS:
		 	ret = PKI_HTTP_POST_data_socket(sock, 
				(char *) data->data, data->size, 
				contType, timeout, (size_t) max_size, ret_sk);
			break;
		// case URI_PROTO_LDAP:
		// 	ret = URL_put_data_ldap_url( url );
		// 	break;
#ifdef HAVE_MYSQL
		case URI_PROTO_MYSQL:
			// ret = URL_put_data_mysql_url( url, data );
			break;
#endif
#ifdef HAVE_PG
		case URI_PROTO_PG:
			// ret = URL_put_data_pg_url( url, data );
			break;
#endif
		// case URI_PROTO_PKCS11:
		// 	ret = URL_put_data_pkcs11_url( url, size );
		// 	break;
		case URI_PROTO_FTP:
		case URI_PROTO_DNS:
		default:
			ret = PKI_ERR;
			break;
	}

	return ( ret );
}

/*!
 * \brief Returns the text representation of a URL
 */

char *URL_get_parsed ( URL *url )
{
	if ( !url || !url->url_s ) return NULL;

	return url->url_s;
}


/* !\brief Returns a URL data structure from the input string
 *
 * This function parses the string passed as input and generates a new URL
 * object. In case of an error in parsing the URL a NULL pointer is returned.
 *
 * Currently supported protocols are: fd:// (URI_PROTO_FD), 
 * file:// (URI_PROTO_FILE), http:// (URI_PROTO_HTTP), ldap:// (URI_PROTO_LDAP),
 * mysql:// (URI_PROTO_MYSQL), pg:// (URI_PROTO_PG), mysql:// (URI_PROTO_MYSQL),
 * pkcs11:// (URI_PROTO_PKCS11), dns://(URI_PROTO_DNS), socket://(URI_PROTO_SOCKET)
 */

URL *URL_new ( char *url_s ) {

	URL *ret = NULL;
	char *tmp_s = NULL;
	char *tmp_s2 = NULL;
	char *tmp_s3 = NULL;
	char *tmp_s4 = NULL;
	char *is_alloc = NULL;
	size_t len = 0;

	if (!url_s)
	{
		is_alloc = url_s = strdup("stdin");
	}

	ret = (URL *) PKI_Malloc ( sizeof( URL ));
	if(ret == 0) 
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		goto err;
	}
	memset( ret, 0, sizeof(URL) );

	if ((ret->url_s = get_env_string(url_s)) == NULL)
	{
		// if( ret ) URL_free ( ret );
		// return ( NULL );
		goto err;
	}

	if (!ret->url_s)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		// if( ret ) URL_free ( ret );
		// return ( NULL );
		goto err;
	}

	if (strncmp_nocase(ret->url_s, "stdin", 5) == 0)
	{
		ret->proto = URI_PROTO_FD;
		ret->addr = strdup("stdin");
		ret->port = fileno(stdin);
		ret->object_num = 0;
	}
	else if (strncmp_nocase(ret->url_s, "stdout", 6) == 0)
	{
		ret->proto = URI_PROTO_FD;
		ret->addr = strdup("stdout");
		ret->port = fileno(stdout);
		ret->object_num = 0;
	}
	else if (strncmp_nocase(ret->url_s, "stderr", 6) == 0)
	{
		ret->proto = URI_PROTO_FD;
		ret->addr = strdup("stderr");
		ret->port = fileno(stderr);
		ret->object_num = 0;
	}
	else if( strncmp("ldap://", ret->url_s, 6 ) == 0)
	{
		ret->proto = URI_PROTO_LDAP;
		ret->port = DEFAULT_LDAP_PORT;

		tmp_s = &ret->url_s[7];

		if((tmp_s3 = strchr(tmp_s, '@')) != NULL ) {
			tmp_s4 = strchr(tmp_s, '/');
			if( tmp_s4 && tmp_s3 < tmp_s4 ) {
				tmp_s2 = strchr( tmp_s, ':' );

				if ( !tmp_s2 || (tmp_s3 < tmp_s2))
				{
					PKI_ERROR(PKI_ERR_URI_PARSE, NULL);
					// return NULL;
					goto err;
				}
				len = (size_t) ( tmp_s2 - tmp_s );
				ret->usr = (char *) malloc (len+1);
				memset( ret->usr, 0, len+1);
				strncpy( ret->usr, tmp_s, len);
				ret->usr[len] = '\x0';
			
				tmp_s = tmp_s2+1;
				tmp_s2 = strchr( tmp_s,'@');

				len = (size_t) ( tmp_s2 - tmp_s );
				ret->pwd = (char *) malloc (len+1);
				memset( ret->pwd, 0, len+1);
				strncpy( ret->pwd, tmp_s, len);
				ret->pwd[len] = '\x0';

				tmp_s = tmp_s2+1;
			}
		}

		// IPv6 Hex Address Parsing
		if( (*tmp_s == '[') && 
				((tmp_s2 = strchr( tmp_s, ']' )) != NULL )) {

			len = (size_t) ( tmp_s2 - tmp_s );
			ret->addr = ( char *) malloc ( len );
			memset ( ret->addr, 0, len );

			strncpy( ret->addr, tmp_s + 1, len-1 );
			ret->addr[len-1] = '\x0';

			tmp_s = tmp_s2 + 1;
			if ( *tmp_s == ':' ) {
				ret->port = atoi ( tmp_s + 1 );
			}

			if( (tmp_s2 = strchr( tmp_s, '/' )) != NULL ) {
				tmp_s =  tmp_s2;
			} else {
				tmp_s = &ret->url_s[7];
			}
		} else if( strchr( tmp_s, ':' )) {
			tmp_s2 = strchr(tmp_s,':');

			len = (size_t) ( tmp_s2 - tmp_s );
			ret->addr = (char *) malloc (len+1);
			memset( ret->addr, 0, len+1 );

			strncpy( ret->addr, tmp_s, len);
			ret->addr[len] = '\x0';

			tmp_s = tmp_s2+1;
			ret->port = atoi( tmp_s );
			if( ret->port == 0 ) {
				/* Error in parsing the port number! */
				// URL_free ( ret );
				PKI_ERROR(PKI_ERR_URI_PARSE, NULL);
				// return(NULL);
				goto err;
			}

			if( (tmp_s2 = strchr( tmp_s, '/' )) != NULL ) {
				tmp_s =  tmp_s2;
			} else {
				tmp_s = &ret->url_s[7];
			}
		}

		if( (tmp_s2 = strchr( tmp_s, '/' )) != NULL ) {
			char *tmp_attrs = NULL;
			tmp_s2++;

			if((tmp_attrs = strchr( tmp_s, '?' )) != NULL) {
				len = strlen( tmp_attrs );
				ret->attrs = (char *) malloc ( len );
				memset( ret->attrs, 0, len );
				memcpy( ret->attrs, tmp_attrs + 1, len);
				len = (size_t) ( tmp_attrs - tmp_s2 );

				ret->path = (char *) malloc ( len +1);
				memset( ret->path, 0, len +1);
				memcpy( ret->path, tmp_s2, len);

				if( !ret->addr ) {
					len = (size_t) (tmp_s2 - tmp_s - 1);
					ret->addr = (char *) malloc (len+1);
					memset( ret->addr, 0, len+1);
					strncpy( ret->addr, tmp_s, len);
					ret->addr[len] = '\x0';
				}
			} else {
				if( !ret->addr ) {
					len = (size_t) ( tmp_s2 - tmp_s );
					ret->addr = (char *) malloc (len+1);
					memset( ret->addr, 0, len+1);
					strncpy( ret->addr, tmp_s, len);
					ret->addr[len] = '\x0';
				}

				tmp_s = tmp_s2;
				ret->path = strdup( tmp_s );
			}
		} else {
			if( !ret->addr )
				ret->addr = strdup( tmp_s );
			ret->path = strdup("/");
		}

	}
	else if (strncmp("mysql://", ret->url_s, 8) == 0)
	{
		ret->proto = URI_PROTO_MYSQL;
		ret->port = DEFAULT_MYSQL_PORT;

		tmp_s = &ret->url_s[8];

		if((tmp_s3 = strchr(tmp_s, '@')) != NULL ) {
			tmp_s4 = strchr(tmp_s, '/');
			if( tmp_s4 && tmp_s3 < tmp_s4 ) {
				tmp_s2 = strchr( tmp_s, ':' );

				if( !tmp_s2 || (tmp_s3 < tmp_s2)) {
					PKI_ERROR(PKI_ERR_URI_PARSE, NULL);
					// return (NULL);
					goto err;
				}
				len = (size_t) ( tmp_s2 - tmp_s );
				ret->usr = (char *) malloc (len+1);
				memset( ret->usr, 0, len+1);
				strncpy( ret->usr, tmp_s, len);
				ret->usr[len] = '\x0';
			
				tmp_s = tmp_s2+1;
				tmp_s2 = strchr( tmp_s,'@');

				len = (size_t) ( tmp_s2 - tmp_s );
				ret->pwd = (char *) malloc (len+1);
				memset( ret->pwd, 0, len+1);
				strncpy( ret->pwd, tmp_s, len);
				ret->pwd[len] = '\x0';

				tmp_s = tmp_s2+1;
			}
		}

		// IPv6 Hex Address Parsing
		if( (*tmp_s == '[') && 
				((tmp_s2 = strchr( tmp_s, ']' )) != NULL )) {

			len = (size_t) ( tmp_s2 - tmp_s );
			ret->addr = ( char *) malloc ( len );
			memset ( ret->addr, 0, len );

			strncpy( ret->addr, tmp_s + 1, len-1 );
			ret->addr[len-1] = '\x0';

			tmp_s = tmp_s2 + 1;
			if ( *tmp_s == ':' ) {
				ret->port = atoi ( tmp_s + 1 );
			}

			if( (tmp_s2 = strchr( tmp_s, '/' )) != NULL ) {
				tmp_s =  tmp_s2;
			} else {
				tmp_s = &ret->url_s[7];
			}
		} else if( strchr( tmp_s, ':' )) {
			tmp_s2 = strchr(tmp_s,':');

			len = (size_t) ( tmp_s2 - tmp_s );
			ret->addr = (char *) malloc (len+1);
			memset( ret->addr, 0, len+1 );

			strncpy( ret->addr, tmp_s, len);
			ret->addr[len] = '\x0';

			tmp_s = tmp_s2+1;
			ret->port = atoi( tmp_s );
			if( ret->port == 0 ) {
				/* Error in parsing the port number! */
				// URL_free ( ret );
				PKI_ERROR(PKI_ERR_URI_PARSE, NULL);
				// return(NULL);
				goto err;
			}

			if( (tmp_s2 = strchr( tmp_s, '/' )) != NULL ) {
				tmp_s =  tmp_s2;
			} else {
				tmp_s = &ret->url_s[7];
			}
		}

		if( (tmp_s2 = strchr( tmp_s, '/' )) != NULL ) {
			char *tmp_attrs = NULL;
			tmp_s2++;

			if((tmp_attrs = strchr( tmp_s, '?' )) != NULL) {
				len = strlen( tmp_attrs );
				ret->attrs = (char *) malloc ( len );
				memset( ret->attrs, 0, len );
				memcpy( ret->attrs, tmp_attrs + 1, len);
				/*
				while( ((tmp_s3 = 
					strchr(tmp_s2,'(')) != NULL) && 
							(tmp_s3 < tmp_s4) ) {
					char *tmp_s5 = NULL;
					char *tmp_s6 = NULL;

					if( (tmp_s5 = strchr(tmp_s3, ')')) 
								== NULL) {
						URL_free( ret );
						return(NULL);
					}
					tmp_s3++;
					tmp_s6 = strchr(tmp_s3, '=');
					if( tmp_s6 > tmp_s5 ) {
						URL_free( ret );
						return(NULL);
					}
					tmp_s6 = (char *) malloc ( tmp_s5 - tmp_s3+1);
					memset( tmp_s6, 0, tmp_s5 - tmp_s3 + 1);
					memcpy( tmp_s6, tmp_s3, tmp_s5 - tmp_s3);
					PKI_STACK_push( ret->attrs, tmp_s6 );

					tmp_s2 = tmp_s3;
				}
				tmp_s = tmp_s4;
				*/
				len = (size_t) (tmp_attrs - tmp_s2);
				ret->path = (char *) PKI_Malloc(len+1);
				memcpy(ret->path, tmp_s2, len);
				ret->path[len] = 0; // Safety

				if( !ret->addr )
				{
					len = (size_t) (tmp_s2 - tmp_s - 1);
					ret->addr = (char *) PKI_Malloc (len+1);
					strncpy(ret->addr, tmp_s, len);
					ret->addr[len] = '\x0';
				}
			} 
			else 
			{
				if(!ret->addr)
				{
					len = (size_t) (tmp_s2 - tmp_s - 1);
					ret->addr = (char *) PKI_Malloc (len+1);
					strncpy(ret->addr, tmp_s, len);
					ret->addr[len] = '\x0';
				}

				tmp_s = tmp_s2;
				ret->path = strdup( tmp_s );
			}
		} 
		else if( !ret->addr )
		{
			ret->addr = strdup( tmp_s );
			ret->path = strdup("/");
		}
	}
	else if( strncmp("pg://", ret->url_s, 5 ) == 0)
	{
		ret->proto = URI_PROTO_PG;
		ret->port = DEFAULT_PG_PORT;

		tmp_s = &ret->url_s[5];

		if((tmp_s3 = strchr(tmp_s, '@')) != NULL ) {
			tmp_s4 = strchr(tmp_s, '/');
			if( tmp_s4 && tmp_s3 < tmp_s4 ) {
				tmp_s2 = strchr( tmp_s, ':' );

				if( !tmp_s2 || (tmp_s3 < tmp_s2)) {
					PKI_ERROR(PKI_ERR_URI_PARSE, NULL);
					// return (NULL);
					goto err;
				}
				len = (size_t) ( tmp_s2 - tmp_s );
				ret->usr = (char *) malloc (len+1);
				memset( ret->usr, 0, len+1);
				strncpy( ret->usr, tmp_s, len);
				ret->usr[len] = '\x0';
			
				tmp_s = tmp_s2+1;
				tmp_s2 = strchr( tmp_s,'@');

				len = (size_t) ( tmp_s2 - tmp_s );
				ret->pwd = (char *) malloc (len+1);
				memset( ret->pwd, 0, len+1);
				strncpy( ret->pwd, tmp_s, len);
				ret->pwd[len] = '\x0';

				tmp_s = tmp_s2+1;
			}
		}

		// IPv6 Hex Address Parsing
		if( (*tmp_s == '[') && 
				((tmp_s2 = strchr( tmp_s, ']' )) != NULL )) {

			len = (size_t) ( tmp_s2 - tmp_s );
			ret->addr = ( char *) malloc ( len );
			memset ( ret->addr, 0, len );

			strncpy( ret->addr, tmp_s + 1, len-1 );
			ret->addr[len-1] = '\x0';

			tmp_s = tmp_s2 + 1;
			if ( *tmp_s == ':' ) {
				ret->port = atoi ( tmp_s + 1 );
			}

			if( (tmp_s2 = strchr( tmp_s, '/' )) != NULL ) {
				tmp_s =  tmp_s2;
			} else {
				tmp_s = &ret->url_s[7];
			}
		} else if( strchr( tmp_s, ':' )) {
			tmp_s2 = strchr(tmp_s,':');

			len = (size_t) ( tmp_s2 - tmp_s );
			ret->addr = (char *) malloc (len+1);
			memset( ret->addr, 0, len+1 );

			strncpy( ret->addr, tmp_s, len);
			ret->addr[len] = '\x0';

			tmp_s = tmp_s2+1;
			ret->port = atoi( tmp_s );
			if( ret->port == 0 ) {
				/* Error in parsing the port number! */
				// URL_free ( ret );
				PKI_ERROR(PKI_ERR_URI_PARSE, NULL);
				// return(NULL);
				goto err;
			}

			if( (tmp_s2 = strchr( tmp_s, '/' )) != NULL ) {
				tmp_s =  tmp_s2;
			} else {
				tmp_s = &ret->url_s[7];
			}
		}

		if( (tmp_s2 = strchr( tmp_s, '/' )) != NULL ) {
			char *tmp_attrs = NULL;
			tmp_s2++;

			if((tmp_attrs = strchr( tmp_s, '?' )) != NULL) {
				len = strlen( tmp_attrs );
				ret->attrs = (char *) malloc ( len );
				memset( ret->attrs, 0, len );
				memcpy( ret->attrs, tmp_attrs + 1, len);
				/*
				while( ((tmp_s3 = 
					strchr(tmp_s2,'(')) != NULL) && 
							(tmp_s3 < tmp_s4) ) {
					char *tmp_s5 = NULL;
					char *tmp_s6 = NULL;

					if( (tmp_s5 = strchr(tmp_s3, ')')) 
								== NULL) {
						URL_free( ret );
						return(NULL);
					}
					tmp_s3++;
					tmp_s6 = strchr(tmp_s3, '=');
					if( tmp_s6 > tmp_s5 ) {
						URL_free( ret );
						return(NULL);
					}
					tmp_s6 = (char *) malloc ( tmp_s5 - tmp_s3+1);
					memset( tmp_s6, 0, tmp_s5 - tmp_s3 + 1);
					memcpy( tmp_s6, tmp_s3, tmp_s5 - tmp_s3);
					PKI_STACK_push( ret->attrs, tmp_s6 );

					tmp_s2 = tmp_s3;
				}
				tmp_s = tmp_s4;
				*/
				len = (size_t) (tmp_attrs - tmp_s2);
				ret->path = (char *) malloc ( len );
				memset( ret->path, 0, len);
				memcpy( ret->path, tmp_s2, len - 1);

				if( !ret->addr ) {
					len = (size_t) (tmp_s2 - tmp_s - 1);
					ret->addr = (char *) malloc (len+1);
					memset( ret->addr, 0, len+1);
					strncpy( ret->addr, tmp_s, len);
					ret->addr[len] = '\x0';
				}
			} else {
				if( !ret->addr ) {
					len = (size_t) (tmp_s2 - tmp_s);
					ret->addr = (char *) malloc (len+1);
					memset( ret->addr, 0, len+1);
					strncpy( ret->addr, tmp_s, len);
					ret->addr[len] = '\x0';
				}

				tmp_s = tmp_s2;
				ret->path = strdup( tmp_s );
			}
		} else {
			if( !ret->addr )
				ret->addr = strdup( tmp_s );
			ret->path = strdup("/");
		}
	}
	else if (strncmp( "file://", ret->url_s, 6 ) == 0)
	{
		char *tmp_s = NULL;
		char *tmp_s2 = NULL;

		ret->port = -1;
		ret->proto = URI_PROTO_FILE;

		tmp_s = &ret->url_s[7];
		len = strlen(tmp_s);

		if( len > 0 ) {
			if((tmp_s2 = strstr(tmp_s, "#" )) != NULL ) {
				*tmp_s2 = 0x0;
				tmp_s2++;
				if( tmp_s2 ) {
					ret->object_num = atoi( tmp_s2 );
				}
				len = strlen( tmp_s );
			}
			ret->addr = (char *) malloc ( len + 1 );
			memset( ret->addr, 0, len + 1 );
			strncpy( ret->addr, tmp_s, len );
		} else {
			ret->addr = strdup("");
		}

	}
	else if (strncmp( "fd://", ret->url_s, 5 ) == 0)
	{
		char *tmp_s = NULL;
		char *tmp_s2 = NULL;

		ret->port = 0;
		ret->proto = URI_PROTO_FD;
		ret->object_num = 0;

		tmp_s = &ret->url_s[5];
		len = strlen( tmp_s );

		if( len > 0 ) {
			if((tmp_s2 = strstr(tmp_s, "#" )) != NULL ) {
				*tmp_s2 = 0x0;
				tmp_s2++;
				if( tmp_s2 ) {
					ret->object_num = atoi( tmp_s2 );
				}
				len = strlen( tmp_s );
			}

			ret->addr = (char *) malloc ( len + 1 );
			memset( ret->addr, 0, len + 1 );
			strncpy( ret->addr, tmp_s, len );
			ret->port =  atoi( ret->addr );
		} else {
			ret->addr = strdup("0");
		}

	}
	else if (strncmp( "id://", ret->url_s, 5 ) == 0)
	{
		char *tmp_s = NULL;
		char *tmp_s2 = NULL;

		ret->port = -1;
		ret->proto = URI_PROTO_ID;

		tmp_s = &ret->url_s[5];
		len = strlen( tmp_s );

		if(( tmp_s2 = strstr(tmp_s, "/" )) != NULL ) {

			if((len = (size_t)(tmp_s2 - tmp_s)) > 0 ) {
				ret->addr = PKI_Malloc( len + 1);
				strncpy( ret->addr, tmp_s, len );
			} else {
				ret->addr = strdup("");
			};

			tmp_s = tmp_s2 + 1;

			if((tmp_s2 = strstr(tmp_s, "#" )) != NULL ) {
				*tmp_s2 = 0x0;
				tmp_s2++;
				if( tmp_s2 ) {
					ret->object_num = atoi( tmp_s2 );
				}
			}

			if((len = strlen( tmp_s )) > 0 ) {
				ret->path = PKI_Malloc( len + 1 );
				strncpy( ret->path, tmp_s, len );
			}
		} else {
			len = strlen(tmp_s);

			if( len > 0 ) {
				if((tmp_s2 = strstr(tmp_s, "#" )) != NULL ) {
					*tmp_s2 = 0x0;
					tmp_s2++;
					if( tmp_s2 ) {
						ret->object_num = atoi(tmp_s2);
					}
					len = strlen( tmp_s );
				}

				ret->addr = PKI_Malloc( len + 1 );
				strncpy( ret->addr, tmp_s, len );
			} else {
				ret->addr = strdup("");
			}
		}

		/*
		tmp_s = &ret->url_s[5];

		if((tmp_s3 = strchr(tmp_s, '@')) != NULL ) {
			tmp_s4 = strchr(tmp_s, '/');
			if( tmp_s4 && tmp_s3 < tmp_s4 ) {
				tmp_s2 = strchr( tmp_s, ':' );

				if( !tmp_s2 || (tmp_s3 < tmp_s2)) {
					return (NULL);
				}
				len = (int) ( (long) tmp_s2 - (long) tmp_s );
				ret->usr = (char *) malloc (len+1);
				memset( ret->usr, 0, len+1);
				strncpy( ret->usr, tmp_s, len);
				ret->usr[len] = '\x0';
			
				tmp_s = tmp_s2+1;
				tmp_s2 = strchr( tmp_s,'@');

				len = (int) ( (long) tmp_s2 - (long) tmp_s );
				ret->pwd = (char *) malloc (len+1);
				memset( ret->pwd, 0, len+1);
				strncpy( ret->pwd, tmp_s, len);
				ret->pwd[len] = '\x0';

				tmp_s = tmp_s2+1;
			}
		}

		if( strchr( tmp_s, ':' )) {
			tmp_s2 = strchr(tmp_s,':');

			len = (int) ( (long) tmp_s2 - (long) tmp_s );
			ret->addr = (char *) malloc (len+1);
			memset( ret->addr, 0, len+1 );

			strncpy( ret->addr, tmp_s, len);
			ret->addr[len] = '\x0';

			tmp_s = tmp_s2+1;
			ret->port = atoi( tmp_s );
			if( ret->port == 0 ) {
				Error in parsing the port number!
				URL_free ( ret );
				return(NULL);
			}

			if( (tmp_s2 = strchr( tmp_s, '/' )) != NULL ) {
				tmp_s =  tmp_s2;
			} else {
				tmp_s = &ret->url_s[7];
			}
		}

		if( (tmp_s2 = strchr( tmp_s, '/' )) != NULL ) {
			char *tmp_attrs = NULL;
			tmp_s2++;

			if((tmp_attrs = strchr( tmp_s, '?' )) != NULL) {
				len = strlen( tmp_attrs );
				ret->attrs = (char *) malloc ( len );
				memset( ret->attrs, 0, len );
				memcpy( ret->attrs, tmp_attrs + 1, len);

				len = tmp_attrs - tmp_s2;
				ret->path = (char *) malloc ( len );
				memset( ret->path, 0, len);
				memcpy( ret->path, tmp_s2, len - 1);

				if( !ret->addr ) {
					len = (int) (tmp_s2 - tmp_s - 1);
					ret->addr = (char *) malloc (len+1);
					memset( ret->addr, 0, len+1);
					strncpy( ret->addr, tmp_s, len);
					ret->addr[len] = '\x0';
				}
			} else {
				if( !ret->addr ) {
					len = (int) 
						((long) tmp_s2 - (long) tmp_s);
					ret->addr = (char *) malloc (len+1);
					memset( ret->addr, 0, len+1);
					strncpy( ret->addr, tmp_s, len);
					ret->addr[len] = '\x0';
				}

				tmp_s = tmp_s2;
				ret->path = strdup( tmp_s );
			}
		} else {
			if( !ret->addr )
				ret->addr = strdup( tmp_s );
			ret->path = "/";
		}
		*/
	}
	else if( strncmp("http://", ret->url_s, 7 ) == 0)
	{
		ret->proto = URI_PROTO_HTTP;
		ret->port  = DEFAULT_HTTP_PORT;
		tmp_s = &ret->url_s[7];

		if((tmp_s3 = strchr(tmp_s, '@')) != NULL ) {
			tmp_s4 = strchr(tmp_s, '/');
			if( tmp_s4 && tmp_s3 < tmp_s4 ) {
				tmp_s2 = strchr( tmp_s, ':' );

				if( !tmp_s2 || (tmp_s3 < tmp_s2)) {
					PKI_ERROR(PKI_ERR_URI_PARSE, NULL);
					// return NULL;
					goto err;
				}
				len = (size_t) ( tmp_s2 - tmp_s );
				ret->usr = (char *) malloc (len+1);
				memset( ret->usr, 0, len+1);

				strncpy( ret->usr, tmp_s, len);
				ret->usr[len] = '\x0';
			
				tmp_s = tmp_s2+1;
				tmp_s2 = strchr( tmp_s,'@');

				len = (size_t) ( tmp_s2 - tmp_s );
				ret->pwd = (char *) malloc (len+1);
				memset( ret->pwd, 0, len+1);
				strncpy( ret->pwd, tmp_s, len);
				ret->pwd[len] = '\x0';

				tmp_s = tmp_s2+1;

			}
		}

		// IPv6 Hex Address Parsing
		if( (*tmp_s == '[') && 
				((tmp_s2 = strchr( tmp_s, ']' )) != NULL )) {

			len = (size_t) ( tmp_s2 - tmp_s );
			ret->addr = ( char *) malloc ( len );
			memset ( ret->addr, 0, len );

			strncpy( ret->addr, tmp_s + 1, len-1 );
			ret->addr[len-1] = '\x0';

			tmp_s = tmp_s2 + 1;
			if ( *tmp_s == ':' ) {
				ret->port = atoi ( tmp_s + 1 );
			}

			if( (tmp_s2 = strchr( tmp_s, '/' )) != NULL ) {
				tmp_s =  tmp_s2;
			} else {
				tmp_s = &ret->url_s[7];
			}

		} else if( strchr( tmp_s, ':' )) {
			tmp_s2 = strchr(tmp_s,':');

			len = (size_t) ( tmp_s2 - tmp_s );
			ret->addr = (char *) malloc (len+1);
			memset( ret->addr, 0, len+1 );

			strncpy( ret->addr, tmp_s, len);
			ret->addr[len] = '\x0';

			tmp_s = tmp_s2+1;
			ret->port = atoi( tmp_s );
			if( (tmp_s2 = strchr( tmp_s, '/' )) != NULL ) {
				tmp_s =  tmp_s2;
			} else {
				tmp_s = &ret->url_s[7];
			}
		}

		if( strchr( tmp_s, '/' )) {

			tmp_s2 = strchr(tmp_s,'/');

			if( !ret->addr ) {
				len = (size_t) ( tmp_s2 - tmp_s );
				ret->addr = (char *) malloc (len+1);
				memset( ret->addr, 0, len+1);
				strncpy( ret->addr, tmp_s, len);
				ret->addr[len] = '\x0';
			}

			tmp_s = tmp_s2;
			ret->path = strdup( tmp_s );
		} else {
			if( !ret->addr )
				ret->addr = strdup( tmp_s );
			ret->path = strdup("/");
		}
	}
	else if( strncmp("https://", ret->url_s, 8 ) == 0)
	{
		ret->proto = URI_PROTO_HTTPS;
		ret->port = DEFAULT_HTTPS_PORT;
		ret->ssl = 1;
		tmp_s = &ret->url_s[8];

		if((tmp_s3 = strchr(tmp_s, '@')) != NULL ) {
			tmp_s4 = strchr(tmp_s, '/');
			if( tmp_s4 && tmp_s3 < tmp_s4 ) {
				tmp_s2 = strchr( tmp_s, ':' );

				if( !tmp_s2 || (tmp_s3 < tmp_s2)) {
					PKI_ERROR(PKI_ERR_URI_PARSE, NULL);
					// return NULL;
					goto err;
				}
				len = (size_t) ( tmp_s2 - tmp_s );
				ret->usr = (char *) malloc (len+1);
				memset( ret->usr, 0, len+1);

				strncpy( ret->usr, tmp_s, len);
				ret->usr[len] = '\x0';
			
				tmp_s = tmp_s2+1;
				tmp_s2 = strchr( tmp_s,'@');

				len = (size_t) ( tmp_s2 - tmp_s );
				ret->pwd = (char *) malloc (len+1);
				memset( ret->pwd, 0, len+1);
				strncpy( ret->pwd, tmp_s, len);
				ret->pwd[len] = '\x0';

				tmp_s = tmp_s2+1;

			}
		}

		// IPv6 Hex Address Parsing
		if( (*tmp_s == '[') && 
				((tmp_s2 = strchr( tmp_s, ']' )) != NULL )) {

			len = (size_t) ( tmp_s2 - tmp_s );
			ret->addr = ( char *) malloc ( len );
			memset ( ret->addr, 0, len );

			strncpy( ret->addr, tmp_s + 1, len-1 );
			ret->addr[len-1] = '\x0';

			tmp_s = tmp_s2 + 1;
			if ( *tmp_s == ':' ) {
				ret->port = atoi ( tmp_s + 1 );
			}

			if( (tmp_s2 = strchr( tmp_s, '/' )) != NULL ) {
				tmp_s =  tmp_s2;
			} else {
				tmp_s = &ret->url_s[7];
			}
		} else if( strchr( tmp_s, ':' )) {
			tmp_s2 = strchr(tmp_s,':');

			len = (size_t) ( tmp_s2 - tmp_s );
			ret->addr = (char *) malloc (len+1);
			memset( ret->addr, 0, len+1 );

			strncpy( ret->addr, tmp_s, len);
			ret->addr[len] = '\x0';

			tmp_s = tmp_s2+1;
			ret->port = atoi( tmp_s );
			if( (tmp_s2 = strchr( tmp_s, '/' )) != NULL ) {
				tmp_s =  tmp_s2;
			} else {
				tmp_s = &ret->url_s[7];
			}
		}

		if( strchr( tmp_s, '/' )) {

			tmp_s2 = strchr(tmp_s,'/');

			if( !ret->addr ) {
				len = (size_t) ( tmp_s2 - tmp_s );
				ret->addr = (char *) malloc (len+1);
				memset( ret->addr, 0, len+1);
				strncpy( ret->addr, tmp_s, len);
				ret->addr[len] = '\x0';
			}

			tmp_s = tmp_s2;
			ret->path = strdup( tmp_s );
		} else {
			if( !ret->addr )
				ret->addr = strdup( tmp_s );
			ret->path = strdup("/");
		}
	}
	else if( strncmp("pkcs11://", ret->url_s, 8 ) == 0)
	{
		ret->proto = URI_PROTO_PKCS11;
		ret->port = DEFAULT_PKCS11_PORT;

		tmp_s = &ret->url_s[9];

		if(( tmp_s3 = strstr(tmp_s, "/(" )) != NULL ) {

			len = (size_t) (tmp_s3 - tmp_s);
			ret->addr = PKI_Malloc( len + 1);
			strncpy( ret->addr, tmp_s, len );
			tmp_s = tmp_s3 + 1;

			if(( tmp_s3 = strchr( tmp_s, '?' )) != NULL ) {
				len = (size_t) (tmp_s3 - tmp_s);
				ret->path = PKI_Malloc( len + 1);
				strncpy( ret->path, tmp_s, len );

				tmp_s = tmp_s3 + 1;
				len = strlen( tmp_s );
				ret->attrs = PKI_Malloc ( len + 1);
				strncpy( ret->attrs, tmp_s, len );
			} else {
				len = strlen( tmp_s );
				ret->path = PKI_Malloc( len + 1 );
				strncpy( ret->path, tmp_s, len );
				ret->attrs = strdup( "data" );
			}

		} else if(( tmp_s3 = strchr( tmp_s, '?')) != NULL ) {

			len = (size_t) (tmp_s3 - tmp_s);
			ret->addr = PKI_Malloc( len + 1 );
			strncpy( ret->addr, tmp_s, len );
			tmp_s = tmp_s3 + 1;

			ret->attrs = strdup( tmp_s );
		} else {
			ret->addr = strdup( tmp_s );
			ret->attrs = strdup( "data" );
			ret->path = strdup( "" );
		}

		if ((ret->addr) && (ret->addr[strlen(ret->addr)-1] == '/') ) {
			ret->addr[strlen(ret->addr)-1] = '\x0';
		}

	}
	else if( strncmp("socket://", ret->url_s, 9 ) == 0)
	{
		tmp_s = &ret->url_s[9];

		if( strchr( tmp_s, ':' )) {

			tmp_s2 = strchr(tmp_s,':');

			len = (size_t) ( tmp_s2 - tmp_s );
			ret->addr = (char *) malloc (len+1);
			memset( ret->addr, 0, len+1 );

			strncpy( ret->addr, tmp_s, len);
			ret->addr[len] = '\x0';

			tmp_s = tmp_s2+1;
			ret->port = atoi( tmp_s );
		} else {
			ret->port = -1;

			ret->addr = (char *) malloc ( BUFF_MAX_SIZE );
			memset( ret->addr, 0, BUFF_MAX_SIZE );
			strncpy( ret->addr, ret->url_s, BUFF_MAX_SIZE);
		}

		ret->proto = URI_PROTO_SOCK;
	}
	else if( strncmp("dns://", ret->url_s, 6 ) == 0)
	{
		ret->proto = URI_PROTO_DNS;
		ret->port = DEFAULT_DNS_PORT;
		ret->path = NULL;

		tmp_s = &ret->url_s[6];

		if (strchr(tmp_s,'?'))
		{
			tmp_s2 = strchr(tmp_s, '?');
			len = (size_t) (tmp_s2 - tmp_s);
			ret->addr = (char *) malloc (len+1);
			memset(ret->addr, 0, len+1);

			strncpy(ret->addr, tmp_s, len);
			ret->addr[len] =  '\x0';

			tmp_s = tmp_s2+1;

			if ((len = strlen(tmp_s)) > 0)
			{
				ret->attrs = (char *) malloc (len+1);
				memcpy(ret->attrs, tmp_s, len);
				ret->attrs[len] = '\x0';
			}
			else ret->attrs = strdup("A");
		}
		else
		{
			ret->attrs = strdup("A");
			ret->addr = (char *) malloc (BUFF_MAX_SIZE);
			memset(ret->addr, 0, BUFF_MAX_SIZE);
			strncpy(ret->addr, ret->url_s, BUFF_MAX_SIZE);
		}
	}
	else
	{
		/* No protocol specified, we assume file:// or sock:// */
		tmp_s = ret->url_s;

		if (strchr( tmp_s, ':'))
		{
			/* Shall we be more liberal ??? */
			// if (ret) URL_free ( ret );
			PKI_ERROR(PKI_ERR_URI_PARSE, NULL);
			// ret = NULL;
			// return ( NULL );
			goto err;

			tmp_s2 = strchr(tmp_s,':');

			len = (size_t) ( tmp_s2 - tmp_s );
			ret->addr = (char *) malloc (len+1);
			memset( ret->addr, 0, len+1 );

			strncpy( ret->addr, tmp_s, len);
			ret->addr[len] = '\x0';

			tmp_s = tmp_s2+1;
			ret->port = atoi( tmp_s );
			ret->proto = URI_PROTO_SOCK;
		}
		else
		{
			// char tmp_val[BUFF_MAX_SIZE];
			size_t len = 0;

			// memset(tmp_val, 0, BUFF_MAX_SIZE);

			ret->port = -1;
			ret->proto = URI_PROTO_FILE;

			if (ret->url_s)
			{
				len = strlen(ret->url_s);

				ret->addr = (char *) PKI_Malloc( len+1 );
				memcpy(ret->addr, ret->url_s, len);
			}
			else
			{
				// if (ret) URL_free (ret);
				// ret = NULL;
				PKI_ERROR(PKI_ERR_URI_PARSE, NULL);

				// return NULL;
				goto err;
			}
		}
	}

	if (is_alloc) PKI_Free(is_alloc);

	return ret;

err:

	if (ret) URL_free(ret);
	if (is_alloc) PKI_Free(is_alloc);

	return NULL;
}

/*! \brief Releases the Memory associated to a URL data structure */

void URL_free ( URL *url ) {

	if( !url ) return;

	if( url->addr )  PKI_ZFree_str (url->addr);
	if( url->usr )   PKI_ZFree_str (url->usr);
	if( url->pwd )   PKI_ZFree_str (url->pwd);
	if( url->path )  PKI_ZFree_str (url->path);
	if( url->url_s ) PKI_ZFree_str (url->url_s);
	if( url->attrs ) PKI_ZFree_str (url->attrs);

	if( url ) PKI_ZFree (url, sizeof(URL));

	return;
}
