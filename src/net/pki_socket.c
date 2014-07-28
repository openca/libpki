/*
 * LIBPKI - OpenSource PKI library
 * by Massimiliano Pala (madwolf@openca.org) and OpenCA project
 *
 * Copyright (c) 2001-2007 The OpenCA Project.  All rights reserved.
 *
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <libpki/pki.h>

/*! \brief Allocates and Inizializes a new PKI_SOCKET */
PKI_SOCKET *PKI_SOCKET_new () {

	PKI_SOCKET *sock = NULL;

	if(( sock = PKI_Malloc ( sizeof (PKI_SOCKET))) == NULL )
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	sock->type = -1;
	sock->fd   = -1;
	sock->ssl  = NULL;
	sock->url  = NULL;

	return sock;
}

/*! \brief Creates a new PKI_SOCKET from an existing PKI_SSL */

PKI_SOCKET *PKI_SOCKET_new_ssl ( PKI_SSL *ssl ) {
	PKI_SOCKET *sock = NULL;

	if ( !ssl ) return NULL;

	if(( sock = PKI_SOCKET_new ()) == NULL ) {
		return NULL;
	}

	PKI_SOCKET_set_ssl ( sock, ssl );

	return sock;
}


/*! \brief Frees memory associated with a PKI_SOCKET data structure */

void PKI_SOCKET_free (PKI_SOCKET *sock) {

	if ( !sock ) return;

	if ( sock->ssl ) PKI_SSL_free ( sock->ssl );
	if ( sock->url ) URL_free ( sock->url );

	PKI_Free ( sock );

	return;
}

/*! \brief Opens a connection to the passed url */

int PKI_SOCKET_open ( PKI_SOCKET *sock, char *url_s, int timeout ) {

	int ret = -1;
	URL *url = NULL;

	if (!sock || !url_s ) return PKI_ERR;

	if ((url = URL_new ( url_s )) == NULL)
	{
		return PKI_ERR;
	}

	ret = PKI_SOCKET_open_url(sock, url, timeout);

	URL_free(url);

	return ret;
}

/*! \brief Opens a connection to the server identified by URL */

int PKI_SOCKET_open_url ( PKI_SOCKET *sock, URL *url, int timeout ) {

	int ret = -1;

	if ( !sock || !url ) return ( PKI_ERR );

	if (sock->url != NULL) URL_free(sock->url);
	sock->url = URL_new(URL_get_parsed(url));

	if ( url->ssl == 1 )
	{
		PKI_log_debug("Creating a SECURE connection (SSL/TLS)");
		ret = PKI_SOCKET_connect_ssl ( sock, url, timeout );
	}
	else
	{
		PKI_log_debug("Creating a simple connection");
		ret = PKI_SOCKET_connect ( sock, url, timeout );
	}

	return ret;
}

/*! \brief Opens a Connection to a URL via an already initialized PKI_SOCKET */

int PKI_SOCKET_connect ( PKI_SOCKET *sock, URL *url, int timeout ) {

	if ( !sock || !url ) return PKI_ERR;

	if (sock->url != NULL) URL_free(sock->url);
	sock->url = URL_new(URL_get_parsed(url));

	if((sock->fd = PKI_NET_open(url, timeout )) > 0 )
	{
		sock->type = PKI_SOCKET_FD;
	}
	else
	{
		PKI_log_err ( "Can not connect to %s:%d (%s)",
			url->addr, url->port, strerror (errno));
		return PKI_ERR;
	}

	return PKI_OK;

}

/*! \brief Opens a Secure Connection to a URL via an already initialized PKI_SOCKET */

int PKI_SOCKET_connect_ssl ( PKI_SOCKET *sock, URL *url, int timeout ) {

	if ( !sock || !url ) return PKI_ERR;

	if (sock->url != NULL) URL_free(sock->url);
	sock->url = URL_new(URL_get_parsed(url));

	if(( sock->fd = PKI_NET_open ( url, timeout )) < 0 ) {
		PKI_log_err("Can not create network connection to %s:%d",
			url->addr, url->port );
		return PKI_ERR;
	}

	if ( sock->ssl == NULL ) {
		sock->ssl = PKI_SSL_new ( NULL );
	}

	if ( PKI_SSL_start_ssl ( sock->ssl, sock->fd ) == PKI_ERR )
	{
		PKI_NET_close ( sock->fd );
		sock->fd = -1;
		return PKI_ERR;
	}

	sock->type = PKI_SOCKET_SSL;

	return PKI_OK;
}

/*! \brief Opens a Connection to a URL via an already initialized PKI_SOCKET */

/*
int PKI_SOCKET_open_url ( PKI_SOCKET *sock, URL *url, int timeout ) {

	if ( !sock || !url ) return PKI_ERR;

	if ( sock->status == PKI_SOCKET_CONNECTED ) {
		PKI_SOCKET_close ( sock );
	}

	switch ( sock->type ) {
		case PKI_SOCKET_FD:
				if((sock->socket.fd = PKI_NET_open ( url, timeout )) < 0) {
					PKI_log_err ("Failed to connect to %s:%d",url->url_s,
						url->port );	
					return PKI_ERR;
				};
				break;
		case PKI_SOCKET_SSL:
				if ( sock->socket.ssl == NULL ) {
					if(( sock->socket.ssl = PKI_SSL_new ( NULL )) == NULL ) {
						PKI_log_err ("SSL Memory Error");
						return PKI_ERR;
					}
				};
				if( PKI_SSL_connect_url( sock->socket.ssl, url, 
												timeout ) == PKI_ERR ) {
					PKI_log_err ("SSL Failed to connect to %s:%d",
						url->url_s, url->port );
				}
				break;
		default:
				PKI_log_err("PKI_SOCKET: type %d not supported", sock->type );
	}

	PKI_log_debug("PKI SOCKET: Connected to %s:%d", url->url_s, url->port );

	sock->url = URL_new ( url->url_s );

	return PKI_OK;
}
*/

/*! \brief Closes a connected socket */

int PKI_SOCKET_close ( PKI_SOCKET *sock )
{
	if (!sock) return PKI_ERR;

	switch ( sock->type )
	{
		case PKI_SOCKET_FD:
			PKI_NET_close ( sock->fd );
			break;

		case PKI_SOCKET_SSL:
			if ( !sock->ssl ) return PKI_ERR;
			PKI_SSL_close ( sock->ssl );
			break;

		default:
			PKI_log_err("PKI SOCKET Close: type %d not supported", sock->type );
			break;
	}

	if ( sock->url ) URL_free ( sock->url );

	sock->url = NULL;
	sock->type = -1;

	return PKI_OK;
}

/*! \brief Sets an already connected PKI_SSL layer in an existing PKI_SOCKET */

int PKI_SOCKET_set_ssl ( PKI_SOCKET *sock, PKI_SSL *ssl )
{
	if ( !sock || !ssl ) return PKI_ERR;

	if ( sock->type == PKI_SOCKET_SSL && sock->ssl ) PKI_SSL_free ( sock->ssl );

	sock->ssl = ssl;

	if (ssl->connected)
	{
		sock->type = PKI_SOCKET_SSL;
		PKI_NET_close ( sock->fd );
		sock->fd = PKI_SSL_get_fd ( ssl );
	}

	return PKI_OK;
}

/*! \brief Sets an already connected fd layer in an existing PKI_SOCKET */

int PKI_SOCKET_set_fd  ( PKI_SOCKET *sock, int fd ) {
	if ( !sock ) return PKI_ERR;

	sock->type = PKI_SOCKET_FD;
	sock->fd = fd;

	if ( sock->ssl && sock->ssl->connected ) {
		PKI_SSL_close ( sock->ssl );
		PKI_SSL_start_ssl ( sock->ssl, sock->fd );
	}

	return PKI_OK;
}


/*! \brief Returns the PKI_SSL layer (if present) */

PKI_SSL *PKI_SOCKET_get_ssl ( PKI_SOCKET *sock ) {

	if ( !sock ) return NULL;

	return sock->ssl;
}

/*! \brief Returns the underlying file descriptor (if present) */

int PKI_SOCKET_get_fd ( PKI_SOCKET *sock ) {

	int ret = -1;

	if ( !sock ) return ( ret );

	if((ret = PKI_SSL_get_fd ( sock->ssl )) < 0 ) {
		ret = sock->fd;
	}

	return ret;
}

/*! \brief Starts an SSL/TLS session on a connected FD socket */

int PKI_SOCKET_start_ssl ( PKI_SOCKET *sock ) {
	if( !sock ) return PKI_ERR;

	if ( !sock->ssl ) {
		sock->ssl = PKI_SSL_new ( NULL );
	}

	if ( sock->ssl && sock->ssl->connected ) return PKI_ERR;

	return PKI_SSL_start_ssl ( sock->ssl, sock->fd );

}

/*! \brief Reads n bytes from a connected socket */

ssize_t PKI_SOCKET_read ( PKI_SOCKET *sock, char *buf, size_t n, int timeout ) {

	if (!sock || !buf ) return -1;

	switch ( sock->type ) {
		case PKI_SOCKET_FD:
			return PKI_NET_read ( sock->fd, buf, n, timeout );
			break;
		case PKI_SOCKET_SSL:
			return (ssize_t) PKI_SSL_read ( sock->ssl, buf, (ssize_t) n );
			break;
		default:
			PKI_log_err ("PKI SOCKET READ: socket type %d not supported");
			return -1;
	}

	return -1;
}

/*! \brief Writes n bytes to a conected socket */

ssize_t PKI_SOCKET_write ( PKI_SOCKET *sock, char *buf, size_t n ) {

	if (!sock || !buf ) return -1;

	switch ( sock->type ) {
		case PKI_SOCKET_FD:
			return PKI_NET_write ( sock->fd, buf, n );
			break;
		case PKI_SOCKET_SSL:
			return PKI_SSL_write ( sock->ssl, buf, (ssize_t) n );
			break;
		default:
			PKI_log_err ("PKI SOCKET WRITE: socket type %d not supported");
			return -1;
	}

	return -1;
}

/*! \brief Returns the URL used in PKI_SOCKET_open or PKI_SOCKET_open_url */

URL *PKI_SOCKET_get_url ( PKI_SOCKET *sock )
{
	if ( !sock ) return NULL;

	return sock->url;
}


