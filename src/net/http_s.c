/* OpenCA libpki package
* (c) 2000-2007 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#include <libpki/pki.h>

#define HTTP_BUF_SIZE	65535

/* ----------------------------- AUXILLARY FUNCS ------------------------------ */


/*
 * Returns the pointer to the end of the header, if found. Starts searching
 * from the provided offset or from the beginning if offset is < 0
 */
char * __find_end_of_header(PKI_MEM *m, ssize_t offset)
{
	ssize_t idx = 0;
	ssize_t size = 0;
	char * ret = NULL;
	static char bytes[4] = { '\r', '\n', '\r', '\n' };

	// Input check
	if (!m || offset >= m->size) return NULL;

	if (m->size <= 4) return NULL;

	size = (ssize_t)m->size;

	// Fix the offset if it is < 0
	if (offset < 0) offset = 0;

	// Looks for the eoh
	for (idx = size - 4; idx >= offset; idx--)
	{
		int i, found;

		// Searches for the "bytes" starting from the offset
		for (i = 0, found = 0; i < sizeof(bytes); i++)
		{
			if (m->data[idx + i] != bytes[i]) break;
		}

		// If i is 4 then we have a match on the whole string
		if (i == 4) found = 1;

		// If we found the End Of Header we return that
		if (found == 1) ret = (char *) &(m->data[idx + 3]);
	}

	return ret;
}

/*
 * Parses the PKI_MEM that contains the header looking for specific HTTP
 * headers, the requested path, and the HTTP version and code. Returns
 * PKI_OK in case of success, PKI_ERR otherwise.
 */
int __parse_http_header(PKI_HTTP *msg)
{
    // Let's parse the first line of the HTTP message
    char *eol = NULL;
    char *method = NULL;
    char *path = NULL;
    char *http_version = NULL;
    char *line = NULL;
    char *tmp_ptr = NULL;
    size_t line_size = 0;

    // Shortcut for msg->head
    PKI_MEM *m = NULL;

    // Checks the input
    if (msg == NULL || msg->head == NULL || msg->head->data == NULL || msg->head->size < 1)
    {
    	PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    	return PKI_ERR;
    }

    // For better understanding, we use a proxy variable to access the head
    m = msg->head;

    // Let's parse the path and the details from the first line in the header
    if (((eol = strchr((char *)m->data, '\n')) == NULL) &&
  		  (eol = strchr((char*)m->data, '\r')) == NULL)
    {
    	// ERROR: here we should have at least one line (since we already
    	// have the eoh detected, return the error by returning NULL
    	return PKI_ERR;
    }

    // Let's parse the path and version number
    line_size = (size_t) (eol - (char*)m->data);
    if ((line = PKI_Malloc(line_size + 1)) == NULL)
    {
  	  PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
  	  return PKI_ERR;
    }

    // Copy the first line (strtok_r alters the original string)
    memcpy(line, m->data, line_size);

    // Retrieves the first token - [i.e., GET/POST/HTTP ...]
    method = strtok_r(line, " ", &tmp_ptr);
    if (method == NULL)
    {
  	  PKI_log_err("Can not parse HTTP method");
  	  PKI_Free(line);

  	  return PKI_ERR;
    }

    if (strncmp_nocase(method, PKI_HTTP_METHOD_HTTP_TXT, 4) == 0)
    {
  	  // This is usually an HTTP response
  	  msg->method = PKI_HTTP_METHOD_HTTP;

  	  // Let's get the version and the code
  	  if (sscanf((const char *)msg->head->data,"HTTP/%f %d", &msg->version, &msg->code) < 1)
  	  {
  		  PKI_log_debug("ERROR Parsing HTTP Version and Code");
  		  PKI_Free(line);

  		  return PKI_ERR;
  	  }
    }
    else if (strncmp_nocase(method, PKI_HTTP_METHOD_GET_TXT, 3) == 0 ||
		  strncmp_nocase(method, PKI_HTTP_METHOD_POST_TXT, 4) == 0)
    {
  	  if (strncmp_nocase(method, PKI_HTTP_METHOD_GET_TXT, 3) == 0)
  		  msg->method = PKI_HTTP_METHOD_GET;
  	  else
  		  msg->method = PKI_HTTP_METHOD_POST;

  	  path = strtok_r(NULL, " ", &tmp_ptr);
  	  if (path == NULL)
  	  {
  		  // This is an error, we should get the path for a POST or a GET
  		  PKI_Free(line);

  		  return PKI_ERR;
  	  }

  	  msg->path = strdup(path);

  	  http_version = strtok_r(NULL, " ", &tmp_ptr);
  	  if (http_version == NULL)
  	  {
  		  // This is an error, we should be able to get the HTTP version from the third token
  		  PKI_Free(line);

  		  return PKI_ERR;
  	  }
  	  else if(sscanf(http_version,"HTTP/%f", &msg->version) < 1)
  	  {
  		  PKI_log_debug("ERROR Parsing HTTP Version");
  		  PKI_Free(http_version);
  		  PKI_Free(line);

  		  return PKI_ERR;
  	  }
    }
    else
    {
    	PKI_log_err("Unsupported HTTP Method detected (%s)", method);
    	PKI_Free(line);

    	return PKI_ERR;
    }

    // We do not need the line anymore, let's free the memory
    if (line) PKI_Free(line);

    // Success
	return PKI_OK;
}

/* ----------------------------- MAIN FUNCS ----------------------------------- */


/*! \brief Frees the memory associated with a PKI_HTTP data structure */

void PKI_HTTP_free ( PKI_HTTP *rv )
{
	if ( !rv ) return;

	if ( rv->location ) PKI_Free ( rv->location );
	if ( rv->type ) PKI_Free ( rv->type );

	if ( rv->body ) PKI_MEM_free ( rv->body );
	if ( rv->head ) PKI_MEM_free ( rv->head );
	if ( rv->path  ) PKI_Free ( rv->path );

	PKI_Free ( rv );

	return;
}


/*! \brief Allocates the memory for a new PKI_HTTP data structure */

PKI_HTTP * PKI_HTTP_new ( void )
{

	PKI_HTTP *ret = NULL;

	if((ret = PKI_Malloc ( sizeof( PKI_HTTP ))) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	/* Standard Header Codes */
	ret->code = 0;
	ret->type = NULL;
	ret->location = NULL;

	/* Data */
	ret->body = NULL;
	ret->head = NULL;
	ret->path = NULL;

	return ( ret );
}

/*! \brief Returns a PKI_HTTP from the content of a char * */

char * PKI_HTTP_get_header_txt (const char * orig_data,
		                        const char * header) {

	char *tk = NULL, *pnt = NULL;
	char *ret = NULL;

	char *data = NULL;
	int found = 0;

	if( !orig_data || !header || !strlen(orig_data) || !strlen(header))
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	if ((data = strdup(orig_data)) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	for (tk = strtok_r ( data, "\r\n", &pnt ); tk; tk = strtok_r(NULL, "\r\n", &pnt)) 
	{
		if ( tk == NULL ) break;

		if (strncmp_nocase(tk, header, (int) strlen(header)) == 0)
		{
			found = 1;
			break;
		}
	}

	if (!found)
	{
		PKI_Free ( data );
		return NULL;
	}

	if ((pnt = strchr( tk, ':' )) == NULL)
	{
		PKI_Free ( data );
		return NULL;
	}
	pnt++;

	while ((pnt != NULL ) && (*pnt == ' ' )) {
			pnt++;
	}

	if (pnt) ret = strdup( pnt );

	PKI_Free ( data );

	return ret;
}


/*! \brief Returns a PKI_HTTP from the content of a PKI_MEM */

char * PKI_HTTP_get_header ( const PKI_HTTP * http,
		                     const char     * header ) {

	if( !http || !http->head || !header ) return NULL;

	return PKI_HTTP_get_header_txt ( (char *)http->head->data, header);
}

/* Internal version, can handle both HTTP and HTTPS */

PKI_HTTP *PKI_HTTP_get_message (const PKI_SOCKET * sock,
		                        int                timeout,
								size_t             max_size) {

  PKI_HTTP * ret = NULL;

  char * eoh = NULL;
  char * body = NULL;

  ssize_t read = 0; // Keeps track of the single reading
  ssize_t free = 0; // Keeps track of the remaining buffer space
  ssize_t idx = 0; // Keeps track of how much data we poured into MEM
  ssize_t size = 0; // Keeps track of the read data from socket

  // Let's initialize some useful variables (code readability)
  long long content_length = -1;

  // Buffer where to keep the data
  PKI_MEM *m = NULL;

  // Allocates the HTTP message container
  if ((ret = PKI_HTTP_new()) == NULL)
  {
      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL );
      goto err;
  }
  ret->method = PKI_HTTP_METHOD_UNKNOWN;

  if (max_size > 0)
  {
	  // Allocates a new MEM object
	  m = PKI_MEM_new(max_size + 1);
  }
  else
  {
	  // Allocates the default buffer for HTTP messages
	  m = PKI_MEM_new(HTTP_BUF_SIZE + 1);
  }

	if (m == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	// Sets the free space in the buffer
	free = (ssize_t) m->size - 1;

  // Let's retrieve the data from the socket. Note that this for
  // always read at most 'free' bytes which carries the amount of
  // free space in the buffer -> safe
  for (read = PKI_SOCKET_read(sock, (char *)(&(m->data[idx])), (size_t) free, timeout);
       read > 0;
       read = PKI_SOCKET_read(sock, (char *)(&(m->data[idx])), (size_t) free, timeout))
  {
      // If read is negative, there was an error on the socket
      // let's just report it as an error and move on
      if (read < 0)
      {
    	  if (!eoh)
    	  {
    		  PKI_log_err("Error while reading from socket");
    		  goto err;
    	  }
    	  else
    	  {
    		  // Nothing to read anymore - let's break
    		  PKI_log_err("Nothing to read anymore (read = %d)", read);
    		  break;
    	  }
      }
      else if (read == 0 && eoh)
      {
    	  // No data was read, let's assume the stream is complete and
    	  // break from the for loop
    	  break;
      }

      // Let's be sure there is a NULL-bound limit to the read data
      size += read;
      free -= read;
      m->data[size] = '\x0';

      // If we don't have a header yet, let's look for it
      if (!eoh && ((eoh = __find_end_of_header(m, idx)) != NULL))
      {
    	  // We want the header to finish with just one '\r\n' - since the
    	  // pointer we receive is at the end of the '\r\n\r\n' sequence,
    	  // we need to shrink by 2 bytes
    	  size_t header_size = (size_t) (eoh - (char *) m->data - 2);
    	  ret->head = PKI_MEM_new_data(header_size + 1, m->data);
    	  ret->head->data[header_size] = '\x0';

    	  // If we can not parse the header - we have to return error
    	  if (PKI_ERR == __parse_http_header(ret)) goto err;

    	  // Let's get the pointer to the start of the body
    	  body = eoh + 1;

    	  // Checks for the content-length is in the header - if we have not found it, yet
    	  if (ret->method != PKI_HTTP_METHOD_GET && content_length < 0)
    	  {
    		  char *cnt_len_s = NULL;
    		  if ((cnt_len_s = PKI_HTTP_get_header(ret, "Content-Length" )) != NULL)
    		  {
    			  content_length = atoll(cnt_len_s);
    			  PKI_Free(cnt_len_s);
    			  PKI_log_debug ( "HTTP Content-Length: %d bytes", content_length);
    		  }
    	  }
      } // End of if (!eoh) ...

      // Updates the start pointer for the next read operation
      idx += read;

      // Let's check if we need to expand the buffer
      if (max_size <= 0)
      {
    	  // We expand the mem if the buffer has less than 2K free
    	  if (free < 2048)
    	  {
    			ssize_t ofs = 0;

    		  if(body)
    		  {
    		    ofs = (ssize_t)(body - (char *)m->data);
          
    		    if(ofs < 0)
    		    {
    		      PKI_log_debug ( "Invalid offset for HTTP body: Start: %p - Body: %p", m->data, body);
    		      PKI_ERROR(PKI_ERR_URI_READ, NULL);
    		      goto err;
    		    }
    		  }

    		  // Grow the memory for the HTTP message
    		  if(content_length > 0 && body && m->size < (size_t)(content_length + ofs))
    		  {
           size_t len = ((size_t)(content_length + ofs) - m->size);

    		    if (PKI_MEM_grow(m, len + 1) == PKI_ERR)
    		    {
    		      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
    		      goto err;
    		    }
    		    free += (ssize_t)len;
    		  }
    		  else
    		  {
    		    if (PKI_MEM_grow(m, HTTP_BUF_SIZE) == PKI_ERR)
    		    {
    		      PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
    		      goto err;
    		    }
    		    free += HTTP_BUF_SIZE;
    		  }

    		  // Let's update the pointer to the body
    		  if(body) body = (char *)m->data + ofs;
    	  }
      }

      // Let's check if we need to perform the next read or not
      if (eoh && ret->method == PKI_HTTP_METHOD_GET)
      {
    	  // We do not need to wait for any other read as GETs do not have
    	  // a full body
    	  break;
      }
      else if ((content_length >= 0) && (&m->data[size] - (unsigned char *)body >= content_length))
      {
    	  // Here we have received the full body (since the size of the body corresponds or exceeds the
    	  // contents of the Content-Length: header line), therefore we can safely get out of the cycle
    	  break;
      }

  } /* End of for..loop */

  // Here we should have both the eoh and the body - if not, there was
  // an error and we return the malformed request message
  if (!eoh)
  {
	  PKI_log_err ( "Read data (so far): %d bytes - Last read: %d bytes", idx, read);
	  PKI_ERROR(PKI_ERR_URI_READ, NULL);
	  goto err;
  }

  // Sets some HTTP specific data
  ret->location = PKI_HTTP_get_header ( ret, "Location" );
  ret->type     = PKI_HTTP_get_header ( ret, "Content-Type" );

  if (ret->method != PKI_HTTP_METHOD_GET && content_length > 0 && body)
  {
	  ssize_t body_start = (ssize_t)(body - (char *)m->data);
	  ssize_t body_size = idx - body_start;

	  if(body_start < 0 || body_size < 0)
	  {
		  PKI_log_err ( "Invalid offset for HTTP body - body_start: %d bytes - body_size: %d bytes", body_start, body_size);
		  PKI_ERROR(PKI_ERR_URI_READ, NULL);
		  goto err;
	  }
 
	  //Check if Content-Length > 0 but body_size is 0
	  if (body_size == 0) goto err; 
	  // Let's allocate the body for the HTTP message (if any)
	  ret->body = PKI_MEM_new_data((size_t)body_size+1, (unsigned char *)body);
		if(ret->body == NULL)
		{
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			goto err;
		}
	  ret->body->size = (size_t) body_size;
  }
  else
  {
	  ret->body = PKI_MEM_new_null();
  }

  // Let's free the buffer memory
  if (m) PKI_MEM_free(m);

  // Now we can return the HTTP message
  return ret;

err:

	// First we free the return message
	if (ret) PKI_HTTP_free(ret);

	// We then free the buffer memory object
	if (m) PKI_MEM_free(m);

	return NULL;
}

/*! \brief Sends a HTTP message to a URL and retrieve the response
 *
 * Sends (POST/GET) data to a url and (if a pointer to a mem stack
 * is provided) returns the received response. PKI_ERR is returned
 * in case of error, otherwise PKI_OK is returned.
 */

int PKI_HTTP_get_url (const URL      * url,
		      const char     * data,
		      size_t           data_size,
		      const char     * content_type,
		      int              method,
		      int              timeout,
		      size_t           max_size,
		      PKI_MEM_STACK ** sk,
		      PKI_SSL        * ssl) {

	PKI_SOCKET *sock = NULL;
	int ret = 0;

	if (!url) return PKI_ERR;

	sock = PKI_SOCKET_new();
	if (ssl) PKI_SOCKET_set_ssl(sock, ssl);

	if (PKI_SOCKET_open_url(sock, url, timeout) == PKI_ERR)
	{
		PKI_SOCKET_free ( sock );
		return PKI_ERR;
	}

	ret = PKI_HTTP_get_socket ( sock, data, data_size, content_type,
				method, timeout, max_size, sk );

	PKI_SOCKET_close ( sock );
	PKI_SOCKET_free ( sock );

	return ret;
}

/*! \brief Reads a data from an HTTP server */

int PKI_HTTP_get_socket (const PKI_SOCKET * sock,
	                 const char       * data,
			 size_t             data_size,
		         const char       * content_type,
			 int                method,
			 int                timeout,
	                 size_t             max_size,
			 PKI_MEM_STACK   ** sk ) {

	size_t len = 0;

	const char *my_cont_type = "application/unknown";

	PKI_HTTP *http_rv	= NULL;

	int rv   = -1;
	int ret  = PKI_OK;

	size_t max_len = 0;
	size_t auth_len = 0;

	char *tmp  = NULL;
	char *auth_tmp = NULL;
    
	char *head_get =
			"GET %s HTTP/1.1\r\n"
			"Host: %s\r\n"
			"User-Agent: LibPKI\r\n"
			"Connection: close\r\n"
			"%s";

	char *head_post = 
			"POST %s HTTP/1.1\r\n"
			"Host: %s\r\n"
			"User-Agent: LibPKI\r\n"
			"Connection: close\r\n"
			"Content-type: %s\r\n"
			"Content-Length: %d\r\n"
			"%s";

	char *head = NULL;

	if ( timeout < 0 ) timeout = 0;

	if ( !sock || !sock->url ) return PKI_ERR;

	// Process the authentication information if provided by the caller
	if (sock->url && sock->url->usr && sock->url->pwd)
	{
		// Rough estimate for the auth string
		max_len = strlen(sock->url->usr) + strlen(sock->url->pwd) + 100;

		// Special case for when a usr/pwd was specified in the URL
		auth_tmp = PKI_Malloc(len);
		auth_len = (size_t)snprintf(auth_tmp, len, "Authentication: user %s:%s\r\n\r\n", sock->url->usr, sock->url->pwd);
	}
	else
	{
		// If we do not have the auth info, we just add the end of header
		auth_len = 2;
		auth_tmp = "\r\n";
	}

	if (method == PKI_HTTP_METHOD_GET)
	{
		// Gets the right header
		head = head_get;

		// Estimate the header's final size
		max_len =
				strlen(head) +
				strlen(sock->url->path) +
				strlen(sock->url->addr) +
				101;

		// Allocates enough space for the header
		tmp = PKI_Malloc ( max_len + auth_len );

		// Prints the header into the tmp container
		len = (size_t) snprintf(tmp, max_len, head, sock->url->path, sock->url->addr, auth_tmp);
	}
	else if (method == PKI_HTTP_METHOD_POST)
	{
		// Gets the right head
		head = head_post;

		// Determines the right content type
		if ( content_type ) my_cont_type = content_type;
		else my_cont_type = "text/html";

		// Checks the max len for the allocated header
		max_len =
				strlen(head) +
				strlen(sock->url->path) +
				strlen(sock->url->addr) +
				strlen(my_cont_type) +
				101;

		// Allocates the memory for the header
		tmp = PKI_Malloc ( max_len + auth_len );

		// Prints the header into the tmp container
		len = (size_t) snprintf(tmp, max_len, head, sock->url->path, sock->url->addr, 
					my_cont_type, data_size, auth_tmp );
	}
	else
	{
		PKI_log_err ( "Method (%d) not supported!", method );
		return PKI_ERR;
	}

	// PKI_MEM *r = PKI_MEM_new_data(len, tmp);
	// URL_put_data("file://http_req.txt", r, NULL, NULL, 0, 0, NULL);
	// PKI_MEM_free(r);

	if ((rv = (int) PKI_SOCKET_write(sock, tmp, len)) < 0)
	{
		PKI_log_err("Can not write HTTP header to socket");
		PKI_Free(tmp);
		goto err;
	}

	// Free the tmp pointer that held the request header
	if (tmp) PKI_Free (tmp);

	// If we were using a POST method, we need to actually send the data
	if(data != NULL)
	{
		PKI_log_err("{DEBUG} Writing Data -> data_size = %d, data = %p", data_size, data);

		if ((PKI_SOCKET_write(sock, data, data_size)) < 0)
		{
			PKI_log_err ("Can not write POST to socket.");
			goto err;
		}
	}
	
	// Let's now wait for the response from the server
	if ((http_rv = PKI_HTTP_get_message(sock, timeout, max_size)) == NULL)
	{
		PKI_log_err ("HTTP retrieval error\n");
		goto err;
	}

	// We shall now check for the return code
	if (http_rv->code >= 400 )
	{
		goto err;
	}
	else if (http_rv->code >= 300)
	{
		/* Redirection - let's try that */
		if (http_rv->location == NULL)
		{
			PKI_log_debug ( "HTTP Redirection but no location provided!");
			goto err;
		}

		PKI_log_debug("HTTP Redirection Location ==> %s", http_rv->location );

		if (strstr(http_rv->location, "://") != NULL)
		{
			URL *url_tmp = NULL;

			if( strncmp_nocase( http_rv->location, sock->url->url_s, 
					(int) strlen(http_rv->location)) == 0)
			{
				PKI_log_debug( "HTTP cyclic redirection!");
				goto err;
			}

			if ((url_tmp = URL_new ( http_rv->location )) == NULL)
			{
				PKI_log_debug("HTTP location is not a valid URI (%s)", http_rv->location );
				goto err;
			}

			if ( sock->url->ssl == 0 )
			{
				ret = PKI_HTTP_get_url ( url_tmp, data, 
					data_size, content_type, method, timeout, 
							max_size, sk, NULL );
			}
			else
			{
				PKI_SSL *ssl2 = PKI_SSL_dup ( sock->ssl );

				ret = PKI_HTTP_get_url ( url_tmp, data, 
					data_size, content_type, method, timeout, 
							max_size, sk, ssl2 );
			}

			if ( url_tmp ) URL_free ( url_tmp );
	
			goto end;

		}
		else
		{
			const char *prot_s = NULL;
			char new_url[2048];
			URL *my_new_url = NULL;
			PKI_SSL *ssl2 = PKI_SSL_dup ( sock->ssl );

			prot_s = URL_proto_to_string ( sock->url->proto );
			if( !prot_s ) goto err;

			snprintf(new_url, sizeof(new_url),"%s://%s%s", prot_s, sock->url->addr, http_rv->location );

			if( strncmp_nocase( new_url, sock->url->url_s, (int) strlen ( new_url )) == 0 )
			{
				PKI_log_debug( "HTTP cyclic redirection!");
				goto err;
			}

			my_new_url = URL_new ( new_url );

			ret = PKI_HTTP_get_url ( my_new_url, data, data_size, content_type, method,
						timeout, max_size, sk, ssl2 );

			if (ssl2) PKI_SSL_free ( ssl2 );
		}
	}
	else if (http_rv->code != 200)
	{
		PKI_log_debug( "HTTP Return code not manageable (%d)", http_rv->code );
		goto err;
	}

	PKI_log_err("{DEBUG} method = %d, header->size = %d, body = %p, body_size = %d",
			  http_rv->method, http_rv->head->size, http_rv->body, http_rv->body->size);

	URL_put_data("file://http-resp-header.txt", http_rv->head, NULL, NULL, 0, 0, NULL);
	URL_put_data("file://http-resp-data.txt", http_rv->body, NULL, NULL, 0, 0, NULL);

	// If a Pointer was provided, we want the data back
	if (sk)
	{
		// Checks if the caller provided an already allocated data
		// structure. If not, we allocate it.
		if (*sk == NULL)
		{
			if ((*sk = PKI_STACK_MEM_new()) == NULL)
			{
				PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
				goto err;
			}
		}

		// Add the returned value to the stack
		if (PKI_STACK_MEM_push(*sk, http_rv->body) != PKI_OK)
		{
			PKI_log_err("Can not push the HTTP result body in the result stack");
			goto err;
		}

		// Remove ownership of the body PKI_MEM from the original
		// HTTP msg container
		http_rv->body = NULL;
	}

end:
	// Finally free the HTTP message memory
	if ( http_rv ) PKI_HTTP_free ( http_rv );

	// Returns the result
	return ret;

err:
	// Error condition
	if ( http_rv ) PKI_HTTP_free ( http_rv );
	return PKI_ERR;
}

/* ------------------------------- HTTP GET --------------------------- */

/*! \brief Returns the data from an HTTP source by using the GET command */

int PKI_HTTP_GET_data (const char     * url_s,
	               int              timeout,
		       size_t           max_size,
		       PKI_MEM_STACK ** ret,
		       PKI_SSL  * ssl ) {

	URL *url = NULL;
	int rv = PKI_OK;

	if( !url_s ) return PKI_ERR;

	if((url = URL_new( url_s )) == NULL ) {
		return PKI_ERR;
	}

	rv = PKI_HTTP_get_url ( url, NULL, 0, NULL,
			PKI_HTTP_METHOD_GET, timeout, max_size, ret, ssl );

	if ( url ) URL_free ( url );
	return rv;
}

/*! \brief Returns the data from an HTTP URL by using the GET command */

int PKI_HTTP_GET_data_url (const URL      * url,
		                   int              timeout,
						   size_t           max_size,
					       PKI_MEM_STACK ** ret,
						   PKI_SSL  * ssl ) {

	if ( !url ) return PKI_ERR;

	return PKI_HTTP_get_url ( url, NULL, 0, NULL,
			PKI_HTTP_METHOD_GET, timeout, max_size, ret, ssl );
}

/*! \brief Returns HTTP data from a PKI_SOCKET by using the GET command */

int PKI_HTTP_GET_data_socket (const PKI_SOCKET * sock,
		                      int                timeout,
							  size_t             max_size,
					          PKI_MEM_STACK   ** ret ) {

	if ( !sock ) return PKI_ERR;

	return PKI_HTTP_get_socket ( sock, NULL, 0, NULL,
			PKI_HTTP_METHOD_GET, timeout, max_size, ret );
}

/* ------------------------------- HTTP POST --------------------------- */

/*! \brief Use POST method to transfer data via HTTP. If a pointer to a
 *         PKI_MEM_STACK (eg., &stack) is provided, the returned data isi
 *         added to it
 */

int PKI_HTTP_POST_data (const char     * url_s,
		                const char     * data,
						size_t           size,
			            const char     * content_type,
						int              timeout,
						size_t           max_size,
				        PKI_MEM_STACK ** ret_sk,
						PKI_SSL  * ssl ) {

	URL *url = NULL;
	int ret = PKI_OK;

	if( !url_s || !data || !content_type ) {
		/* ERROR: All data are strictly required! */
		return PKI_ERR;
	}

	if((url = URL_new(url_s)) == NULL ) {
		/* Error in creating the URL structure */
		return PKI_ERR;
	}

	ret = PKI_HTTP_get_url ( url, data, size, content_type,
			PKI_HTTP_METHOD_POST, timeout, max_size, ret_sk, ssl);

	if ( url ) URL_free (url);

	return ret;
}

/*! \brief Use POST method to transfer data via HTTP. If a pointer to a
 *         PKI_MEM_STACK (eg., &stack) is provided, the returned data is
 *         added to it
 */

int PKI_HTTP_POST_data_url (const URL    * url,
		                    const char   * data,
							size_t         size,
			                const char   * content_type,
							int            timeout,
							size_t         max_size,
				            PKI_MEM_STACK **ret_sk,
							PKI_SSL *ssl ) {


	if ( !url ) return PKI_ERR;

	return PKI_HTTP_get_url ( url, data, size, content_type,
			PKI_HTTP_METHOD_POST, timeout, max_size, ret_sk, ssl);
}

/*! \brief Use POST method to transfer data via HTTP. If a pointer to a
 *         PKI_MEM_STACK (eg., &stack) is provided, the returned data is
 *         added to it
 */

int PKI_HTTP_POST_data_socket (const PKI_SOCKET * sock,
		                       const char       * data,
							   size_t             size,
			                   const char       * content_type,
							   int                timeout,
							   size_t             max_size,
				               PKI_MEM_STACK   ** ret_sk ) {


	if ( !sock ) return PKI_ERR;

	return PKI_HTTP_get_socket ( sock, data, size, content_type,
			PKI_HTTP_METHOD_POST, timeout, max_size, ret_sk );
}

