/* OpenCA libpki package
* (c) 2000-2007 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#include <libpki/pki.h>

/*! \brief Returns a new PKI_MEM object with no data associated with it */

PKI_MEM *PKI_MEM_new_null ( void ) {

	PKI_MEM *ret = NULL;

	ret = PKI_Malloc ( sizeof( PKI_MEM ));
	if( !ret ) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return (NULL);
	};

	return (ret);
}

/*! \brief Returns a new PKI_MEM object with size allocated data */

PKI_MEM *PKI_MEM_new ( size_t size ) {
	PKI_MEM *ret = NULL;

	ret = PKI_MEM_new_null();
	if( !ret ) return (NULL);

	ret->data = PKI_Malloc ( size );
	if( !ret->data ) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		PKI_MEM_free ( ret );
		return (NULL);
	}
	ret->size = size;

	return(ret);
}

/*!  \brief Returns a new PKI_MEM object with a copy of the data passed as arg
 */

PKI_MEM *PKI_MEM_new_data ( size_t size, const unsigned char *data ) {

	PKI_MEM *ret = NULL;

	if (size == 0) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	if ((ret = PKI_MEM_new(size)) == NULL) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	if (data) memcpy(ret->data, data, size);
	else memset(ret->data, 0, size);

	return ret;
}

/*! \brief Duplicates a PKI_MEM */

PKI_MEM *PKI_MEM_dup ( PKI_MEM *mem ) {
	if (!mem) return NULL;

	return PKI_MEM_new_data ( mem->size, mem->data );
}


/*! \brief Returns a PKI_MEM with the contents decoded via a function 
 *
 * Returns a new PKI_MEM object filled with the data from an object
 * and its renderer function from func which accepts BIO * and data *
 * as its input.
 */

PKI_MEM *PKI_MEM_new_func ( void *obj, int (*func)(void *, unsigned char **p)) {

	size_t size = 0;
	int i = 0;
	PKI_MEM * ret = NULL;

	if (!obj || !func ) return NULL;

	if((i =  func ( obj, NULL)) <= 0 ) {
		return NULL;
	}

	size = (size_t) i;

	if((ret = PKI_MEM_new ( size )) == NULL ) {
		return NULL;
	}

	if ( !func(obj, &(ret->data)) ) {
		PKI_MEM_free ( ret );
		return NULL;
	}

	return ret;
}


/*! \brief Returns the content from a BIO after dec it with func(BIO*,void*) */

PKI_MEM *PKI_MEM_new_func_bio ( void *obj, int (*func)(BIO *, void *) ) {

	BIO *bio_mem = NULL;
	PKI_MEM *ret = NULL;

	BUF_MEM *bio_mem_ptr = NULL;

	int i = 0;
	size_t size = 0;

	if (!obj || !func ) {
		return NULL;
	}

	if(( bio_mem = BIO_new(BIO_s_mem())) == NULL ) {
		return NULL;
	}

	// fprintf( stderr, "BIO=>%p -- OBJ=>%p\n", bio_mem, obj );
	if((i = func( bio_mem, obj )) <= 0 ) {
		return NULL;
	}

	BIO_get_mem_ptr( bio_mem, &bio_mem_ptr );

	if ( bio_mem_ptr == NULL ) {
		if( bio_mem ) BIO_free ( bio_mem );
		return ( NULL );
	}

	/* Adds the data to the return PKI_MEM */
	size = (size_t) bio_mem_ptr->length;
	ret = PKI_MEM_new_data( size, (unsigned char *) bio_mem_ptr->data);

	/* Closes the BIO and frees the memory */
	if( bio_mem ) BIO_free ( bio_mem );

	return ( ret );

}


void PKI_MEM_free_void ( void *buf ) {
	PKI_MEM_free( (PKI_MEM *) buf);
}

/*! \brief Frees the memory associated with a PKI_MEM, returns 1 */

int PKI_MEM_free ( PKI_MEM *buf ) {

	if( !buf ) return (0);

	if (buf->data)
	{
		PKI_ZFree(buf->data, buf->size);
		buf->data = NULL;
	}

	PKI_ZFree(buf, sizeof(PKI_MEM));

	return 1;
}

/*! \brief Grows the allocated size of data_size bytes */

int PKI_MEM_grow( PKI_MEM *buf, size_t data_size )
{
	size_t new_size = 0;

	if (!buf) return PKI_ERR;

	if (buf->data == NULL)
	{
		buf->data = PKI_Malloc(data_size);

		if (!buf->data)
		{
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			return (PKI_ERR);
		}
		
		buf->size = data_size;
	}
	else
	{
		new_size = buf->size + data_size;
		buf->data = realloc(buf->data, new_size);
		buf->size = new_size;
	}

	return ((int) buf->size);
}

/*! \brief Adds the passed data to a PKI_MEM */

int PKI_MEM_add( PKI_MEM *buf, const unsigned char *data, size_t data_size ) {
	
	size_t curr_size = 0;

	if( (!buf) || (!data) || (data_size == 0) ) {
		return (PKI_ERR);
	}

	curr_size = PKI_MEM_get_size ( buf );

	if( PKI_MEM_grow( buf, data_size ) == 0 ) {
		PKI_log_err("Can not mem grow!");
		return (PKI_ERR);
	}

	memcpy(buf->data + curr_size, data, data_size );

	return( PKI_OK );
}

/*! \brief Returns the pointer to the data within a PKI_MEM datastructure */

unsigned char * PKI_MEM_get_data( PKI_MEM *buf ) {

	if (!buf ) { 
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return (PKI_ERR);
	};

	return( buf->data );
}

/*! \brief Returns the size of the data within a PKI_MEM datastructure */

size_t PKI_MEM_get_size( PKI_MEM *buf ) {

	if( !buf || !buf->data ) {
		if(!buf) PKI_ERROR(PKI_ERR_POINTER_NULL, NULL);
		return (0);
	};

	return( buf->size );
}

/*! \brief Returns the contents of the PKI_MEM in a string which is guaranteed
 *         to carry all the contents of the original PKI_MEM and terminated (at
 *         size + 1) with a NULL char.
 */
char * PKI_MEM_get_parsed(PKI_MEM *buf)
{
	char *ret = NULL;

	if (!buf || !buf->data) return NULL;

	if (buf->size < 1)
	{
		ret = PKI_Malloc(1);
		*ret = '\x0';

		return
				ret;
	}

	ret = PKI_Malloc(buf->size + 1);
	if (!ret)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	memcpy(ret, buf->data, buf->size);
	ret[buf->size] = '\x0';

	return ret;

}

/*! \brief Allocates size bytes of memory, zeroize it, and returns the pointer
 *         to the beginning of the memory region
 */

void *PKI_Malloc( size_t size )
{
	void *ret = NULL;

	// Checks we have a sensitive size to malloc
	if ( size == 0 ) return NULL;

	// Allocates and zeroize memory (this might prevent
	// some cross-process / cross-thread information leaking)
#ifdef HAVE_CALLOC
	ret = calloc(1, size);
#else
	if ((ret = (void *) malloc( size )) != NULL)
		memset(ret, 0, size );
#endif

	// Returns the pointer to the allocated memory
	return (ret);
}

/*! \brief Frees memory associated with a pointer (allocated with PKI_Malloc) */

void PKI_Free( void *ret )
{
	// Checks we have a valid pointer
	if( ret == NULL ) return;
	
	// Frees the associated memory
	free ( ret );

	return;
}

/*! \brief Frees and Zeroizes memory associated with a pointer */

void PKI_ZFree ( void *pnt, size_t size ) {

	/* Check the Input */
	if (!pnt) return;

	/* If No size is provided, normal PKI_Free() is used */
	if ( size <= 0 ) return PKI_Free ( pnt );

	/* Zeroize the Memory */
	memset( pnt, '\xFF', size );

	/* Free The Memory */
	PKI_Free ( pnt );

	return;
}

/*! \brief Frees and Zeroizes memory associated with a string */

void PKI_ZFree_str ( char *str ) {

	if ( str == NULL ) return;

	/* Wipe the String's Memory */
	memset( str, '\xFF', strlen(str));

	PKI_Free ( str );

	return;
}

/*! \brief Prints the content of a PKI_MEM to stdout */

ssize_t PKI_MEM_printf( PKI_MEM * buf ) {

	return PKI_MEM_fprintf( stdout, buf );
}

/*! \brief Prints the content of a PKI_MEM to a FILE pointer */

ssize_t PKI_MEM_fprintf( FILE *file, PKI_MEM *buf ) {

	ssize_t i = 0;

	if ( !buf ) return 0;

	for (i = 0; i < buf->size; i++ ) {
		fprintf(file, "%c", buf->data[i]);
	}

	return i;
}

/*! \brief Returns a PKI_MEM with the contents of a memory PKI_IO */

PKI_MEM *PKI_MEM_new_membio ( PKI_IO *io ) {

	BUF_MEM *buf_mem = NULL;
	PKI_MEM *pki_mem = NULL;

	if( !io ) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return ( NULL );
	}

	/* Copy the data from the BIO to the PKI_MEM structure */
	BIO_get_mem_ptr( io, &buf_mem);

	if( buf_mem ) {
		if((pki_mem = PKI_MEM_new_null()) == NULL ) {
			return ( NULL );
		}
		PKI_MEM_add( pki_mem, (const unsigned char *)buf_mem->data, (size_t) buf_mem->length );
	}

	return( pki_mem );
}

/*! \brief Returns a PKI_MEM with the contents read from the PKI_IO */

PKI_MEM *PKI_MEM_new_bio(PKI_IO *io, PKI_MEM **mem)
{
	unsigned char buf[4096];

	PKI_MEM *my_mem = NULL;

	if (!io) return NULL;

	if (mem != NULL)
	{
		if (*mem)
		{
			my_mem = *mem;
		}
		else
		{
			*mem = PKI_MEM_new_null();
			my_mem = *mem;
		}
	}
	else
	{
		my_mem = PKI_MEM_new_null();
	}
	
	if (!my_mem) return NULL;

	{
		int i = -1;
		for (i = BIO_read(io, buf, sizeof(buf)); i > 0; i = BIO_read(io, buf, sizeof(buf)))
		{
			if (i > 0) PKI_MEM_add(my_mem, buf, (size_t) i);
		}
	}

	return my_mem;
}

/*! \brief Returns a new B64-encoded PKI_MEM.
 *
 * @param mem The first parameter should be a pointer to a valid PKI_MEM container.
 * @param skipNewLines The second parameter controls the format of the B64 data. If
 *     set to non-0 values, the encoded data will be bound with new lines every 76
 *     chars. Otherwise (if 0) no line breaks will be added to the resulting PKI_MEM.
 * @return This function returns a new PKI_MEM container with the B64-encoded content
 */

PKI_MEM *PKI_MEM_get_b64_encoded (PKI_MEM *mem, int addNewLines)
{
	PKI_IO *b64 = NULL;
	PKI_IO *bio = NULL;

	PKI_MEM *encoded = NULL;

	if(!(b64 = BIO_new(BIO_f_base64()))) {
		return NULL;
	}

	// Sets the flag to not output any new-line (only one line)
	if (addNewLines == 0) BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	if(!(bio = BIO_new(BIO_s_mem()))) {
		BIO_free_all ( b64 );
		return NULL;
	}

	bio = BIO_push(b64, bio);
	BIO_write ( bio, mem->data, (int) mem->size );
	(void) BIO_flush (bio);
	bio = BIO_pop ( bio );
	BIO_free ( b64 );

	/* Now we get back the info from the bio */
	if((encoded = PKI_MEM_new_bio( bio, NULL )) != NULL)
	{
		// The new data might have an ending EOL added to it, let's get
		// rid of it
		size_t size = encoded->size;
		while (size > 0)
		{
			if (encoded->data[size] == '\n' || encoded->data[size] == '\r' || encoded->data[size] == '\x0')
			{
				if (encoded->data[size] != '\x0') encoded->size--;
				encoded->data[size] = '\x0';
				size--;
			}
			else break;
		}
	}
	else
	{
		BIO_free ( bio );
		return NULL;
	}

	BIO_free ( bio );

	return encoded;
}

/*! \brief Returns a new PKI_MEM from a B64-encoded one.
 *
 * @param b64_mem The first parameter should be a pointer to a valid PKI_MEM container.
 * @param withNewLines The second parameter controls the format of the expected B64 data. If set to
 *    negative values, the B64 data is expected to be on one line, if set to positive
 *    values, the data is expected to be on multiple lines. If set to 0, the data is
 *    assumed to be separated in 76 chars lines.
 * @return This function returns a new PKI_MEM container with the B64-decoded content
 */

PKI_MEM *PKI_MEM_get_b64_decoded(PKI_MEM *mem, int withNewLines)
{
	PKI_MEM *decoded = NULL;

	PKI_IO *b64 = NULL;
	PKI_IO *bio = NULL;

	int n = 0;

	char buf[4096];

	if (!(b64 = BIO_new(BIO_f_base64()))) return NULL;
	if (withNewLines <= 0) BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	if ((bio = BIO_new_mem_buf(mem->data, (int) mem->size)) == NULL)
	{
		BIO_free_all(b64);
		return NULL;
	}
	BIO_push(b64, bio);

	if ((decoded = PKI_MEM_new_null()) == NULL)
	{
		BIO_free_all(b64);
		return NULL;
	}

	while ((n = BIO_read(b64, buf, sizeof(buf))) > 0)
	{
		PKI_MEM_add(decoded, (const unsigned char *)buf, (size_t)n);
	}
	BIO_free_all(b64);

	return decoded;
}

/*! \brief Returns a new URL-encoded PKI_MEM.
 *
 * @param mem The first parameter should be a pointer to a valid PKI_MEM container.
 * @param skipNewLines If set to anything but 0, new line characters (\n and \r)
 *    will be skipped (and, thus, NOT encoded).
 * @return This function returns a new PKI_MEM container with the URL-encoded content
 */

PKI_MEM *PKI_MEM_get_url_encoded(PKI_MEM *mem, int skipNewLines)
{
	PKI_MEM *encoded = NULL;

	unsigned char enc_buf[1024];

	int i = 0;
	size_t enc_idx = 0;

	if (!mem || !mem->data || (mem->size == 0))
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	if ((encoded = PKI_MEM_new_null()) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	for( i = 0; i < mem->size; i++ )
	{
		char *str = "=$&+,/:;=?@ <>#\%{}|\\^~[]\r\n`";
		unsigned char tmp_d2 = 0;

		if (skipNewLines && (mem->data[i] == '\r' || mem->data[i] == '\n')) continue;

		tmp_d2 = mem->data[i];
		if ((strchr( str, tmp_d2 ) != NULL ) ||
			(tmp_d2 <= 31) || ( tmp_d2 >= 127 ) || (isgraph(tmp_d2) == 0))
		{
			enc_idx += (size_t) sprintf((char *)&enc_buf[enc_idx], "%%%2.2x", tmp_d2 );
			// PKI_MEM_add ( encoded, enc_buf, 3 );
		}
		else
		{
			// PKI_MEM_add ( encoded, (char *) &(mem->data[i]), 1);
			enc_buf[enc_idx++] = mem->data[i];
		}

		// Let's check if it is time to move the buffer contents into the
		// PKI_MEM. If so, let's transfer the content and reset the buffer
		// index
		if (enc_idx >= sizeof(enc_buf) - 4)
		{
			PKI_MEM_add(encoded, enc_buf, enc_idx);
			enc_idx = 0;
		}
	}

	// If there is something left in the buffer that needs to be added
	// we add it
	if (enc_idx > 0) PKI_MEM_add(encoded, enc_buf, enc_idx);

	// Let's now return the encoded PKI_MEM
	return encoded;
}

/*! \brief Returns a new URL-decoded PKI_MEM.
 *
 * @param mem The first parameter should be a pointer to a valid PKI_MEM container.
 * @return This function returns a new PKI_MEM container with the URL-encoded content
 */

PKI_MEM *PKI_MEM_get_url_decoded(PKI_MEM *mem)
{
	PKI_MEM *decoded = NULL;
	unsigned char *data = NULL;

	int i = 0;
	size_t enc_idx = 0;

	if(!mem || !mem->data || (mem->size == 0) )
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	// Let's allocate a big buffer - same size of the encoded one
	// is enough as URL encoding expands the size (decoded is smaller)
	if ((data = PKI_Malloc(mem->size)) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	// Let's do the decoding
	for( i = 0; i < mem->size; i++ )
	{
		int p;
		unsigned char k;

		if (sscanf((const char *)&mem->data[i], "%%%2x", &p) > 0)
		{
			k = (unsigned char) p;
			data[enc_idx++] = k;
			i += 2;
		}
		else
		{
			data[enc_idx++] = mem->data[i];
		}
	}

	// Allocates the new PKI_MEM for the decoding operations
	if((decoded = PKI_MEM_new_data(enc_idx, data)) == NULL)
	{
		PKI_Free(data);
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	// Free the allocated memory
	PKI_Free(data);

	// Returns the newly allocated url-decoded PKI_MEM
	return decoded;
}

/*! \brief Returns a new PKI_MEM whose content is encoded according to the selected format.
 *
 * @param mem The first parameter should be a pointer to a valid PKI_MEM container.
 * @param format The second parameter controls the encoding format. Supported formats
 *    are PKI_DATA_FORMAT_B64 and PKI_DATA_FORMAT_URL.
 * @param opts The third parameter is format-specific. For B64 encoding, if this
 *    parameter is set to anything but 0, the encoded data will be bound with new lines
 *    every 76 chars. For URL encoding, if this parameter is set to anything but 0, new
 *    line characters (\n and \r) will be skipped (and, thus, NOT encoded).
 * @return This function returns a new PKI_MEM container with the encoded content.
 */

PKI_MEM * PKI_MEM_get_encoded(PKI_MEM *mem, PKI_DATA_FORMAT format, int opts)
{
	if (!mem || !mem->data)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	// Let's check the available encodings
	switch (format)
	{
		case PKI_DATA_FORMAT_B64:
			return PKI_MEM_get_b64_encoded(mem, opts);
			break;

		case PKI_DATA_FORMAT_URL:
			return PKI_MEM_get_url_encoded(mem, opts);
			break;

		default:
			// Unknown data format
			PKI_ERROR(PKI_ERR_DATA_FORMAT_UNKNOWN, NULL);
	}

	// If we reach here, it means no valid format was detected
	return NULL;
}

/*! \brief Returns a new PKI_MEM whose content is decoded according to the selected format.
 *
 * @param mem The first parameter should be a pointer to a valid PKI_MEM container.
 * @param format The second parameter controls the format to be decoded. Supported
 *    formats are PKI_DATA_FORMAT_B64 and PKI_DATA_FORMAT_URL.
 * @param opts The third parameter is format-specific. For B64 decoding, if this
 *    parameter is set to anything but 0, the decoded data will be bound with new lines
 *    every 76 chars (Max). For URL encoding, this parameter has no effect.
 * @return This function returns a new PKI_MEM container with the encoded content.
 */

PKI_MEM * PKI_MEM_get_decoded(PKI_MEM *mem, PKI_DATA_FORMAT format, int opts)
{
	if (!mem || !mem->data)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	// Let's check the available encodings
	switch (format)
	{
		case PKI_DATA_FORMAT_B64:
			return PKI_MEM_get_b64_decoded(mem, opts);
			break;

		case PKI_DATA_FORMAT_URL:
			return PKI_MEM_get_url_decoded(mem);
			break;

		default:
			// Unknown data format
			PKI_ERROR(PKI_ERR_DATA_FORMAT_UNKNOWN, NULL);
	}

	// If we reach here, it means no valid format was detected
	return NULL;
}

/* !\brief Encodes the contents of a PKI_MEM according to the provided data format.
 *
 * @param mem The first parameter should be a pointer to a valid PKI_MEM container.
 * @param format The second parameter controls the format to be encoded. Supported
 *    formats are PKI_DATA_FORMAT_B64 and PKI_DATA_FORMAT_URL.
 * @param opts The third parameter is format-specific. For B64 encoding, if this
 *    parameter is set to anything but 0, the encoded data will be bound with new lines
 *    every 76 chars. For URL encoding, if this parameter is set to anything but 0, new
 *    line characters (\n and \r) will be skipped (and, thus, NOT encoded).
 * @return PKI_OK if the decoding was successful. In case of errors, the appropriate
 *    error code is returned.
 */
int PKI_MEM_encode(PKI_MEM *mem, PKI_DATA_FORMAT format, int opts)
{
	PKI_MEM *encoded = NULL;

	if ((encoded = PKI_MEM_get_encoded(mem, format, opts)) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return PKI_ERR_MEMORY_ALLOC;
	}

	// Clears the memory for the old PKI_MEM
	// if (mem->data) PKI_Free(mem->data);

	// Transfer ownership of the data
	mem->data = encoded->data;
	mem->size = encoded->size;

	// Clears the encoded data container
	// encoded->data = NULL;
	// encoded->size = 0;

	// Free the newly-allocated (now empty) container
	// PKI_MEM_free(encoded);

	// Returns success
	return PKI_OK;
}

/*! \brief Decodes the contents of a PKI_MEM according to the selected format.
 *
 * @param mem The first parameter should be a pointer to a valid PKI_MEM container.
 * @param format The second parameter controls the format to be decoded. Supported
 *    formats are PKI_DATA_FORMAT_B64 and PKI_DATA_FORMAT_URL.
 * @param opts The third parameter is format-specific. For B64 decoding, if this
 *    parameter is set to anything but 0, the decoded data will be bound with new lines
 *    every 76 chars (Max). For URL encoding, this parameter has no effect.
 * @return PKI_OK if the decoding was successful. In case of errors, the appropriate
 *    error code is returned.
 */

int PKI_MEM_decode(PKI_MEM *mem, PKI_DATA_FORMAT format, int opts)
{
	PKI_MEM *decoded = NULL;

	if ((decoded = PKI_MEM_get_decoded(mem, format, opts)) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return PKI_ERR_MEMORY_ALLOC;
	}

	// Clears the memory for the old PKI_MEM
	if (mem->data) PKI_Free(mem->data);

	// Transfer ownership of the data
	mem->data = decoded->data;
	mem->size = decoded->size;

	// Clears the encoded data container
	decoded->data = NULL;
	decoded->size = 0;

	// Free the newly-allocated (now empty) container
	PKI_MEM_free(decoded);

	// Returns success
	return PKI_OK;
}
