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

PKI_MEM *PKI_MEM_new_data ( size_t size, unsigned char *data ) {

	PKI_MEM *ret = NULL;

	if( !data || size == 0 ) return ( NULL );

	if((ret = PKI_MEM_new ( size )) == NULL ) {
		return ( NULL );
	}

	memcpy(ret->data, data, size);

	return ( ret );
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

	// fprintf( stderr, "BIO MEM PTR => %p [%d]\n", 
	// 			bio_mem_ptr, bio_mem_ptr->length );
	//
	// if(( ret = PKI_MEM_new_null()) == NULL ) {
	// 	if( bio_mem ) BIO_free ( bio_mem );
	// 	return NULL;
	// }

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

	PKI_ZFree(buf->data, buf->size);
	buf->data = NULL;

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

int PKI_MEM_add( PKI_MEM *buf, char *data, size_t data_size ) {
	
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

		return ret;
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

void *PKI_Malloc( size_t size ) {

	void *ret = NULL;

	if ( size <= 0 ) return NULL;

	if((ret = (void *) malloc( size )) != NULL ) {
		memset(ret, 0, size );
	};

	return (ret);
}

/*! \brief Frees memory associated with a pointer (allocated with PKI_Malloc) */

void PKI_Free( void *ret ) {
	
	if( ret == NULL ) return;

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

PKI_MEM *PKI_MEM_get_url_encoded(PKI_MEM *mem, int skip_newlines)
{
	PKI_MEM *encoded = NULL;

	char enc_buf[10];
	int i = 0;

	if( !mem || !mem->data || (mem->size == 0) )
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	if((encoded = PKI_MEM_new_null()) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	for( i = 0; i < mem->size; i++ )
	{
		char *str = "=$&+,/:;=?@ <>#\%{}|\\^~[]\r\n`";
		unsigned char tmp_d2 = 0;

		if (skip_newlines && ( mem->data[i] == '\r' || mem->data[i] == '\n')) continue;

		tmp_d2 = mem->data[i];
		if ((strchr( str, tmp_d2 ) != NULL ) ||
			(tmp_d2 <= 31) || ( tmp_d2 >= 127 ) || (isgraph(tmp_d2) == 0))
		{
			sprintf(enc_buf, "%%%2.2x", tmp_d2 );
			PKI_MEM_add ( encoded, enc_buf, 3 );
		}
		else
		{
			PKI_MEM_add ( encoded, (char *) &(mem->data[i]), 1);
		}
	}

	return encoded;
}

PKI_MEM *PKI_MEM_get_url_decoded(PKI_MEM *mem, int skip_newlines)
{
	PKI_MEM *decoded = NULL;
	ssize_t data_size = 0;
	unsigned char *data = NULL;
	int i = 0;

	if(!mem || !mem->data || (mem->size == 0) )
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	// Allocates the new PKI_MEM for the decoding operations
	if((decoded = PKI_MEM_new_null()) == NULL)
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
			PKI_MEM_add(decoded, (char *) &k, 1);
			i += 2;
		}
		else
		{
			PKI_MEM_add(decoded, (char*) &data[i], 1);
		}
	}

	// Returns the newly allocated url-decoded PKI_MEM
	return decoded;
}

/*! \brief Returns a new PKI_MEM with a URL-safe encoded version of a PKI_MEM */

int PKI_MEM_url_encode(PKI_MEM *mem, int skip_newlines)
{
	PKI_MEM *encoded = NULL;

	if ((encoded = PKI_MEM_get_url_encoded(mem, skip_newlines)) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return PKI_ERR_MEMORY_ALLOC;
	}

	// Clears the memory for the old PKI_MEM
	if (mem->data) PKI_Free(mem->data);

	// Transfer ownership of the data
	mem->data = encoded->data;
	mem->size = encoded->size;

	// Clears the encoded data container
	encoded->data = NULL;
	encoded->size = 0;

	// Free the newly-allocated (now empty) container
	PKI_MEM_free(encoded);

	// Returns success
	return PKI_OK;
}


/*! \brief Decodes a URL-encoded PKI_MEM and returns the pointer to
 *         the same PKI_MEM object if successful, NULL otherwise */

int PKI_MEM_url_decode(PKI_MEM *mem, int skip_newlines)
{
	PKI_MEM *decoded = NULL;

	if ((decoded = PKI_MEM_get_url_decoded(mem, skip_newlines)) == NULL)
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
		PKI_MEM_add( pki_mem, buf_mem->data, (size_t) buf_mem->length );
	}

	return( pki_mem );
}

/*! \brief Returns a PKI_MEM with the contents read from the PKI_IO */

PKI_MEM *PKI_MEM_new_bio(PKI_IO *io, PKI_MEM **mem)
{
	unsigned char buf[1024];

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
			if (i > 0) PKI_MEM_add(my_mem, (char *)buf, (size_t) i);
		}
	}

	return my_mem;
}

/*! \brief Encodes the contents of a PKI_MEM in B64 format. If the second parameter
 *         is not 0, the resulting encoding is presented on a single line (no line
 *         breaks will be added to the resulting PKI_MEM */

PKI_MEM *PKI_MEM_B64_encode (PKI_MEM *der, int skipNewLines)
{
	PKI_IO *b64 = NULL;
	PKI_IO *bio = NULL;
	PKI_MEM *ret_mem = NULL;

	if(!(b64 = BIO_new(BIO_f_base64()))) {
		return NULL;
	}

	if (skipNewLines != 0)
	{
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	}

	if(!(bio = BIO_new(BIO_s_mem()))) {
		BIO_free_all ( b64 );
		return NULL;
	}

	bio = BIO_push(b64, bio);
	BIO_write ( bio, der->data, (int) der->size );
	(void) BIO_flush (bio);
	bio = BIO_pop ( bio );
	BIO_free ( b64 );

	/* Now we get back the info from the bio */
	if((ret_mem = PKI_MEM_new_bio( bio, NULL )) != NULL)
	{
		// Free the old data
		PKI_Free ( der->data );

		// Get the new data from the ret_mem
		der->data = ret_mem->data;
		der->size = ret_mem->size;

		// Free the ret_mem
		PKI_Free ( ret_mem );

		// The new data might have an ending EOL added to it, let's get
		// rid of it
		size_t size = der->size;
		while(size > 0)
		{
			if (der->data[size] == '\n' || der->data[size] == '\r' || der->data[size] == '\x0')
			{
				if (der->data[size] != '\x0') der->size--;
				der->data[size] = '\x0';
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

	return der;
}

/*! \brief Decodes a PKI_MEM from B64. The second parameter controls the format of the
 *         expected B64 data. If set to negative values, the B64 data is expected to be
 *         on one line, if set to positive values, the data is expected to be on multiple
 *         lines. If set to 0, the data is assumed to be separated in 76 chars lines. */

PKI_MEM *PKI_MEM_B64_decode ( PKI_MEM *b64_mem, int lineSize ) {

	PKI_MEM *ret_mem = NULL;
	PKI_IO *b64 = NULL;
	PKI_IO *bio = NULL;
	int i = 0;
	int64_t size = 0;
	char buf[1024];
	unsigned char *tmp_ptr;

	if(!(b64 = BIO_new(BIO_f_base64()))) {
		return NULL;
	};

	if (lineSize <= 0) BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	if(!(bio = BIO_new(BIO_s_mem()))) {
		BIO_free_all ( b64 );
		return NULL;
	}

	/* Let's write the data first */
	/* It seems that OpenSSL has a max line length of 76, so we need linebreaks */
	// so we can not use this: BIO_write ( bio, b64_mem->data, b64_mem->size );
	size = (int64_t) b64_mem->size;
	tmp_ptr = b64_mem->data;

	// Let's write the file in chunks of lineSize (default 76)
	if (lineSize > 0)
	{
		if (lineSize > 76) lineSize = 76;
		while (size > lineSize)
		{
			BIO_write(bio, tmp_ptr, (int) lineSize);
			BIO_write(bio, "\n", 1);

			size -= lineSize;
			tmp_ptr += lineSize;
		}
		BIO_write(bio, tmp_ptr, (int) size);
	}
	else
	{
		BIO_write(bio, b64_mem->data, (int) b64_mem->size);
	}

	bio = BIO_push(b64, bio);
	ret_mem = PKI_MEM_new_null();
	do {
		i = BIO_read ( bio, buf, sizeof (buf));
		if ( i > 0 ) {
			size = (size_t) i;
			PKI_MEM_add(ret_mem, buf, (size_t) size );
		}
	} while ( i > 0 );

	(void)BIO_flush(bio);
	bio = BIO_pop(bio);
	BIO_free( b64 );
	BIO_free( bio );

	if ( ret_mem->size > 0 ) {
		PKI_Free ( b64_mem->data );
		b64_mem->data = ret_mem->data;
		b64_mem->size = ret_mem->size;
		PKI_Free ( ret_mem );
	} else {
		PKI_Free ( ret_mem );
		return PKI_ERR;
	}

	return b64_mem;
}
