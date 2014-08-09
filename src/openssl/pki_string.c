/* STRING management for libpki */

#include <libpki/pki.h>

/*!
 * \brief Create an empty PKI_STRING of type passed as the only argument
 */

PKI_STRING * PKI_STRING_new_null ( int type ) {
	return( PKI_STRING_new( type, NULL, 0 ));
}

/*! \brief Returns a new PKI_STRING of type and contents set from the passed
 *         parameters 
 */

PKI_STRING * PKI_STRING_new( int type, char * val, ssize_t size ) {
	PKI_STRING *ret = NULL;

	switch ( type ) {
		case PKI_STRING_IA5:
			ret = ASN1_IA5STRING_new();
			break;
		case PKI_STRING_UTF8:
			ret = ASN1_UTF8STRING_new();
			break;
		case PKI_STRING_BMP:
			ret = ASN1_BMPSTRING_new();
			break;
		case PKI_STRING_BIT:
			ret = ASN1_BIT_STRING_new();
			break;
		case PKI_STRING_OCTET:
			ret = ASN1_OCTET_STRING_new();
			break;
		case PKI_STRING_GENERAL:
			ret = ASN1_GENERALSTRING_new();
			break;
		case PKI_STRING_VISIBLE:
			ret = ASN1_VISIBLESTRING_new();
			break;
		case PKI_STRING_UNIVERSAL:
			ret = ASN1_UNIVERSALSTRING_new();
			break;
		case PKI_STRING_PRINTABLE:
		case PKI_STRING_NUMERIC:
		case PKI_STRING_T61:
		default:
			PKI_log_debug( "PKI STRING type %d not implemented",
				type );
			return ( NULL );
	}

	if(val)
	{
		if( size <= 0 ) 
		{
			ASN1_STRING_free(ret);
			return ( NULL );
		}

		if (PKI_STRING_set( ret, val, size ) != PKI_OK)
		{
			ASN1_STRING_free(ret);
			return NULL;
		}
	}

	return ( ret );
}

/*! \brief Duplicates a PKI_STRING data structure */

PKI_STRING * PKI_STRING_dup ( PKI_STRING *a )
{
	if (!a) return NULL;

	return ASN1_STRING_dup ( a );
}

/*! \brief Sets the content of a PKI_STRING */

int PKI_STRING_set( PKI_STRING *s, char *content, ssize_t size )
{
	// Checks the parameters
	if( !s || !content )
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return ( PKI_ERR );
	}

	// Sets the string - note that the content is copied by OSSL
	if (ASN1_STRING_set( s, content, (int) size ) < 0) return PKI_ERR;

	return PKI_OK;
}

/*! \brief Returns the type of the PKI_STRING (PKI_STRING_IA5, etc.) */

int PKI_STRING_get_type( PKI_STRING *s )
{
	int type = PKI_STRING_UNKNOWN;
	int ret = PKI_STRING_UNKNOWN;

	if( !s ) return ( ret );

	type = ASN1_STRING_type ( s );

	switch( type ) {
		case PKI_STRING_IA5:
		case PKI_STRING_UTF8:
		case PKI_STRING_BMP:
		case PKI_STRING_T61:
		case PKI_STRING_OCTET:
		case PKI_STRING_BIT:
			ret = type;
			break;
		default:
			ret = PKI_STRING_UNKNOWN;
	}

	return ( ret );
}

/*! \brief Returns the parsed value (char *) of the PKI_STRING (in UTF-8) */

char * PKI_STRING_get_parsed ( PKI_STRING *s )
{
	char * ret = NULL;
	unsigned short data;
	int size, i, type, count;

	if ( !s || !s->data || !s->length ) return NULL;

	type = PKI_STRING_get_type ( s );

	switch (type)
	{
		case PKI_STRING_IA5:
		case PKI_STRING_UTF8:
		case PKI_STRING_BMP:
		case PKI_STRING_T61:
			ret = PKI_STRING_get_utf8( s );
			break;

		case PKI_STRING_OCTET:
		case PKI_STRING_BIT:
			size = s->length * 3;
			if ((ret = PKI_Malloc((size_t) size + 1)) == NULL)
			{
				PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
				return NULL;
			}
			count = 0;
			for (i = 0; i < s->length ; i++)
			{
				data = s->data[i];
				sprintf(&ret[count], "%2.2x:", data );
				count += 3;
			};
			ret[count] = '\x0';
			break;
	}

	return ret;
}

/*! \brief Returns the parsed value (char *) of the PKI_STRING (in UTF-8) */

char * PKI_STRING_get_utf8( PKI_STRING *s ) {

	char *ret = NULL;

	if( !s ) return ( NULL );

	if((ASN1_STRING_to_UTF8( (unsigned char **) &ret, s )) < 0 ) {
		PKI_log_debug("Error, can not convert string to utf8!"
					" [type %d]", s->type );
		return NULL;
	}

	return ret;
}

/*!
 * 	\brief Returns the digest calculated on the string value
 */

PKI_DIGEST * PKI_STRING_get_digest ( PKI_STRING *s, PKI_DIGEST_ALG *digest ) {

	PKI_DIGEST *ret = NULL;

	if ( !s || !s->data || !s->length ) return NULL;

	if (!digest) digest = PKI_DIGEST_ALG_DEFAULT;

	if((ret = PKI_DIGEST_new(digest, s->data, (size_t) s->length)) == NULL)
	{
		PKI_ERROR(PKI_ERR_GENERAL, NULL);
	}

	return ret;
}


/*! \brief Releases the memory associated with a PKI_STRING */

void PKI_STRING_free( PKI_STRING *s ) {

	if( !s ) return;

	ASN1_STRING_free ( s );

	return;
}

/*! \brief Prints the contents of a PKI_STRING to Standard Output */

int PKI_STRING_print( PKI_STRING *s ) {
	return ( PKI_STRING_print_fp( stdout, s ));
}

/*! \brief Prints the contents of a PKI_STRING to a FILE pointer (eg., stdout)*/

int PKI_STRING_print_fp( FILE *fp, PKI_STRING *s ) {

	char *str = NULL;

	if( !s ) return ( PKI_ERR );

	if((str = PKI_STRING_get_utf8( s )) == NULL ) {
		return ( PKI_ERR );
	}

	fprintf( fp, "%s", str );

	PKI_Free( str );

	return ( PKI_OK );
}

/*! \brief Compares two ASN1 strings. Returns non-zero if the two string are equal */

int PKI_STRING_cmp(PKI_STRING *a, PKI_STRING *b)
{
	if (!a || !b) return -1;

	return ASN1_STRING_cmp(a, b);
}

