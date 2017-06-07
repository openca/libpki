/* PKI_INTEGER */

#include <libpki/pki.h>

/*! \brief Returns a PKI_INTEGER object from a string */

PKI_INTEGER *PKI_INTEGER_new_char( char *val ) {
	char *buf = NULL;
	PKI_INTEGER *ret = NULL;

	if(( buf = PKI_Malloc ( strlen(val) + 3 )) == NULL ) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	snprintf(buf, strlen(val)+3, "0x%s", val);

	ret = (PKI_INTEGER *) s2i_ASN1_INTEGER( NULL, buf );
	PKI_Free( buf );

	return( ret );
}

/*! \brief Returns a PKI_INTEGER object starting from a long long value */

PKI_INTEGER *PKI_INTEGER_new( long long val ) {

	PKI_INTEGER *ret = NULL;

	if((ret = (PKI_INTEGER *) ASN1_INTEGER_new()) == NULL ) {
		return ( NULL );
	}

	ASN1_INTEGER_set((ASN1_INTEGER *) ret, (long int) val );

	return( ret );
}

void PKI_INTEGER_free_void(void *i)
{
	PKI_INTEGER_free( (PKI_INTEGER *) i);
	return;
}

/*! \brief Frees memory associated with a PKI_INTEGER */

int PKI_INTEGER_free( PKI_INTEGER *i ) {

	if( !i ) return (PKI_ERR);

	ASN1_INTEGER_free( (ASN1_INTEGER *) i );

	return (PKI_OK);
}

/*! \brief Returns a string representation of the PKI_INTEGER */

char *PKI_INTEGER_get_parsed ( PKI_INTEGER *i ) {

	char *ret = NULL;

	if( !i ) return (NULL);

	ret = i2s_ASN1_INTEGER( NULL, (ASN1_INTEGER *) i );

	return( ret );

}

/*! \brief Compare two PKI_INTEGERs */

int PKI_INTEGER_cmp ( PKI_INTEGER *a, PKI_INTEGER *b ) {

	if (!a || !b ) return ( -1 );

	return ASN1_INTEGER_cmp( (ASN1_INTEGER *) a,
			(ASN1_INTEGER *) b );
}

/*! \brief Duplicates a PKI_INTEGER data structure */

PKI_INTEGER * PKI_INTEGER_dup ( PKI_INTEGER *a ) {

	if (!a ) return NULL;

	return ASN1_INTEGER_dup ( a );
}


/*! \brief Generate a new PKI_INTEGER from raw bit data */

PKI_INTEGER *PKI_INTEGER_new_bin ( unsigned char *data, size_t size ) {

	BIGNUM *bn;

	// Input Checks
	if (!data || !size) return NULL;

	// Converts the String into a BIGNUM
	if (!BN_dec2bn(&bn, (const char *)data)) return NULL;

	// Returns the result
	return (PKI_INTEGER *) BN_to_ASN1_INTEGER(bn, NULL);

	/* DEPRECATED:
	 *
	 * Old (pre 1.0.0) version

	return (PKI_INTEGER *) c2i_ASN1_INTEGER ( NULL, 
			(const unsigned char ** ) &data, (long int) size );
	*/

}

/*! \brief Prints the contents of a PKI_INTEGER to Standard Output */

int PKI_INTEGER_print( PKI_INTEGER *s ) {
	return ( PKI_INTEGER_print_fp( stdout, s ));
}

/*! \brief Prints the contents of a PKI_INTEGER to a FILE pointer (eg.,stdout)*/

int PKI_INTEGER_print_fp( FILE *fp, PKI_INTEGER *s ) {

	char *str = NULL;

	if( !s ) return ( PKI_ERR );

	if((str = PKI_INTEGER_get_parsed( s )) == NULL ) {
		return ( PKI_ERR );
	}

	fprintf( fp, "%s", str );

	PKI_Free( str );

	return ( PKI_OK );
}

