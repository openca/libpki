/* PKI_TIME */

#include <libpki/pki.h>

/*!
 * \brief Returns a new PKI_TIME with offset (secs) from current time
 */

PKI_TIME *PKI_TIME_new( long long offset ) {

	PKI_TIME *time = NULL;

	if((time = (PKI_TIME *) ASN1_GENERALIZEDTIME_new()) == NULL ) {
		return ( NULL );
	}

	/* Set the time offset - if offset is 0 then it gets the current
	   time */
#if ( LIBPKI_OS_BITS == LIBPKI_OS32 )
	long off32 = (long) offset;
	X509_gmtime_adj((ASN1_GENERALIZEDTIME *) time, off32);
#else
	X509_gmtime_adj((ASN1_GENERALIZEDTIME *) time, offset);
#endif

	return( time );
}

void PKI_TIME_free_void( void *time )
{
	int ret = PKI_OK;

	ret = PKI_TIME_free( (PKI_TIME *) time);
	if (ret == PKI_ERR) PKI_ERROR(PKI_ERR_GENERAL, "Error freeing the time structure");

	return;
}

/*!
 * \brief Frees memory associated with a PKI_TIME
 */

int PKI_TIME_free( PKI_TIME *time ) {

	if( !time ) return (PKI_ERR);

	ASN1_TIME_free( (ASN1_TIME *) time );

	return (PKI_OK);
}

/*!
 * \brief Sets the passed PKI_TIME to the provided time_t
 */

PKI_TIME *PKI_TIME_set(PKI_TIME *time, time_t new_time) {

	if (!time) {
		return NULL;
	}

	return ASN1_GENERALIZEDTIME_adj(time, new_time, 0, 0);
}

/*!
 * \brief Adjusts the time by adding/subtracting the offset seconds from current value
 */

int PKI_TIME_adj( PKI_TIME *time, long long offset ) {

	if ( !time ) {
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
	};

#if ( LIBPKI_OS_BITS == LIBPKI_OS32 )
	long off32 = (long) offset;
	if(!X509_gmtime_adj( time, off32 )) 
	{
#else
	if(!X509_gmtime_adj( time, offset ))
	{
#endif
		return PKI_ERROR(PKI_ERR_GENERAL, NULL);
	};

	return PKI_OK;
};

/*!
 * \brief Returns a Human readable version of a PKI_TIME
 */

char *PKI_TIME_get_parsed ( PKI_TIME *t ) {

	BUF_MEM *bm = NULL;
	BIO *mem = NULL;
	char *ret = NULL;

	if( !t ) return (NULL);
	if ((mem = BIO_new(BIO_s_mem())) == NULL) return(NULL);

	ASN1_TIME_print(mem, (ASN1_TIME *)t);
	BIO_get_mem_ptr(mem, &bm);

	if(( ret = PKI_Malloc( (size_t) (bm->length + 1) )) != NULL ) {
		memcpy((char *)ret, bm->data, (size_t) bm->length);
		ret[bm->length] = '\x0';
	}

	BIO_free( mem );
	return( ret );

}

/*! \brief Returns a duplicate of the PKI_TIME object */

PKI_TIME * PKI_TIME_dup ( PKI_TIME *time ) {
	if ( !time ) return NULL;

	return (PKI_TIME *) M_ASN1_TIME_dup ( (ASN1_TIME *) time );
}

/*!
 * \brief Prints a PKI_TIME to standard output
 */

int PKI_TIME_print ( PKI_TIME *time ) {
	return ( PKI_TIME_print_fp( stdout, time ));
}

/*!
 * \brief Prints out a PKI_TIME to a FILE stream
 */

int PKI_TIME_print_fp ( FILE *fp, PKI_TIME *time ) {

	BIO *out = NULL;
	if( !time || !fp ) return ( PKI_ERR );

	if((out = BIO_new_fp( fp, BIO_NOCLOSE )) == NULL ) {
		return( PKI_ERR );
	}
	
	ASN1_GENERALIZEDTIME_print(out, time);

	if( out ) BIO_free ( out );

	return (PKI_OK);
}

