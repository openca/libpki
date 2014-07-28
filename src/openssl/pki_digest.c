/* openssl/pki_digest.c */

#include <libpki/pki.h>

/*! \brief Free the memory associated with a PKI_DIGEST data structure
 */

void PKI_DIGEST_free ( PKI_DIGEST *data )
{
	if( !data ) return;

	if (data->digest) PKI_Free(data->digest);
	data->digest = NULL; // Safety
	data->algor = NULL; // Safety

	PKI_Free( data );

	return;
}

/*! \brief Calculate digest over data provided in a buffer
 */

PKI_DIGEST *PKI_DIGEST_new ( PKI_DIGEST_ALG *alg, 
					unsigned char *data, size_t size ) {

	EVP_MD_CTX md;
	char buf[EVP_MAX_MD_SIZE];
	size_t digest_size = 0;

	PKI_DIGEST *ret = NULL;

	if( !data || !alg ) return ( NULL );

	/* Let's initialize the MD context */
	EVP_MD_CTX_init( &md );

	/* Initialize the Digest by using the Alogrithm identifier */
	if ((EVP_DigestInit_ex( &md, alg, NULL )) == 0 ) 
	{
		EVP_MD_CTX_cleanup( &md );
		return( NULL );
	}

	/* Update the digest - calculate over the data */
	EVP_DigestUpdate(&md, data, size);

	if ((EVP_DigestFinal_ex(&md, (unsigned char *) buf, NULL)) == 0)
	{
		/* Error in finalizing the Digest */
		EVP_MD_CTX_cleanup( &md );
		return( NULL );
	}

	/* Set the size of the md */
	digest_size = (size_t) EVP_MD_CTX_size( &md );

	/* Allocate the return structure */
	if ((ret = PKI_Malloc(sizeof(PKI_DIGEST))) == NULL)
	{
		/* Memory Allocation Error! */
		EVP_MD_CTX_cleanup(&md);
		return( NULL );
	}
	
	/* Allocate the buffer */
	if ((ret->digest = PKI_Malloc(size)) == NULL)
	{
		/* Memory Error */
		EVP_MD_CTX_cleanup(&md);
		PKI_Free (ret);
		return(NULL);
	}

	/* Set the size of the Digest */
	ret->size = digest_size;

	/* Copy the Digest Data */
	memcpy(ret->digest, buf, ret->size);

	/* Sets the algorithm used */
	ret->algor = alg;

	/* Let's clean everything up */
	EVP_MD_CTX_cleanup(&md);

	/* Return the Digest Data structure */
	return ( ret );

}

/*! \brief Calculates a digest over data buffer
 */

PKI_DIGEST *PKI_DIGEST_new_by_name ( char *alg_name, 
					unsigned char *data, size_t size ) {

	PKI_DIGEST_ALG *alg = NULL;

	if(( alg = PKI_DIGEST_ALG_get_by_name( alg_name )) == NULL ) {
		/* Algorithm Error */
		return (NULL);
	}

	return ( PKI_DIGEST_new( alg, data, size ));
}

/*! \brief Calculates a digest over data contained in a PKI_MEM
 */

PKI_DIGEST *PKI_DIGEST_MEM_new ( PKI_DIGEST_ALG *alg, PKI_MEM *data ) {
	return ( PKI_DIGEST_new( alg, data->data, data->size ));
}

PKI_DIGEST *PKI_DIGEST_MEM_new_by_name ( char *alg_name, PKI_MEM *data ) {

	PKI_DIGEST_ALG *alg = NULL;

	if(( alg = PKI_DIGEST_ALG_get_by_name( alg_name )) == NULL ) {
		/* Algorithm Error */
		return (NULL);
	}

	return ( PKI_DIGEST_new( alg, data->data, data->size ));
}

/*! \brief Calculate the digest of data retrieved via a URL
 */

PKI_DIGEST *PKI_DIGEST_URL_new ( PKI_DIGEST_ALG *alg, URL *url ) {

	PKI_MEM_STACK * stack = NULL;
	PKI_MEM *data = NULL;
	PKI_DIGEST *ret = NULL;

	if(( stack = URL_get_data_url( url, 0, 0, NULL )) == NULL ) {
		/* Error, Can not grab the data */
		return ( NULL );
	}

	if( (data = PKI_STACK_MEM_pop( stack )) == NULL ) {
		/* Error, no objects returned! */
		PKI_STACK_free( stack );
		return ( NULL );
	}

	/* Calculate the Digest over the first object */
	ret = PKI_DIGEST_MEM_new( alg, data );

	/* Let's free the data */
	PKI_MEM_free( data );

	/* Let's free the stack data structure */
	PKI_STACK_free ( stack );

	/* Return the diget data */
	return ( ret );
}

PKI_DIGEST *PKI_DIGEST_URL_new_by_name ( char *alg_name, URL *url ) {

	PKI_DIGEST_ALG *alg = NULL;

	if(( alg = PKI_DIGEST_ALG_get_by_name( alg_name )) == NULL ) {
		/* Algorithm Error */
		return (NULL);
	}

	return ( PKI_DIGEST_URL_new( alg, url ));
}

/*! \brief Returns the size of the output of the selected digest algorithm */

ssize_t PKI_DIGEST_get_size(PKI_DIGEST_ALG *alg)
{
	int digest_size = 0;
	ssize_t ret = -1;

	if (!alg) return ret;

	digest_size = EVP_MD_size ( alg );

	ret = (ssize_t) digest_size;

	return ret;

}

/*! \brief Returns the parsed (string) version of the digest content */

char * PKI_DIGEST_get_parsed ( PKI_DIGEST *digest ) {

	char *ret = NULL;
	int i = 0;

	if( !digest ) return ( NULL );

	if ((digest->size <= 0) || (!digest->digest ))
		return ( NULL );

	ret = PKI_Malloc((digest->size * 3) + 1);
	// ret = PKI_Malloc ( 1024 );
	ret[0] = '\x0';

	for (i = 0; i < digest->size; i++)
	{
		unsigned char c;
		char kk[4];

		if( i > 0 ) strcat (ret, ":" );

		c = digest->digest[i];
		sprintf(kk, "%2.2x%c", c,'\x0' );
		strcat(ret, kk);
	}

	return ( ret );
}

