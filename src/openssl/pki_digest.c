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

PKI_DIGEST *PKI_DIGEST_new(const PKI_DIGEST_ALG *alg, 
		  	   const unsigned char  *data,
			   size_t          size ) {

	EVP_MD_CTX * md_ctx = NULL;
	char buf[EVP_MAX_MD_SIZE];
	size_t digest_size = 0;

	PKI_DIGEST *ret = NULL;

	// Input Checks
	if (!data || !alg) return NULL;

	// Allocate a new CTX
	if ((md_ctx = EVP_MD_CTX_new()) == NULL) return NULL;

	/* Let's initialize the MD context */
	EVP_MD_CTX_init(md_ctx);

	/* Initialize the Digest by using the Alogrithm identifier */
	if ((EVP_DigestInit_ex(md_ctx, alg, NULL )) == 0 ) goto err;

	/* Update the digest - calculate over the data */
	EVP_DigestUpdate(md_ctx, data, size);

	// Finalize the digest
	if ((EVP_DigestFinal_ex(md_ctx, (unsigned char *) buf, NULL)) == 0) goto err;

	/* Set the size of the md */
	digest_size = (size_t) EVP_MD_CTX_size(md_ctx);

	/* Allocate the return structure and the internal digest */
	if (((ret = PKI_Malloc(sizeof(PKI_DIGEST))) == NULL) ||
	    ((ret->digest = PKI_Malloc(size)) == NULL)) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		goto err;
	}
	
	/* Set the size of the Digest */
	ret->size = digest_size;

	/* Copy the Digest Data */
	memcpy(ret->digest, buf, ret->size);

	/* Sets the algorithm used */
	ret->algor = alg;

	/* Let's clean everything up */
	EVP_MD_CTX_reset(md_ctx);
	EVP_MD_CTX_free(md_ctx);

	/* Return the Digest Data structure */
	return ret;

err:

	if (md_ctx) {
		// Cleanup the CTX
		EVP_MD_CTX_reset(md_ctx);

		// Free Memory
		EVP_MD_CTX_free(md_ctx);
	}

	// Free Memory
	if (ret) PKI_Free(ret);

	// Nothing to return
	return NULL;
}

/*! \brief Calculates a digest over data buffer
 */

PKI_DIGEST *PKI_DIGEST_new_by_name(const char *alg_name, 
				   const unsigned char *data,
				   size_t size ) {

	PKI_DIGEST_ALG *alg = NULL;

	if(( alg = PKI_DIGEST_ALG_get_by_name( alg_name )) == NULL ) {
		/* Algorithm Error */
		return (NULL);
	}

	return ( PKI_DIGEST_new( alg, data, size ));
}

/*! \brief Calculates a digest over data contained in a PKI_MEM
 */

PKI_DIGEST *PKI_DIGEST_MEM_new(const PKI_DIGEST_ALG *alg, const PKI_MEM *data) {
	return (PKI_DIGEST_new(alg, data->data, data->size ));
}

PKI_DIGEST *PKI_DIGEST_MEM_new_by_name(const char *alg_name, 
				       const PKI_MEM *data ) {

	PKI_DIGEST_ALG *alg = NULL;

	if(( alg = PKI_DIGEST_ALG_get_by_name( alg_name )) == NULL ) {
		/* Algorithm Error */
		return (NULL);
	}

	return ( PKI_DIGEST_new( alg, data->data, data->size ));
}

/*! \brief Calculate the digest of data retrieved via a URL
 */

PKI_DIGEST *PKI_DIGEST_URL_new(const PKI_DIGEST_ALG *alg, const URL *url ) {

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

PKI_DIGEST *PKI_DIGEST_URL_new_by_name(const char *alg_name, const URL *url) {

	PKI_DIGEST_ALG *alg = NULL;

	if(( alg = PKI_DIGEST_ALG_get_by_name( alg_name )) == NULL ) {
		/* Algorithm Error */
		return (NULL);
	}

	return ( PKI_DIGEST_URL_new( alg, url ));
}

/*! \brief Returns the size of the output of the selected digest algorithm */

ssize_t PKI_DIGEST_get_size(const PKI_DIGEST_ALG *alg)
{
	int digest_size = 0;
	ssize_t ret = -1;

	if (!alg) return ret;

	digest_size = EVP_MD_size ( alg );

	ret = (ssize_t) digest_size;

	return ret;

}

/*! \brief Returns the parsed (string) version of the digest content */

char * PKI_DIGEST_get_parsed(const PKI_DIGEST *digest ) {

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

