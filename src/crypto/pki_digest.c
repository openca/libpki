/* openssl/pki_digest.c */

#include <libpki/pki.h>

/*! \brief Free the memory associated with a CRYPTO_DIGEST data structure
 */

void PKI_DIGEST_free ( CRYPTO_DIGEST *data )
{
	if( !data ) return;

	if (data->digest) PKI_Free(data->digest);
	data->digest = NULL; // Safety
	data->algor = NULL; // Safety

	PKI_Free( data );

	return;
}

int PKI_DIGEST_new_value(unsigned char       ** dst_buf,
		         const PKI_DIGEST_ALG * alg,
		         const unsigned char  * data,
		         size_t                 size) {

	EVP_MD_CTX * md_ctx = NULL;
		// Crypto Context for Digest Calculation

	int mem_alloc = 0;
		// Tracks where the mem alloc happened

	int digest_size = 0;
		// Return Value

	int success = 0;
		// Tracks the success of the operation

	// Input Checks
	if (!data || !alg || !dst_buf) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return 0;
	}

	// Allocate a new CTX
	if ((md_ctx = EVP_MD_CTX_new()) == NULL) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return 0;
	}

	// Let's initialize the MD context
	EVP_MD_CTX_init(md_ctx);
	
	// Allocates the buffer if not provided
	if (*dst_buf == NULL) {
		*dst_buf = PKI_Malloc(EVP_MAX_MD_SIZE); 
		mem_alloc = 1;
	}

	// Makes sure we have a good buffer
	if (*dst_buf == NULL) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return 0;
	}

	// Initializes the Digest
	success = EVP_DigestInit_ex(md_ctx, alg, NULL);
	if (success == 1 ) {

		// Updates the digest value
		EVP_DigestUpdate(md_ctx, data, size);

		// Finalize the digest
		if ((EVP_DigestFinal_ex(md_ctx, *dst_buf, NULL)) == 1) {

			// All Ok
			digest_size = EVP_MD_CTX_size(md_ctx);
		}

		// // Let's clean everything up
		EVP_MD_CTX_reset(md_ctx);

		// Free the CTX memory
		EVP_MD_CTX_free(md_ctx);
		md_ctx = NULL; // Safety
	}

	// If we have an error, let's return '0'
	if (digest_size <= 0) goto err;

	// Return the calculated value
	return digest_size;

err:
	// Let's clean everything up
	if (md_ctx) {
		EVP_MD_CTX_reset(md_ctx);
		EVP_MD_CTX_free(md_ctx);
	}

	// Free the allocated memory only if we are not re-using
	// the provided output buffer (dst_buf)
	if (mem_alloc) {
		PKI_Free(*dst_buf);
		*dst_buf = NULL; // Safety
	}

	// Nothing to return
	return 0;

}
				     
/*! \brief Calculate digest over data provided in a buffer
 */

CRYPTO_DIGEST *PKI_DIGEST_new(const PKI_DIGEST_ALG *alg, 
		  	   const unsigned char  *data,
			   size_t                size ) {

	// Return Object
	CRYPTO_DIGEST *ret = NULL;

	// Input Checks
	if (!data || !alg) return NULL;

	// Allocates the memory for the return CRYPTO_DIGEST
	if ((ret = PKI_Malloc(sizeof(CRYPTO_DIGEST))) != NULL) {

		int dgst_size = 0;

		// Fills in the data and the size of the digest
		if ((dgst_size = PKI_DIGEST_new_value(&ret->digest, 
						alg, data, size)) <= 0) {
			goto err;
		}

		ret->size = (size_t) dgst_size;
	}

	// All done
	return ret;

err:
	// Let's free any allocated memory
	if (ret) PKI_DIGEST_free(ret);

	// No digest was calculated, return the error
	return NULL;
}

/*! \brief Calculates a digest over data buffer
 */

CRYPTO_DIGEST *PKI_DIGEST_new_by_name(const char *alg_name, 
				   const unsigned char *data,
				   size_t size ) {

	const PKI_DIGEST_ALG *alg;

	if ((alg = PKI_DIGEST_ALG_get_by_name( alg_name )) == NULL) {
		/* Algorithm Error */
		return NULL;
	}

	return PKI_DIGEST_new(alg, data, size);
}

/*! \brief Calculates a digest over data contained in a PKI_MEM
 */

CRYPTO_DIGEST *PKI_DIGEST_MEM_new(const PKI_DIGEST_ALG *alg, const PKI_MEM *data) {
	return (PKI_DIGEST_new(alg, data->data, data->size ));
}

CRYPTO_DIGEST *PKI_DIGEST_MEM_new_by_name(const char *alg_name, 
				       const PKI_MEM *data ) {

	const PKI_DIGEST_ALG *alg;

	if ((alg = PKI_DIGEST_ALG_get_by_name(alg_name)) == NULL) {
		/* Algorithm Error */
		return NULL;
	}

	return ( PKI_DIGEST_new( alg, data->data, data->size ));
}

/*! \brief Calculate the digest of data retrieved via a URL
 */

CRYPTO_DIGEST *PKI_DIGEST_URL_new(const PKI_DIGEST_ALG *alg, const URL *url ) {

	PKI_MEM_STACK * stack = NULL;
	PKI_MEM *data = NULL;
	CRYPTO_DIGEST *ret = NULL;

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

CRYPTO_DIGEST *PKI_DIGEST_URL_new_by_name(const char *alg_name, const URL *url) {

	const PKI_DIGEST_ALG *alg;

	if ((alg = PKI_DIGEST_ALG_get_by_name(alg_name)) == NULL) {
		/* Algorithm Error */
		return NULL;
	}

	return PKI_DIGEST_URL_new(alg, url);
}

/*! \brief Returns the size of the output of the selected digest algorithm */

ssize_t PKI_DIGEST_get_size(const PKI_DIGEST_ALG *alg)
{
	int digest_size = 0;
	ssize_t ret = -1;

	if (!alg) return ret;

	digest_size = EVP_MD_size(alg);

	ret = (ssize_t) digest_size;

	return ret;

}

/*! \brief Returns the size of the output of the provided algorithm */

int PKI_DIGEST_get_size_by_name(const char *alg_name) {

	const PKI_DIGEST_ALG *alg = NULL;

	if ((alg = PKI_DIGEST_ALG_get_by_name(alg_name)) == NULL) {
		/* Algorithm Error */
		return -1;
	}

	return EVP_MD_size(alg);
};

/*! \brief Returns the pointer to the calculated digest */
const unsigned char * PKI_DIGEST_get_value(const CRYPTO_DIGEST *digest) {

	// Input Checks	
	if (!digest || !digest->digest || digest->size == 0)
		return NULL;

	// Returns the pointer
	return digest->digest;

}


/*! \brief Returns the size of a calculated digest */

size_t PKI_DIGEST_get_value_size(const CRYPTO_DIGEST *dgst)
{
	if (!dgst || !dgst->digest || !dgst->size) return 0;

	return dgst->size;
}

/*! \brief Returns the parsed (string) version of the digest content */

char * PKI_DIGEST_get_parsed(const CRYPTO_DIGEST *digest ) {

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

