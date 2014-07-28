/* HMAC utility */

#include <libpki/pki.h>

/*
 * \brief Allocates and return a new (empty) PKI_HMAC
 */
PKI_HMAC *PKI_HMAC_new_null(void)
{
	PKI_HMAC *ret = NULL;
	ret = PKI_Malloc(sizeof(PKI_HMAC));

	ret->key = NULL;
	ret->value = NULL;
	ret->digestAlg = NULL;
	ret->initialized = 0;

	HMAC_CTX_init(&ret->ctx);

	return ret;
}

/*
 * \brief Allocates and initializes a new PKI_HMAC
 */
PKI_HMAC *PKI_HMAC_new(unsigned char *key, size_t key_size, PKI_DIGEST_ALG *digest, HSM *hsm)
{
	PKI_HMAC *ret = PKI_HMAC_new_null();
	if (!ret) return ret;

	if (PKI_HMAC_init(ret, key, key_size, digest, hsm) != PKI_OK)
	{
		PKI_HMAC_free(ret);
		return NULL;
	}

	return ret;
}

/*
 * \brief Allocates and initializes a new PKI_HMAC by using a PKI_MEM to hold the secret key
 */
PKI_HMAC *PKI_HMAC_new_mem(PKI_MEM *key, PKI_DIGEST_ALG *digest, HSM *hsm)
{
	PKI_HMAC *ret = NULL;

	if (!key || !key->data || key->size <= 0)
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	ret = PKI_HMAC_new_null();
	if (!ret)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	if (PKI_HMAC_init(ret, key->data, key->size, digest, hsm) != PKI_OK)
	{
		PKI_HMAC_free(ret);
		return NULL;
	}

	return ret;
}

/*
 * \brief Frees the memory associated with a PKI_HMAC
 */
void PKI_HMAC_free(PKI_HMAC *hmac)
{
	if (!hmac) return;

	if (hmac->key) PKI_MEM_free (hmac->key);
	if (hmac->value) PKI_MEM_free (hmac->value);

	hmac->digestAlg = NULL;

	HMAC_CTX_cleanup(&hmac->ctx);
}

/*
 * \brief Initializes the passed hmac to use the passed key and digest algorithm
 */
int PKI_HMAC_init(PKI_HMAC *hmac, unsigned char *key, size_t key_size, PKI_DIGEST_ALG *digest, HSM *hsm)
{
	if (!hmac) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// Free the memory if another key was used
	if (hmac->key) PKI_MEM_free(hmac->key);
	hmac->key = NULL;

	if (hmac->value) PKI_MEM_free(hmac->value);
	hmac->value = NULL;

	// Generate the new PKI_MEM to hold the key data
	hmac->key = PKI_MEM_new_data(key_size, key);
	if (!hmac->key || !hmac->key->data || hmac->key->size <= 0)
	{
		hmac->initialized = 0;
		return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
	}

	// Sets the algoritm
	hmac->digestAlg = digest ? digest : PKI_DIGEST_ALG_SHA1;

	// Checks if HSM implementation was asked by the developer
	if (hsm)
	{
		PKI_ERROR(PKI_ERR_GENERAL, "Code to support HMAC on HSMs not implemented, yet.");
		hmac->initialized = 0;
		return PKI_ERR;
	}

	// Initializes the Context
	HMAC_Init_ex(&hmac->ctx, (const void *) key, (int) key_size, hmac->digestAlg, NULL);

	// Sets the initialization flag
	hmac->initialized = 1;

	return PKI_OK;
}

int PKI_HMAC_update(PKI_HMAC *hmac, unsigned char *data, size_t data_size)
{
#if OPENSSL_VERSION_NUMBER > 0x0090900fL
	int rv = 0;
#endif

	if (!hmac || !hmac->initialized)
	{
		return PKI_ERROR(PKI_ERR_GENERAL, "PKI_HMAC is not initialized");
	}

#if OPENSSL_VERSION_NUMBER > 0x0090900fL
	rv = HMAC_Update(&hmac->ctx, (const unsigned char *) data, (unsigned int) data_size);
	if (rv == 0)
	{
		return PKI_ERROR(PKI_ERR_GENERAL, "Error while updating the HMAC value");
	}
#else
	HMAC_Update(&hmac->ctx, (const unsigned char *) data, (unsigned int) data_size);
#endif

	return PKI_OK;
}

int PKI_HMAC_update_mem(PKI_HMAC *hmac, PKI_MEM *data)
{
	if (!hmac || !data || !data->data || data->size <= 0)
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	return PKI_HMAC_update(hmac, data->data, data->size);
}

int PKI_HMAC_finalize(PKI_HMAC *hmac)
{
	int size = 0;
	unsigned int verify_size = 0;

	if (!hmac || !hmac->initialized)
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// Let's prepare the return value
	size = EVP_MD_size(hmac->digestAlg);
	verify_size = (unsigned int) size;

	// Generate a new PKI_MEM container
	hmac->value = PKI_MEM_new((size_t) size);

	// Let's finalize the HMAC
#if OPENSSL_VERSION_NUMBER > 0x0090900fL
	int rv = HMAC_Final(&hmac->ctx, hmac->value->data, &verify_size);
	if (!rv)
	{
		PKI_log_err("can not finalize HMAC");
		PKI_MEM_free(hmac->value);
		hmac->value = NULL;

		return PKI_ERR;
	}
#else
	// In OpenSSL < 0.9.9 the return value is actually void
	HMAC_Final(&hmac->ctx, hmac->value->data, &verify_size);
#endif

	// Checks the sizes
	if (verify_size != size)
	{
		PKI_log_err("Error while finalizing HMAC, size (%d) should be (%d)",
			verify_size, hmac->value->size);

		PKI_MEM_free(hmac->value);
		hmac->value = NULL;

		return PKI_ERR;
	}

	return PKI_OK;
}

/*
 * \brief Returns a PKI_MEM with the hmac raw value
 */
PKI_MEM * PKI_HMAC_get_value(PKI_HMAC *hmac)
{
	if (!hmac) return NULL;

	return PKI_MEM_dup(hmac->value);
}


/*
 * \brief Returns a B64 encoded PKI_MEM for the hmac value
 */
PKI_MEM *PKI_HMAC_get_value_b64(PKI_HMAC *hmac)
{
	PKI_MEM *ret = NULL;

	// This returns a duplicate of the PKI_MEM value
	ret = PKI_HMAC_get_value(hmac);
	if (!ret) PKI_log_err("can not get the HMAC PKI_MEM value");

	// If a valid PKI_MEM is returned, let's B64 it
	if (ret && ret->data && ret->size > 0)
	{
		if (PKI_MEM_B64_encode(ret, 1) == NULL)
		{
			PKI_log_err("can not B64 encoding HMAC PKI_MEM value");
			if (ret) PKI_MEM_free(ret);

			return NULL;
		}
	}

	return ret;
}

PKI_MEM * PKI_HMAC_new_data(PKI_MEM *data, PKI_MEM *key, PKI_DIGEST_ALG *digest)
{	
	unsigned char *hmac_value = NULL;
	unsigned int hmac_size = 0;

	int key_size = 0;
	size_t data_size = 0;

	PKI_MEM *ret = NULL;

	// Input parameters check
	if (!data || data->size <= 0 || !key || key->size <= 0) 
	{
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	// Let's use the correct types for the sizes (for the HMAC call)
	key_size = (int) key->size;
	data_size = (size_t) data->size;

	// Retrieve the data from the OpenSSL library
	hmac_value = HMAC(digest ? digest : PKI_DIGEST_ALG_SHA1, 
		(unsigned char *) key->data, key_size, 
		(unsigned char *) data->data, data_size, 
		NULL, &hmac_size);

	// If no data is returned or size is wrong, let's return null
	if (!hmac_value || hmac_size <= 0)
	{
		if (hmac_value) PKI_Free(hmac_value);
		return NULL;
	}

	// Create a new PKI_MEM object for returning the calculated value
	ret = PKI_MEM_new_data(hmac_size, hmac_value);

	// Return the PKI_MEM object that contains the HMAC value
	return ret;
}

