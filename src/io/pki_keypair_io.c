/* PKI_X509 object management */

#include <libpki/pki.h>

/* ------------------------ KEYPAIR get (load) functions ------------------- */

/*! \brief Returns a PKI_X509_KEYPAIR obejct from a url address (string) */

PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_get (char *url_s, PKI_DATA_FORMAT format,
					PKI_CRED *cred, HSM *hsm) {

	return PKI_X509_get ( url_s, PKI_DATATYPE_X509_KEYPAIR, format, cred, hsm );
}

/*! \brief Returns a PKI_X509_KEYPAIR obejct from a URL */

PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_get_url ( URL *url, PKI_DATA_FORMAT format,
					PKI_CRED *cred, HSM *hsm ) {
	
	return PKI_X509_get_url ( url, PKI_DATATYPE_X509_KEYPAIR, format, cred, hsm );
}

/*! \brief Returns a STACK of PKI_X509_KEYPAIR obejcts from a url address */

PKI_X509_KEYPAIR_STACK *PKI_X509_KEYPAIR_STACK_get ( char *url_s, 
					PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm ) {

	return PKI_X509_STACK_get (url_s, PKI_DATATYPE_X509_KEYPAIR, format, cred, hsm);
}

/*! \brief Returns a STACK of PKI_X509_KEYPAIR obejcts from the passed URL */

PKI_X509_KEYPAIR_STACK *PKI_X509_KEYPAIR_STACK_get_url ( URL *url, 
					PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm ) {
	
	return PKI_X509_STACK_get_url ( url, PKI_DATATYPE_X509_KEYPAIR, 
					format, cred, hsm );
}

/* ---------------------- KEYPAIR put (write) functions ------------------- */

int PKI_X509_KEYPAIR_put ( PKI_X509_KEYPAIR *x, PKI_DATA_FORMAT format, 
			char *url_string, PKI_CRED *cred, HSM *hsm) {

	if ( x->type != PKI_DATATYPE_X509_KEYPAIR) return PKI_ERR;

	return PKI_X509_put ( x, format, url_string, NULL, cred, hsm );
}

int PKI_X509_KEYPAIR_put_url(PKI_X509_KEYPAIR *x, PKI_DATA_FORMAT format, 
					URL *url, PKI_CRED * cred, HSM *hsm) {

	if ( x->type != PKI_DATATYPE_X509_KEYPAIR ) return PKI_ERR;

	return PKI_X509_put_url ( x, format, url, NULL, cred, hsm );
}

/* --------------------------- MEM I/O ---------------------------------- */

PKI_X509_KEYPAIR * PKI_X509_KEYPAIR_get_mem(const PKI_MEM         * const mem,
											const PKI_DATA_FORMAT   format,
											const PKI_CRED        * const cred ) {

	return PKI_X509_get_mem((PKI_MEM *)mem, PKI_DATATYPE_X509_KEYPAIR, format, (PKI_CRED *)cred, NULL);
}

/*! \brief Reads a PKI_X509_KEYPAIR_VALUE object from a PKI_MEM */

PKI_X509_KEYPAIR_VALUE * PKI_X509_KEYPAIR_VALUE_get_mem(const PKI_MEM         * const mem, 
												        const PKI_DATA_FORMAT   format,
												        const PKI_CRED        * const cred ) {

	PKI_X509_KEYPAIR * key = NULL;
	PKI_X509_KEYPAIR_VALUE * val = NULL;

	// Gets the Key in the generic format
	key = PKI_X509_get_mem((PKI_MEM *)mem, PKI_DATATYPE_X509_KEYPAIR, format, (PKI_CRED *)cred, NULL);
	if (!key) return NULL;

	// Extracts the crypto-library specific value
	val = PKI_X509_get_value(key);

	// Resets the generic container and free the
	// memory for the generic wrapper
	key->value = NULL;
	PKI_X509_free(key);

	// All Done
	return val;
}

PKI_MEM * PKI_X509_KEYPAIR_put_mem(const PKI_X509_KEYPAIR *  const key,
								   const PKI_DATA_FORMAT     format, 
								   PKI_MEM                ** const pki_mem,
								   const PKI_CRED          * cred,
								   const HSM               * hsm) {
	return PKI_X509_put_mem((PKI_X509_KEYPAIR *)key, format, pki_mem, (PKI_CRED *)cred);
}

PKI_MEM * PKI_X509_KEYPAIR_VALUE_put_mem(const PKI_X509_KEYPAIR_VALUE  * const key,
								   		 const PKI_DATA_FORMAT           format, 
								   		 PKI_MEM                      ** const pki_mem,
								   		 const PKI_CRED                * cred,
								   		 const HSM                     * hsm) {
	
	PKI_X509_KEYPAIR * wrapper = NULL;
	PKI_X509_KEYPAIR_VALUE * key_val = NULL;

	PKI_MEM * buff = NULL;

	// Input Checks
	if (!key) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	// Wraps the VALUE into a PKI_X509
	wrapper = PKI_X509_new_value(PKI_DATATYPE_X509_KEYPAIR, (void *)key, (HSM *)hsm);
	if (!wrapper) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	// Assigns the existing buffer, if any was passed
	if (pki_mem && *pki_mem) {
		buff = (PKI_MEM *)*pki_mem;
	}

	// Saves the keypair into the output buffer
	PKI_X509_KEYPAIR_put_mem(wrapper, format, &buff, cred, hsm);

	// Detaches the VALUE from the PKI_X509
	if (wrapper->value) PKI_X509_detach(wrapper, (void **)&key_val, NULL, NULL);
	PKI_X509_free(wrapper);
	wrapper = NULL;

	// Checks the results
	if (!buff || !buff->data) {
		*pki_mem = NULL;
		return *pki_mem;
	}

	// Detaches the value from the wrapper
	PKI_X509_detach(wrapper, NULL, NULL, NULL);

	// Free the wrapper's memory
	PKI_X509_free(wrapper);
	wrapper = NULL;

	// Sets the output buffer
	*pki_mem = buff;

	// All done
	return buff;
}