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

/*! \brief Reads a PKI_X509_KEYPAIR object from a PKI_MEM */

PKI_X509_KEYPAIR *PKI_X509_KEYPAIR_get_mem( PKI_MEM *mem, 
					PKI_DATA_FORMAT format, PKI_CRED *cred ) {

	return PKI_X509_get_mem ( mem, PKI_DATATYPE_X509_KEYPAIR, format, cred, NULL );

}

/*! \brief Puts a X509_KEYPAIR to a PKI_MEM */

PKI_MEM *PKI_X509_KEYPAIR_put_mem ( PKI_X509_KEYPAIR *key, 
		PKI_DATA_FORMAT format, PKI_MEM **pki_mem, PKI_CRED *cred, 
								HSM *hsm ) {
	return PKI_X509_put_mem ( key, format, pki_mem, cred );
}
