/* openssl/pki_algorthm.c */

#include <libpki/pki.h>

/*!
 * \brief Returns an empty PKI_ALGORITHM data structure
 */

PKI_ALGORITHM * PKI_ALGORITHM_new () {
	PKI_ALGORITHM *ret = NULL;

	if((ret = X509_ALGOR_new()) == NULL) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
	}

	return ret;
};

/*!
 * \brief Frees memory associated with a PKI_ALGORITHM data structure
 */

void PKI_ALGORITHM_free ( PKI_ALGORITHM *a ) {
	if ( !a ) return;

	X509_ALGOR_free ( a );

	return;
}

/*!
 * \brief Returns a PKI_ALGORITHM initialized with provided algor id
 */

PKI_ALGORITHM * PKI_ALGORITHM_new_type ( int type ) {

	PKI_ALGORITHM *ret = NULL;

	if (( ret = X509_ALGOR_new()) == NULL ) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	};

	if (!(ret->algorithm=OBJ_nid2obj(type))) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		goto err;
	}

	return ret;

err:

	if ( ret ) PKI_ALGORITHM_free ( ret );

	return NULL;

};

/*!
 * \brief Returns a PKI_ALGORITHM initialized with digest algorithm
 */

PKI_ALGORITHM * PKI_ALGORITHM_new_digest ( PKI_DIGEST_ALG *alg ) {

	PKI_ALGOR *ret = NULL;
	PKI_ID id = PKI_ID_UNKNOWN;

	if ( !alg ) return NULL;

	if((id = EVP_MD_type( alg )) == NID_undef) {
		return NULL;
	};

	if (( ret = X509_ALGOR_new()) == NULL ) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	};

	if (!(ret->algorithm=OBJ_nid2obj(id))) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		goto err;
	}

    if ((ret->parameter=ASN1_TYPE_new()) == NULL) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		goto err;
	}

    ret->parameter->type=V_ASN1_NULL;

	return ret;

err:
	if (ret) X509_ALGOR_free ( ret );

	return NULL;
};

