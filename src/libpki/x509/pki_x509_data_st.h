/* OpenCA libpki package
* (c) 2000-2006 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#ifndef _LIBPKI_PKI_DATATYPES_H
#include <libpki/datatypes.h>
#endif

#ifndef _LIBPKI_PKI_CRED_H
#include <libpki/pki_cred.h>
#endif

#ifndef _LIBPKI_PKI_X509_DATATYPES_ST_H
#define _LIBPKI_PKI_X509_DATATYPES_ST_H

typedef struct pki_x509_callbacks_st {

	// /* ---------------- Memory Management -------------------- */
	
	// void * (*new) (void    );
	// void   (*del) (void	 *x );

	/* ------------ DER Encoding and Decoding ---------------------- */

	void * (*encode)(PKI_X509 *x, unsigned char **out, size_t *size
				unsigned char *secret, size_t secret_len);
	void * (*decode)(PKI_X509 *x, unsigned char *in, size_t size);

	/* Set and Retrieve Data */

} PKI_ASN1_CALLBACKS;

/* This structure helps us in maintaining all the drivers aligned */

typedef struct pki_x509_callback

typedef struct pki_x509_all_callbacks_st {
	const struct pki_x509_callbacks_st * test_only;
} PKI_X509_CALLBACKS_ALL;

/* PKI_X509 general object */
typedef struct pki_x509_st {

	/* Type of Object - taken from PKI_DATATYPE */
	PKI_DATATYPE type;

	/* Internal Value - usually the supported crypto lib internal format */
	void *value;

	/* HSM to use for operations */
	struct hsm_st *hsm;

	/* Reference URL */
	URL *ref;

	/* Callbacks */
	const PKI_X509_ENCODING_CB *cb;

	/* Template Reference */
	const ASN1_ITEM * asn1_it;

	/* Internal Status */
	int status;

	/* Auxillary Data */
	void * aux_data;

	/* Callback to free auxillary data */
	void (*free_aux_data)(void *);

	/* Callback to duplicate auxillary data */
	void * (*dup_aux_data)(void *);

} PKI_X509;

/* End of _LIBPKI_PKI_X509_DATA_ST_H */
#endif
