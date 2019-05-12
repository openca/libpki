/* OpenCA libpki package
* (c) 2000-2006 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#ifndef _LIBPKI_PKI_X509_DATA_ST_H
#define _LIBPKI_PKI_X509_DATA_ST_H

#define PKI_IO			BIO
#define PKI_IO_new		BIO_new
#define PKI_IO_write		BIO_write
#define PKI_IO_read		BIO_write
#define PKI_IO_free		BIO_free_all

typedef struct pki_x509_callbacks_st {

	/* ---------------- Memory Management -------------------- */
	void * (*create)  (void    );
	void   (*free) (void *x );
	void * (*dup)  (void *x );

	/* ----------------- Data Management ---------------------- */
	char * (* get_parsed ) ( void *x, PKI_X509_DATA type );
	void * (* get_data ) ( void *x, PKI_X509_DATA type );
	int (* print_parsed) ( void *x, PKI_X509_DATA type, int fd);

	/* ----------------- Write Conversion --------------------- */
	int (* to_pem ) ( PKI_IO *out, void *data );
	int (* to_pem_ex) (PKI_IO *out, void *data, void *enc,
				unsigned char *key, int key_len, void *pwd_callback, void *u );
	int (* to_der ) ( PKI_IO *out, void *data );
	int (* to_txt ) ( PKI_IO *out, void *data );
	int (* to_b64 ) ( PKI_IO *out, void *data );
	int (* to_xml ) ( PKI_IO *out, void *data );

	/* ----------------- Read Conversions --------------------- */
	void * (* read_pem ) ( PKI_IO *in, void *, void *, void *);
	void * (* read_der ) ( PKI_IO *in, void * );
	void * (* read_txt ) ( PKI_IO *in, void * );
	void * (* read_b64 ) ( PKI_IO *in, void * );
	void * (* read_xml ) ( PKI_IO *in, void * );

} PKI_X509_CALLBACKS;

/* This structure helps us in maintaining all the drivers aligned */

typedef struct pki_x509_all_callbacks_st {
	const PKI_X509_CALLBACKS * x509_keypair_cb_set;
	const PKI_X509_CALLBACKS * x509_cert_cb_set;
	const PKI_X509_CALLBACKS * x509_req_cb_set;
	const PKI_X509_CALLBACKS * x509_crl_cb_set;
	const PKI_X509_CALLBACKS * x509_pkcs7_cb_set;
	const PKI_X509_CALLBACKS * x509_cms_cb_set;
	const PKI_X509_CALLBACKS * x509_pkcs12_cb_set;
	const PKI_X509_CALLBACKS * x509_ocsp_req_cb_set;
	const PKI_X509_CALLBACKS * x509_ocsp_resp_cb_set;
	const PKI_X509_CALLBACKS * x509_xpair_cb_set;
	const PKI_X509_CALLBACKS * x509_cmc_cb_set;
	const PKI_X509_CALLBACKS * x509_scep_cb_set;
	const PKI_X509_CALLBACKS * x509_prqp_req_cb_set;
	const PKI_X509_CALLBACKS * x509_prqp_resp_cb_set;
	const PKI_X509_CALLBACKS * x509_lirt_resp_cb_set;
} PKI_X509_CALLBACKS_FULL;

/* PKI_X509 general object */
typedef struct pki_x509_st {

	/* Type of Object - taken from PKI_DATATYPE */
	PKI_DATATYPE type;

	/* Internal Value - usually the supported crypto lib internal format */
	void *value;

	/* Credentials used to import/export/encrypt/decript data */
	PKI_CRED *cred;

	/* HSM to use for operations */
	struct hsm_st *hsm;

	/* Reference URL */
	URL *ref;

	/* Callbacks */
	const PKI_X509_CALLBACKS *cb;

	/* Template Reference */
	const ASN1_ITEM * it;

	/* Auxillary Data */
	void * aux_data;

	/* Callback to free auxillary data */
	void (*free_aux_data)(void *);

	/* Callback to duplicate auxillary data */
	void * (*dup_aux_data)(void *);

} PKI_X509;

/* End of _LIBPKI_PKI_X509_DATA_ST_H */
#endif
