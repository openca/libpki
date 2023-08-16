#include <libpki/pki.h>
#include <libpki/scep/scep.h>

#include <openssl/cms.h>
#include <libpki/pki_x509_cms.h>

const PKI_X509_CALLBACKS PKI_OPENSSL_X509_KEYPAIR_CALLBACKS = {
	// Memory Management
	(void *) EVP_PKEY_new, // PKI_KEYPAIR_new_null
	(void *) EVP_PKEY_free, // PKI_KEYPAIR_free
	(void *) OPENSSL_HSM_KEYPAIR_dup, // PKI_KEYPAIR_dup

	// Data Retrieval
	(void *) NULL, // PKI_KEYPAIR_get_parsed
	(void *) NULL, // PKI_KEYPAIR_data;
	(void *) NULL, // PKI_KEYPAIR_print_parsed;

	// Data Conversion
	NULL, // (void *) PEM_write_bio_PUBKEY, // PEM format
	(void *) OPENSSL_HSM_write_bio_PrivateKey, // PEM format
	// (void *) PEM_write_bio_PKCS8PrivateKey, // PEM format
	(void *) i2d_PrivateKey_bio,	 // DER format
	(void *) NULL, 			 // TXT format
	(void *) NULL,			 // B64 format
	(void *) NULL,			 // XML format

	// Data Conversion
	(void *) PEM_read_bio_PrivateKey,// PEM format
	(void *) d2i_PrivateKey_bio,   	// DER format
	(void *) NULL,			// TXT format
	(void *) NULL,  		// B64 format
	(void *) NULL			// XML format
};

const PKI_X509_CALLBACKS PKI_OPENSSL_X509_CERT_CALLBACKS = {
	/* Memory Management */
	(void*)X509_new,
	(void*)X509_free,
	(void*)X509_dup,

	/* Data Retrieval */
	(void *) PKI_X509_CERT_get_parsed,
	(void *) PKI_X509_CERT_get_data,
	(void *) PKI_X509_CERT_print_parsed,

	/* Data Conversion */
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
	(void *) PEM_write_bio_X509_AUX, // PEM format
#else
	(void *) PEM_write_bio_X509, // PEM format
#endif
	NULL,                        // PEM EX (encrypted) format
	(void *) i2d_X509_bio,       // DER format
	(void *) X509_print,         // TXT format
	NULL,                        // B64 format (B64_write_bio)
	NULL,                        // XML format

	/* Data Conversion */
	(void *) PEM_read_bio_X509_AUX,  // PEM format
	(void *) d2i_X509_bio,       // DER format
	NULL,                        // TXT format
	NULL,                        // B64 format
	NULL                         // XML format
};


const PKI_X509_CALLBACKS PKI_OPENSSL_X509_REQ_CALLBACKS = {
	/* Memory Management */
	(void *) X509_REQ_new,
	(void *) X509_REQ_free,
	(void *) X509_REQ_dup,

	/* Data Retrieval */
	(void *) PKI_X509_REQ_get_parsed,
	(void *) PKI_X509_REQ_get_data,
	(void *) PKI_X509_REQ_print_parsed,

	/* Data Conversion */
	(void *) PEM_write_bio_X509_REQ, // PEM format
	NULL,  				// PEM EX (encrypted) format
	(void *) i2d_X509_REQ_bio,	// DER format
	(void *) X509_REQ_print,	// TXT format
	(void *) NULL,			// B64 format
	(void *) NULL,			// XML format

	/* Data Conversion */
	(void *) PEM_read_bio_X509_REQ,  // PEM format
	(void *) d2i_X509_REQ_bio,       // DER format
	(void *) NULL,		         // TXT format
	(void *) NULL,                   // B64 format
	(void *) NULL		         // XML format
};

const PKI_X509_CALLBACKS PKI_OPENSSL_X509_CRL_CALLBACKS = {
	/* Memory Management */
	(void *) X509_CRL_new,
	(void *) X509_CRL_free,
	(void *) X509_CRL_dup,

	/* Data Retrieval */
	(void *) PKI_X509_CRL_get_parsed,
	(void *) PKI_X509_CRL_get_data,
	(void *) NULL, // PKI_X509_CRL_print_parsed,

	/* Data Conversion */
	(void *) PEM_write_bio_X509_CRL, // PEM format
  NULL,  												// PEM EX (encrypted) format
	(void *) i2d_X509_CRL_bio,	// DER format
	(void *) X509_CRL_print,		// TXT format
	(void *) NULL,			// B64 format
	(void *) NULL,			// XML format

	/* Data Conversion */
	(void *) PEM_read_bio_X509_CRL,  // PEM format
	(void *) d2i_X509_CRL_bio,       // DER format
	(void *) NULL,		        // TXT format
	(void *) NULL,                   // B64 format
	(void *) NULL		        // XML format
};

const PKI_X509_CALLBACKS PKI_OPENSSL_X509_PKCS7_CALLBACKS = {

	/* Memory Management */
	(void *) PKCS7_new,
	(void *) PKCS7_free,
	(void *) PKCS7_dup,

	/* Data Retrieval */
	(void *) NULL, // PKI_X509_PKCS7_get_parsed;
	(void *) NULL, // PKI_X509_PKCS7_get_data;
	(void *) NULL, // PKI_X509_PKCS7_print_parsed;

	/* Data Conversion */
	(void *) PEM_write_bio_PKCS7,   // PEM format
	NULL,  												// PEM EX (encrypted) format
	(void *) i2d_PKCS7_bio,		// DER format
	(void *) PKI_X509_PKCS7_VALUE_print_bio, // TXT format
	(void *) NULL,			// B64 format
	(void *) NULL,			// XML format

	/* Data Conversion */
	(void *) PEM_read_bio_PKCS7,     // PEM format
	(void *) d2i_PKCS7_bio,          // DER format
	(void *) NULL,		        // TXT format
	(void *) NULL,			// B64 format
	(void *) NULL		        // XML format
};


const PKI_X509_CALLBACKS PKI_OPENSSL_X509_CMS_CALLBACKS = {

	/* Memory Management */
	(void *) PKI_X509_CMS_VALUE_new,
	(void *) PKI_X509_CMS_VALUE_free,
	(void *) PKI_X509_CMS_VALUE_dup,

	/* Data Retrieval */
	(void *) NULL, // PKI_X509_PKCS7_get_parsed;
	(void *) NULL, // PKI_X509_PKCS7_get_data;
	(void *) NULL, // PKI_X509_PKCS7_print_parsed;

	/* Data Conversion */
	(void *) PEM_write_bio_CMS,     // PEM format
	NULL,  							// PEM EX (encrypted) format
	(void *) i2d_CMS_bio,		    // DER format
	(void *) PKI_X509_CMS_VALUE_print_bio, // TXT format
	(void *) NULL,			// B64 format
	(void *) NULL,			// XML format

	/* Data Conversion */
	(void *) PEM_read_bio_CMS,     // PEM format
	(void *) d2i_CMS_bio,          // DER format
	(void *) NULL,		        // TXT format
	(void *) NULL,			// B64 format
	(void *) NULL		        // XML format
};


const PKI_X509_CALLBACKS PKI_OPENSSL_X509_PKCS12_CALLBACKS = {
	// Memory Management
	(void *) PKCS12_new,
	(void *) PKCS12_free,
	(void *) NULL,

	// Data Retrieval
	(void *) NULL, // PKI_X509_PKCS12_get_parsed;
	(void *) NULL, // PKI_X509_PKCS12_get_data;
	(void *) NULL, // PKI_X509_PKCS12_print_parsed;

	// Data Conversion
	(void *) PEM_write_bio_PKCS12,   // PEM format
  NULL,  												// PEM EX (encrypted) format
	(void *) i2d_PKCS12_bio,		// DER format
	(void *) NULL,			// TXT format
	(void *) NULL,			// B64 format
	(void *) NULL,			// XML format

	// Data Conversion
	(void *) PEM_read_bio_PKCS12,    // PEM format
	(void *) d2i_PKCS12_bio,         // DER format
	(void *) NULL,		        // TXT format
	(void *) NULL,                   // B64 format
	(void *) NULL		        // XML format
};

const PKI_X509_CALLBACKS PKI_OPENSSL_X509_OCSP_REQ_CALLBACKS = {
	// Memory Management
	(void *) OCSP_REQUEST_new,
	(void *) OCSP_REQUEST_free,
	(void *) NULL,

	// Data Retrieval
	(void *) PKI_X509_OCSP_REQ_get_parsed, // PKI_X509_OCSP_REQ_get_parsed;
	(void *) PKI_X509_OCSP_REQ_get_data, // PKI_X509_OCSP_REQ_get_data;
	(void *) NULL, // PKI_X509_OCSP_REQ_print_parsed;

	// Data Conversion
	(void *) PEM_write_bio_OCSP_REQ,// PEM format
  NULL,  												// PEM EX (encrypted) format
	(void *) i2d_OCSP_REQ_bio,	// DER format
	(void *) NULL,			// TXT format
	(void *) NULL,			// B64 format
	(void *) NULL,			// XML format

	// Data Conversion
	(void *) PEM_read_bio_OCSP_REQ,	// PEM format
	(void *) d2i_OCSP_REQ_bio,   	// DER format
	(void *) NULL,		       	// TXT format
	(void *) NULL,  		// B64 format
	(void *) NULL			// XML format
};

const PKI_X509_CALLBACKS PKI_OPENSSL_X509_OCSP_RESP_CALLBACKS = {
	// Memory Management
	(void *) PKI_OCSP_RESP_new,
	(void *) PKI_OCSP_RESP_free,
	(void *) NULL,

	// Data Retrieval
	(void *) PKI_X509_OCSP_RESP_get_parsed,
	(void *) PKI_X509_OCSP_RESP_get_data,
	(void *) NULL, // PKI_X509_OCSP_RESP_print_parsed;

	// Data Conversion
	(void *) PEM_write_bio_PKI_X509_OCSP_RESP_VALUE,	// PEM format
  NULL,  												// PEM EX (encrypted) format
	(void *) i2d_PKI_X509_OCSP_RESP_VALUE_bio,	// DER format
	(void *) NULL,			// TXT format
	(void *) NULL,			// B64 format
	(void *) NULL,			// XML format

	// Data Conversion
	(void *) PEM_read_bio_PKI_X509_OCSP_RESP_VALUE,// PEM format
	(void *) d2i_PKI_X509_OCSP_RESP_VALUE_bio, // DER format
	(void *) NULL,		    // TXT format
	(void *) NULL,  		// B64 format
	(void *) NULL			// XML format
};

const PKI_X509_CALLBACKS PKI_OPENSSL_X509_XPAIR_CALLBACKS = {
	// Memory Management
	(void *) PKI_XPAIR_new_null,
	(void *) PKI_XPAIR_free,
	(void *) NULL,

	// Data Retrieval
	(void *) NULL, // PKI_X509_XPAIR_get_parsed;sed;
	(void *) NULL, // PKI_X509_XPAIR_get_data;
	(void *) NULL, // PKI_X509_XPAIR_print_parsed;

	// Data Conversion
	(void *) PEM_write_bio_PKI_XPAIR, // PEM format
  NULL,  												// PEM EX (encrypted) format
	(void *) i2d_PKI_XPAIR_bio,	// DER format
	(void *) PKI_XPAIR_print,	// TXT format
	(void *) NULL,			// B64 format
	(void *) NULL,			// XML format

	// Data Conversion
	(void *) PEM_read_bio_PKI_XPAIR,// PEM format
	(void *) d2i_PKI_XPAIR_bio,   	// DER format
	(void *) NULL,		       	// TXT format
	(void *) NULL,  		// B64 format
	(void *) NULL			// XML format
};

const PKI_X509_CALLBACKS PKI_OPENSSL_X509_PRQP_REQ_CALLBACKS = {
	// Memory Management
	(void *) PKI_PRQP_REQ_new,
	(void *) PKI_PRQP_REQ_free,
	(void *) PKI_PRQP_REQ_dup,

	// Data Retrieval
	(void *) NULL, //PKI_X509_PRQP_REQ_get_parsed, // PKI_X509_OCSP_REQ_get_parsed;
	(void *) PKI_X509_PRQP_REQ_get_data, // PKI_X509_OCSP_REQ_get_data;
	(void *) NULL, // PKI_X509_OCSP_REQ_print_parsed;

	// Data Conversion
	(void *) PEM_write_bio_PRQP_REQ,// PEM format
  NULL,  												// PEM EX (encrypted) format
	(void *) i2d_PRQP_REQ_bio,	// DER format
	(void *) NULL,			// TXT format
	(void *) NULL,			// B64 format
	(void *) NULL,			// XML format

	// Data Conversion
	(void *) PEM_read_bio_PRQP_REQ,	// PEM format
	(void *) d2i_PRQP_REQ_bio,   	// DER format
	(void *) NULL,		       	// TXT format
	(void *) NULL,  		// B64 format
	(void *) NULL			// XML format
};

const PKI_X509_CALLBACKS PKI_OPENSSL_X509_PRQP_RESP_CALLBACKS = {
	// Memory Management
	(void *) PKI_PRQP_RESP_new,
	(void *) PKI_PRQP_RESP_free,
	(void *) PKI_PRQP_RESP_dup,

	// Data Retrieval
	(void *) NULL,//PKI_X509_PRQP_RESP_get_parsed,
	(void *) PKI_X509_PRQP_RESP_get_data,
	(void *) NULL, // PKI_X509_OCSP_RESP_print_parsed;

	// Data Conversion (write of the ->value data )
	(void *) PEM_write_bio_PRQP_RESP,	// PEM format
  NULL,  												// PEM EX (encrypted) format
	(void *) i2d_PRQP_RESP_bio,	// DER format
	(void *) NULL,			// TXT format
	(void *) NULL,			// B64 format
	(void *) NULL,			// XML format

	// Data Conversion (read the ->value)
	(void *) PEM_read_bio_PRQP_RESP,// PEM format
	(void *) d2i_PRQP_RESP_bio, 	// DER format
	(void *) NULL,			// TXT format
	(void *) NULL,  		// B64 format
	(void *) NULL			// XML format
};


const PKI_X509_CALLBACKS_FULL PKI_OPENSSL_X509_CALLBACKS_FULL = {
	// X509_KEYPAIR
	&PKI_OPENSSL_X509_KEYPAIR_CALLBACKS,
	// X509_CERT
	&PKI_OPENSSL_X509_CERT_CALLBACKS,
	// X509_REQ
	&PKI_OPENSSL_X509_REQ_CALLBACKS,
	// X509_CRL
	&PKI_OPENSSL_X509_CRL_CALLBACKS,
	// X509_PKCS7
	&PKI_OPENSSL_X509_PKCS7_CALLBACKS,
	// X509_CMS
	&PKI_OPENSSL_X509_CMS_CALLBACKS,
	// X509_PKCS12
	&PKI_OPENSSL_X509_PKCS12_CALLBACKS,
	// X509_OCSP_REQ
	&PKI_OPENSSL_X509_OCSP_REQ_CALLBACKS,
	// X509_OCSP_RESP
	&PKI_OPENSSL_X509_OCSP_RESP_CALLBACKS,
	// X509_OCSP_XPAIR
	&PKI_OPENSSL_X509_XPAIR_CALLBACKS,
	// X509_OCSP_CMS
	NULL, // &PKI_OPENSSL_X509_CMC_CALLBACKS,
	// X509_OCSP_SCEP
	&PKI_OPENSSL_X509_PKCS7_CALLBACKS, // &PKI_OPENSSL_X509_SCEP_CALLBACKS
	// PRQP_REQ
	&PKI_OPENSSL_X509_PRQP_REQ_CALLBACKS,
	// PRQP_RESP
	&PKI_OPENSSL_X509_PRQP_RESP_CALLBACKS
};

const PKI_X509_CALLBACKS *HSM_OPENSSL_X509_get_cb ( PKI_DATATYPE type ) {

	const PKI_X509_CALLBACKS *ret = NULL;

	switch ( type ) {
		case PKI_DATATYPE_X509_KEYPAIR :
			ret = &PKI_OPENSSL_X509_KEYPAIR_CALLBACKS;
			break;
		case PKI_DATATYPE_X509_CERT :
			ret = &PKI_OPENSSL_X509_CERT_CALLBACKS;
			break;
		case PKI_DATATYPE_X509_REQ :
			ret = &PKI_OPENSSL_X509_REQ_CALLBACKS;
			break;
		case PKI_DATATYPE_X509_CRL :
			ret = &PKI_OPENSSL_X509_CRL_CALLBACKS;
			break;
		case PKI_DATATYPE_X509_PKCS7 :
			ret = &PKI_OPENSSL_X509_PKCS7_CALLBACKS;
			break;
		case PKI_DATATYPE_X509_CMS :
			ret = &PKI_OPENSSL_X509_CMS_CALLBACKS;
			break;
		case PKI_DATATYPE_X509_PKCS12 :
			ret = &PKI_OPENSSL_X509_PKCS12_CALLBACKS;
			break;
		case PKI_DATATYPE_X509_OCSP_REQ :
			ret = &PKI_OPENSSL_X509_OCSP_REQ_CALLBACKS;
			break;
		case PKI_DATATYPE_X509_OCSP_RESP :
			ret = &PKI_OPENSSL_X509_OCSP_RESP_CALLBACKS;
			break;
		case PKI_DATATYPE_X509_XPAIR :
			ret = &PKI_OPENSSL_X509_XPAIR_CALLBACKS;
			break;
		case PKI_DATATYPE_X509_CMS_MSG :
			// TODO: Provide support for CMS
			// ret = &PKI_OPENSSL_X509_CMS;
			break;
		case PKI_DATATYPE_EST_MSG :
			// TODO: Provide support for EST
			// ret = &PKI_OPENSSL_X509_CMS_CALLBACKS;
			break;
		case PKI_DATATYPE_SCEP_MSG :
			ret = &PKI_OPENSSL_X509_PKCS7_CALLBACKS;
			break;
		case PKI_DATATYPE_X509_PRQP_REQ :
			ret = &PKI_OPENSSL_X509_PRQP_REQ_CALLBACKS;
			break;
		case PKI_DATATYPE_X509_PRQP_RESP :
			ret = &PKI_OPENSSL_X509_PRQP_RESP_CALLBACKS;
			break;
		default:
			return NULL;
	}

	return ret;
}
