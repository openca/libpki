/* openssl/pki_x509_cms.c */

#include <openssl/opensslv.h>
#include "internal/ossl_1_1_1/cms_lcl.h"
#include <openssl/x509.h>

#ifndef _LIBPKI_PKI_H
#include <libpki/pki.h>
#endif

#ifdef LIBPKI_X509_DATA_ST_H
#include "internal/x509_data_st.h"
#endif

/* ------------------------------ internal (static ) ------------------------- */

/*
static STACK_OF(X509) * __get_chain (const PKI_X509_CMS * const cms) {

	PKI_X509_CMS_VALUE * value = NULL;

	if( !cms || !(value = PKI_X509_get_value(cms))) return PKI_ERR;

	switch (PKI_X509_CMS_get_type(cms)) {

		// Signed CMS
		case PKI_X509_CMS_TYPE_SIGNED: {
			return CMS_get1_certs(value);
		} break;

		default: {
			PKI_DEBUG("CMS Type not suitable for Certificates retrieval.");
		}
	}

	// No Success
	return NULL;
}

static const STACK_OF(X509_CRL) *__get_crl (const PKI_X509_CMS * const cms ) {

	PKI_X509_CMS_VALUE * value = NULL;

	if (!cms || !(value = PKI_X509_get_value(cms))) return PKI_ERR;

	switch (PKI_X509_CMS_get_type(cms)) {

		// Signed CMS
		case PKI_X509_CMS_TYPE_SIGNED: {
			// Success Case
			return CMS_get1_crls(value);
		} break;

		default: {
			PKI_DEBUG("CMS Type not suitable for CRL retrieval.");
		}
	}

	// No Success
	return NULL;
}
*/

/*! \brief Returns the number of recipients */

int PKI_X509_CMS_get_recipients_num(const PKI_X509_CMS * const cms ) {

	STACK_OF(CMS_RecipientInfo) *r_sk = NULL;
	PKI_X509_CMS_VALUE * val = NULL;

	if (!cms || !(val = PKI_X509_get_value(cms))) return -1;

	// Gets a reference to the recipient Infos
	r_sk  = CMS_get0_RecipientInfos(val);

	// Returns the number of entries in the recipient info stack
	// or zero ('0') otherwise
	return (r_sk == NULL ? 0 : sk_CMS_RecipientInfo_num(r_sk));
}

/*! \brief Returns the number of signers */

int PKI_X509_CMS_get_signers_num(const PKI_X509_CMS * const cms) {

	STACK_OF(CMS_SignerInfo) *r_sk = NULL;
	PKI_X509_CMS_VALUE * val = NULL;

	if (!cms || !(val = PKI_X509_get_value(cms))) return -1;

	// Gets a reference to the recipient Infos
	r_sk  = CMS_get0_SignerInfos(val);

	// Returns the number of entries in the recipient info stack
	// or zero ('0') otherwise
	return (r_sk == NULL ? 0 : sk_CMS_SignerInfo_num(r_sk));
}

PKI_X509_CMS_RECIPIENT_INFO * PKI_X509_CMS_get_recipient_info(
					                            const PKI_X509_CMS         * const cms,
					                            int                    idx ) {

	STACK_OF(CMS_RecipientInfo) *r_sk = NULL;
	PKI_X509_CMS_RECIPIENT_INFO * ri = NULL;
	PKI_X509_CMS_VALUE * val = NULL;

	// Checks we have an internal value
	if (!cms || !(val = (PKI_X509_CMS_VALUE *)PKI_X509_get_value(cms)))
		return NULL;

	// Gets a reference to the recipient Infos
	if ((r_sk  = CMS_get0_RecipientInfos(val)) == NULL)
		return NULL;

	// Let's check we have enough values
	if (idx < sk_CMS_RecipientInfo_num(r_sk))
		ri = sk_CMS_RecipientInfo_value(r_sk, idx);

	// Returns the number of entries in the recipient info stack
	// or zero ('0') otherwise
	return ri;
}

/*! \brief Returns the Recipient Info position for the passed cert */

int PKI_X509_CMS_recipient_num(const PKI_X509_CMS  * const cms,
                               const PKI_X509_CERT * const x ) {

	PKI_X509_CMS_RECIPIENT_INFO *r_info = NULL;
	  // Temp Pointer

	int idx = 0;
	int res = 0;
	  // Index and intermediate result for loop cycle

	while ((r_info = PKI_X509_CMS_get_recipient_info(cms, idx)) != NULL) {

		// Checks if this r_info is the one for the passed certificates
		if ((res = CMS_RecipientInfo_kari_orig_id_cmp(r_info, x->value)) == 0) {
			return idx;
		}

		// Increase the counter
		idx++;
	}

	// If here, we did not find it
	return -1;
}

/*! \brief Returns the encryption algorithm */

const PKI_X509_ALGOR_VALUE * PKI_X509_CMS_get_encode_alg(
				const PKI_X509_CMS * const cms) {

	PKI_X509_ALGOR_VALUE *ret = NULL;
	PKI_X509_CMS_VALUE *val = NULL;

	// Input Check
	if( !cms || !(val = PKI_X509_get_value(cms)))
		return NULL;

	// Different Types of data
	switch (PKI_X509_CMS_get_type(cms)) {

		// Enveloped Data (common case)
		case PKI_X509_CMS_TYPE_ENVELOPED: {
			if (val->d.envelopedData && val->d.envelopedData->encryptedContentInfo)
				ret = val->d.envelopedData->encryptedContentInfo->contentEncryptionAlgorithm;
		} break;

		// Encrypted Data (less common case)
		case PKI_X509_CMS_TYPE_SYM_ENCRYPTED: {
			if (val->d.envelopedData && val->d.envelopedData->encryptedContentInfo)
				ret = val-> d.envelopedData->encryptedContentInfo->contentEncryptionAlgorithm;
		} break;
/*
		case PKI_X509_CMS_TYPE_SIGNEDANDENCRYPTED:
			ret = val->d.signed_and_enveloped->enc_data->algorithm;
			break;
*/

		default:
			ret = NULL;
	}

	return ret;
}

const PKI_X509_CMS_SIGNER_INFO * PKI_X509_CMS_get_signer_info(
					const PKI_X509_CMS * const cms, 
					int                        idx ) {

  STACK_OF(CMS_SignerInfo) * x_sk = NULL;
    // Stack of Signer Info

  PKI_X509_CMS_VALUE * val = NULL;
    // Pointer to Internal value for CMS

  PKI_X509_CMS_SIGNER_INFO * ret = NULL;
    // Pointer for the return value

  int cnt = 0;
    // Number of SignerInfo

	// Input Check
	if (!cms || !(val = PKI_X509_get_value(cms)))
		return NULL;

	// Gets the list of signer info
	if ((x_sk = CMS_get0_SignerInfos((CMS_ContentInfo *)val)) == NULL)
		return NULL;

	// Retrieves the Signer Info structure
	if ((cnt = sk_CMS_SignerInfo_num(x_sk)) < 0) {
		PKI_ERROR(PKI_ERR_X509_CMS_SIGNER_INFO_NULL, NULL);
		return NULL;
	}

	// If the requested is out of scope, nothing to return
	if (idx > cnt) return NULL;

	// Retrieves the value
	if( idx >= 0 ) {
		ret = sk_CMS_SignerInfo_value(x_sk, idx);
	} else {
		ret = sk_CMS_SignerInfo_value(x_sk, cnt-1);
	}
	
	// All Done
	return ret;
}

/* --------------------- Internal Mem Functions ----------------------- */

PKI_X509_CMS_VALUE * PKI_X509_CMS_VALUE_new(void) {
	return M_ASN1_new_of(CMS_ContentInfo);
}

PKI_X509_CMS_VALUE * PKI_X509_CMS_VALUE_dup(const PKI_X509_CMS_VALUE * const cms) {
	return ASN1_item_dup((const ASN1_ITEM *)cms, NULL);
}

void PKI_X509_CMS_VALUE_free(PKI_X509_CMS_VALUE *cms) {
	M_ASN1_free_of(cms, CMS_ContentInfo);
}

/* ----------------------- PEM I/O Functions ------------------------- */

#if OPENSSL_VERSION_NUMBER <= 0x10101000L
PKI_X509_CMS_VALUE *PEM_read_bio_CMS( PKI_IO *bp ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
	return (PKI_X509_CMS_VALUE *) PEM_ASN1_read_bio( (char *(*)()) d2i_CMS_ContentInfo, 
				PEM_STRING_CMS, bp, NULL, NULL, NULL);
#else
	return (PKI_X509_CMS_VALUE *) PEM_ASN1_read_bio( (void *(*)()) d2i_CMS_ContentInfo, 
				PEM_STRING_CMS, bp, NULL, NULL, NULL);
#endif
}

int PEM_write_bio_CMS( BIO *bp, PKI_X509_CMS_VALUE *o ) {
	return PEM_ASN1_write_bio ( (int (*)())i2d_CMS_ContentInfo, 
			PEM_STRING_CMS, bp, (char *) o, NULL, 
				NULL, 0, NULL, NULL );
}
#endif


/* ----------------------- Exported Functions ------------------------- */

void PKI_X509_CMS_free_void(void *cms) {
	// Free the memory associated with the CMS
	if (cms) PKI_X509_free((PKI_X509_CMS *) cms);
	return;
}

void PKI_X509_CMS_free(PKI_X509_CMS *cms) {
	// Free the memory associated with the CMS
	if (cms) PKI_X509_free(cms);
	return;
}

PKI_X509_CMS *PKI_X509_CMS_new(PKI_X509_CMS_TYPE type, int flags) {

	PKI_X509_CMS * cms = NULL;
	PKI_X509_CMS_VALUE * value  = NULL;
	  // Container for the main data structures

	unsigned int u_flags;

	// Creation Flags
	if (flags <= 0) {
		// Sets the Default Flags
		flags = PKI_X509_CMS_FLAGS_INIT_DEFAULT;
	}

	// Make sure we have the CMS_PARTIAL in the flags
	u_flags = (unsigned int)(flags |= CMS_PARTIAL);

	// Initializes Based on the Type
	switch (type) {

        case PKI_X509_CMS_TYPE_DATA: {
        	value = CMS_data_create(NULL, u_flags);
        } break;

				case PKI_X509_CMS_TYPE_SIGNED: {
					flags |= PKI_X509_CMS_FLAGS_REUSE_DIGEST;
					if (flags & PKI_X509_CMS_FLAGS_DETACHED)
						flags |= PKI_X509_CMS_FLAGS_STREAM;
					value = CMS_sign(NULL, NULL, NULL, NULL, u_flags);
				} break;

        case PKI_X509_CMS_TYPE_ENVELOPED: {
        	if (flags & PKI_X509_CMS_FLAGS_DETACHED) flags |= PKI_X509_CMS_FLAGS_STREAM;
        	value = CMS_encrypt(NULL, NULL, PKI_CIPHER_AES(256, cbc), u_flags);
        } break;

        case PKI_X509_CMS_TYPE_DIGEST: {
        	value = CMS_digest_create(NULL, PKI_DIGEST_ALG_SHA256, u_flags);
        } break;

        case PKI_X509_CMS_TYPE_SMIME_COMPRESSED: {
        	value = CMS_compress(NULL, NID_zlib_compression, u_flags);
        } break;

        case PKI_X509_CMS_TYPE_SYM_ENCRYPTED: {
        	value = CMS_EncryptedData_encrypt(NULL, PKI_CIPHER_AES(256, cbc), NULL, 0, u_flags);
        } break;

        default: {
        	PKI_ERROR(PKI_ERR_X509_CMS_TYPE_UNKNOWN, NULL);
        	return NULL;
        } break;
	}

	if ((flags & CMS_DETACHED) > 0 && !CMS_set_detached(value, 1)) {
		PKI_ERROR(PKI_ERR_X509_CMS_SET_DETACHED, NULL);
		CMS_ContentInfo_free(value);

		return NULL;
	}

	// Allocates the new structure with the generated value
	if ((cms = PKI_X509_new_value(PKI_DATATYPE_X509_CMS, value, NULL)) == NULL) {

		// Reports the error
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		CMS_ContentInfo_free(value);

		// Nothing to return
		return NULL;
	}

	// Updates the internal status/flags
	cms->status = flags;

	// TODO: Remove the Debug
	PKI_DEBUG("Created CMS [ Flags = %d/%u ]", flags, u_flags);

	// Returns the allocated structure
	return cms;
}

PKI_X509_CMS *PKI_X509_CMS_new_value(PKI_X509_CMS_VALUE * value) {

	return PKI_X509_new_value(PKI_DATATYPE_X509_CMS, value, NULL);
}

/*!
 * \brief Returns the type of the PKI_X509_CMS data (see PKI_X509_CMS_TYPE)
 */

PKI_X509_CMS_TYPE PKI_X509_CMS_get_type(const PKI_X509_CMS * const cms ) {

	const PKI_OID * cms_type = NULL;
	// PKI_X509_CMS_TYPE type = PKI_X509_CMS_TYPE_UNKNOWN;
	  // Pointer for the CMS Type (ASN1 OBJECT)

	PKI_X509_CMS_TYPE ret = PKI_X509_CMS_TYPE_UNKNOWN;
	  // Return value;

	// Input Checks
	if (!cms || !cms->value) {
		// Reports the Error
		PKI_ERROR(PKI_ERR_PARAM_NULL,
			"Missing required parameter (cms: %p, value: %p)",
			cms, (cms ? cms->value : NULL));
		// Return Unknown
		return ret;
	}

	// Gets the type
	if ((cms_type = CMS_get0_type((PKI_X509_CMS_VALUE *)cms->value)) == NULL) {
		// Reports the Error
		PKI_ERROR(PKI_ERR_X509_CMS_TYPE_UNKNOWN, "Cannot get the CMS type");
		// Returns Unknown
		return PKI_X509_CMS_TYPE_UNKNOWN;
	}

	/*
	// Let's get the ID of the Type
	type = (PKI_X509_CMS_TYPE) PKI_OID_get_id(cms_type);

	// Checks it is a recognized type
	switch ( type ) {

		// Fall-through on purpose
        case PKI_X509_CMS_TYPE_DATA:
        case PKI_X509_CMS_TYPE_DIGEST:
        case PKI_X509_CMS_TYPE_SIGNED:
        case PKI_X509_CMS_TYPE_ENVELOPED:
        case PKI_X509_CMS_TYPE_SMIME_COMPRESSED:
        case PKI_X509_CMS_TYPE_SYM_ENCRYPTED: {
        	// Sets the right type to return
        	ret = type;
        } break;

		default: {
			// Sets to the unknown type
			ret = PKI_X509_CMS_TYPE_UNKNOWN;
		} break;
	}
	*/

	// Returns the Type
	return (PKI_X509_CMS_TYPE) PKI_OID_get_id(cms_type);

}

int PKI_X509_CMS_data_set_mem(PKI_X509_CMS  * cms,
							  PKI_MEM       * mem,
							  PKI_MEM      ** out_mem,
							  int             flags) {

	return PKI_X509_CMS_data_set(cms, mem->data, mem->size, out_mem, flags);
}

int PKI_X509_CMS_data_set(PKI_X509_CMS  * cms, 
						  unsigned char * data,
						  size_t          size,
						  PKI_MEM      ** out_data,
						  int             flags) {

	PKI_IO * out_io = NULL;
	  // Empty Output IO

	PKI_IO * cms_io = NULL;
	  // Container for the data

	PKI_MEM * x_out = NULL;
	  // Container for output memory data

	if ((cms_io = BIO_new_mem_buf(data, (int) size)) == NULL) {
		PKI_DEBUG("Cannot Initialize the Data [ Crypto Error: %s (%d) ]",
			HSM_get_errdesc(HSM_get_errno(NULL), NULL), HSM_get_errno(NULL));
		return PKI_ERROR(PKI_ERR_X509_CMS_DATA_INIT, NULL);
	}

	// If we want to get the data, we have to set
	// the detached flag - does not work with Data only
	if (out_data) flags |= PKI_X509_CMS_FLAGS_DETACHED;
		
	// Switch depending on the type of CMS
	switch (PKI_X509_CMS_get_type(cms)) {

		case PKI_X509_CMS_TYPE_SIGNED:
		case PKI_X509_CMS_TYPE_ENVELOPED:
		case PKI_X509_CMS_TYPE_SYM_ENCRYPTED:
		case PKI_X509_CMS_TYPE_SMIME_COMPRESSED: {
			// If detached, we need to collect the
			// output for the detached data
			if (flags &= PKI_X509_CMS_FLAGS_DETACHED) {
				if ((out_io = BIO_new(BIO_s_mem())) == NULL) {
					PKI_IO_free(cms_io);
					return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
				}
			}
		}

		default : {
			// Nothing to do here
		}
	}

	// Sets the flags (if any are passed to override the initial ones)
	if (flags > 0) cms->status = flags;

	// Let's finalize the CMS
	if (!CMS_final((PKI_X509_CMS_VALUE *)cms->value, 
		              cms_io, out_io, (unsigned int)cms->status)) {
		// Reports the error
		PKI_DEBUG("Cannot finalize CMS [%d::%s]",
			HSM_get_errno(NULL), HSM_get_errdesc(HSM_get_errno(NULL), NULL));

		// Free allocated memory
		if (cms_io) PKI_IO_free(cms_io);

		// Returns the error
		return PKI_ERROR(PKI_ERR_X509_CMS_DATA_FINALIZE, NULL);
	}

	if (out_io && BIO_pending(out_io) > 0) {

		size_t data_size = 0;
		unsigned char buf[1024];

		data_size = (size_t)BIO_pending(out_io);

		// Creates the output MEM
		if ((x_out = PKI_MEM_new_null()) == NULL) {
			// Memory Allocation Error
			return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		}

		// Reads from the I/O and writes to the PKI_MEM
		if ((data_size = (size_t) PKI_IO_read(out_io, buf, (int)data_size)) > 0) {

			// Let's Add the Data to the output buffer
			if (PKI_MEM_add(x_out, buf, data_size) != PKI_OK) {

				// Free Memory
				if (cms_io) PKI_IO_free(cms_io);
				if (x_out) PKI_MEM_free(x_out);

				// Reports the error
				return PKI_ERROR(PKI_ERR_X509_CMS_DATA_WRITE, NULL);
			}

			// Let's make sure we save the output in
			// the output variable
			if (!out_data) {
				// Set the reference
				out_data = &x_out;
			} else if (out_data) {
				// Free associated memory
				if (*out_data) PKI_MEM_free(*out_data);
				// Set the reference
				*out_data = x_out;
			}

		} else {

			// Here we failed to read, therefore there is no
			// data for us to process, let's cleanup the output var
			PKI_MEM_free(x_out);
			x_out = NULL;
		}
	}

	// Cleanup
	if (cms_io) PKI_IO_free(cms_io);
	if (out_io) PKI_IO_free(out_io);

	// All Done
	return PKI_OK;
}

PKI_IO * PKI_X509_CMS_stream_init(PKI_X509_CMS * cms) {
	
	PKI_IO * ret = NULL;
		// Container for returned I/O

	// Input Checks
	if (!cms || !cms->value) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	if ((ret = CMS_dataInit((PKI_X509_CMS_VALUE *)cms->value, NULL)) == NULL) {
		PKI_ERROR(PKI_ERR_X509_CMS_DATA_INIT,
			"Cannot Initialize the Data [ Crypto Error: %s (%d) ]",
			HSM_get_errdesc(HSM_get_errno(NULL), NULL), HSM_get_errno(NULL));
	}

	return ret;
}

int PKI_X509_CMS_stream_write_mem(PKI_IO        * stream,
	                              const PKI_MEM * data) {

	return PKI_X509_CMS_stream_write(stream, data->data, data->size);
}

int PKI_X509_CMS_stream_write(PKI_IO              * stream,
                              const unsigned char * data,
                              size_t                size) {

	// Input Checks
	if (!stream || !data)
		return PKI_ERR_PARAM_NULL;

	if (size > 0 && !PKI_IO_write(stream, data, (int)size))
		return PKI_ERR;

	return PKI_OK;
}

int PKI_X509_CMS_stream_final(PKI_X509_CMS * cms, PKI_IO * cms_io) {

	unsigned long err = 0;

	// Input Checks
	if (!cms || !cms->value || !cms_io)
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// Finalizes the calls
	if (!CMS_dataFinal((PKI_X509_CMS_VALUE *)cms->value, cms_io)) goto err;

	// All done
	return PKI_OK;

err:

	err = ERR_get_error();
    if (err != 0)
            PKI_DEBUG("Crypto Error: %s", ERR_error_string(err, NULL));

	return PKI_ERR;

}

PKI_X509_CMS * PKI_X509_CMS_wrap(PKI_X509_CMS      ** cms,
								 PKI_X509_CMS_TYPE    type) {

	return NULL;
}

PKI_X509_CMS * PKI_X509_CMS_unwrap(PKI_X509_CMS **cms) {
	return NULL;
}


int PKI_X509_CMS_add_crl(PKI_X509_CMS     * cms,
			               const PKI_X509_CRL * const crl ) {

	// Input Check
	if (!cms || !cms->value || !crl || !crl->value)
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// Adds the CRL to the CMS value structure
	CMS_add1_crl(cms->value, crl->value);

	// All Done
	return PKI_OK;
}

int PKI_X509_CMS_add_crl_stack(PKI_X509_CMS             * cms, 
				               const PKI_X509_CRL_STACK * const crl_sk ) {

	// Input Check
	if (!cms || !cms->value || !crl_sk ) {
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
	}

	// Cycle through the CRL stack and add them to the CMS
	for (int i = 0; i < PKI_STACK_X509_CRL_elements(crl_sk); i++) {
		PKI_X509_CRL *crl = NULL;

		// Gets the CRL from the stack
		if ((crl = PKI_STACK_X509_CRL_get_num(crl_sk, i)) == NULL) {
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			return PKI_ERR;
		}

		// Adds the CRL to the CMS value structure
		CMS_add1_crl( cms->value, crl->value);
	}

	// All Done
	return PKI_OK;
}


/*! \brief Returns the number of CRLs present in the signature */

int PKI_X509_CMS_get_crls_num(const PKI_X509_CMS * const cms ) {

	int n_elements = -1;

	STACK_OF(X509_CRL) * sk = NULL; 
		// Retrieves the CRL stack from the CMS structure

	// Input Check
	if (!cms || !cms->value) return n_elements;

	// Gets the CRL stack from the CMS structure
	sk = CMS_get1_crls(cms->value);
	if (!sk) return -1;

	// Gets the number of elements from the stack
	n_elements = PKI_STACK_X509_CERT_elements(sk);

	// Frees the stack
	sk_X509_CRL_free(sk);

	// All Done
	return n_elements;
}


/*! \brief Returns a copy of the n-th CRL from the signature */

PKI_X509_CRL *PKI_X509_CMS_get_crl(const PKI_X509_CMS * const cms,
				                   int                        idx) {


	PKI_X509_CRL_VALUE * ret_value = NULL;
	PKI_X509_CRL *ret = NULL;
		// Return value

	STACK_OF(X509_CRL) * sk = NULL; 
		// Stack of X509_CRL_VALUE

	// Input Check
	if (!cms || !cms->value) return NULL;

	// Gets the CRL stack from the CMS structure
	sk = CMS_get1_crls(cms->value);
	if (!sk) return NULL;

	// Gets the n-th element from the stack
	ret_value = sk_X509_CRL_value(sk, idx);
	if (!ret_value) return NULL;

	// Builds the return object
	ret = PKI_X509_CRL_new_null();
	if (!ret) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	// Assigns the internal value
	ret->value = ret_value;
	ret_value = NULL;

	// Free the memory
	sk_X509_CRL_free(sk);
	sk = NULL;

	// All done
	return ret;
}

/*! \brief Adds a certificate to the signature's certificate chain */

int PKI_X509_CMS_add_cert(const PKI_X509_CMS  * cms, 
			    		  const PKI_X509_CERT * const x) {

	if (!cms || !cms->value || !x || !x->value) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	if (!CMS_add1_cert(cms->value, x->value)) {
		PKI_DEBUG("Cannot Add the certificate to the CMS structure (%s)", 
			HSM_get_errdesc(HSM_get_errno(NULL), NULL));
		return PKI_ERR;
	}

	return PKI_OK;
}

/*! \brief Adds a stack of certificates to the signature's certificate chain */

int PKI_X509_CMS_add_cert_stack(const PKI_X509_CMS        * cms, 
				  				const PKI_X509_CERT_STACK * const x_sk) {

	// Input Checks
	if( !cms || !cms->value || !x_sk ) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	// Adds the individual certificates
	for(int i = 0; i < PKI_STACK_X509_CERT_elements( x_sk ); i++ ) {

		PKI_X509_CERT *x = NULL;
			// Certificate from the stack

		if ((x = PKI_STACK_X509_CERT_get_num( x_sk, i )) == NULL) {
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			return PKI_ERR;
		}

		if (!PKI_X509_CMS_add_cert(cms, x)) {
			PKI_DEBUG("ERROR::Cannot add the %d-th certificate to the CMS", i);
			return PKI_ERR;
		}
	}

	// All done
	return PKI_OK;
}

/*! \brief Returns the number of certificates present in the signature chain */

int PKI_X509_CMS_get_certs_num(const PKI_X509_CMS * const cms ) {

	int ret = 0;
	STACK_OF(X509) *x_sk = NULL;
		// Internal stack of certificates

	// Input Check
	if (!cms || !cms->value) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return -1;
	}

	// Gets the internal stack of certificates
	x_sk = CMS_get1_certs(cms->value);
	if (!x_sk) return -1;

	// Gets the number of elements in the stack
	ret = sk_X509_num(x_sk);

	// Free the stack
	sk_X509_pop_free(x_sk, X509_free);
	x_sk = NULL;

	// All Done
	return ret;
}


/*! \brief Returns a copy of the n-th cert from a singed/signed&enc PKCS7 */

PKI_X509_CERT *PKI_X509_CMS_get_cert(const PKI_X509_CMS * const cms,
				       				 int 						idx) {

	PKI_X509_CERT * ret = NULL;
		// Return value

	PKI_X509_CERT_VALUE * x = NULL;
	STACK_OF(X509) *x_sk = NULL;
		// Internal stack of certificates

	// Input Check
	if (!cms || !cms->value) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	// Gets the internal stack of certificates
	x_sk = CMS_get1_certs(cms->value);
	if (!x_sk) return NULL;

	// Gets the number of elements in the stack
	x = sk_X509_value(x_sk, idx);
	if (!x) {
		PKI_ERROR(PKI_ERR_POINTER_NULL, NULL);
		return NULL;
	}

	// Duplicates the certificate and put it in a PKI_X509 structure
	ret = PKI_X509_new_dup_value(PKI_DATATYPE_X509_CERT, x, NULL);
	if (!ret) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	// Free the stack
	sk_X509_pop_free(x_sk, X509_free);
	x_sk = NULL;

	if (!ret) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;		
	}

	// All Done
	return ret;
}

int PKI_X509_CMS_get_signer_num(const PKI_X509_CMS * cms) {

	STACK_OF(CMS_SignerInfo) *si_sk = NULL;
		// Internal stack of SignerInfo

	// Input Check
	if (!cms || !cms->value) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	// Retrieves the stack of signer infos
	si_sk = CMS_get0_SignerInfos(cms->value);
	if (!si_sk) {
		PKI_ERROR(PKI_ERR_POINTER_NULL, NULL);
		return NULL;
	}

	// All Done
	return sk_CMS_SignerInfo_num(si_sk);
}

PKI_X509_CERT *PKI_X509_CMS_get_signer_cert(const PKI_X509_CMS * cms,
				       				    	int                  idx) {

	PKI_X509_CERT * ret = NULL;
		// Return value

	int x_found = 0;
	PKI_X509_CERT_VALUE * x = NULL;
	STACK_OF(X509) *x_sk = NULL;
		// Internal stack of certificates

	STACK_OF(CMS_SignerInfo) *si_sk = NULL;
		// Internal stack of SignerInfo

	// Input Check
	if (!cms || !cms->value) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return NULL;
	}

	// Retrieves the stack of signer infos
	si_sk = CMS_get0_SignerInfos(cms->value);
	if (!si_sk) {
		PKI_ERROR(PKI_ERR_POINTER_NULL, NULL);
		return NULL;
	}

	// Retrieves the stack of certificates
	x_sk = CMS_get1_certs(cms->value);
	if (!x_sk) {
		PKI_ERROR(PKI_ERR_POINTER_NULL, NULL);
		return NULL;
	}

	// Checks we have enough signers
	if (idx > sk_CMS_SignerInfo_num(si_sk)) {
		PKI_ERROR(PKI_ERR_PARAM_RANGE, NULL);
		goto err;
	}

	// Fixes wrong values
	if (idx < 0) idx = 0;

	// Retrieves the idx-th signer info
	PKI_X509_CMS_SIGNER_INFO * si = sk_CMS_SignerInfo_value(si_sk, idx);
	if (!si) {
		PKI_ERROR(PKI_ERR_POINTER_NULL, NULL);
		goto err;
	}

	// Retrieves the right certificate
	for (int i = 0; i < sk_X509_num(x_sk); i++) {
		x = sk_X509_value(x_sk, i);
		if (!x) {
			PKI_ERROR(PKI_ERR_POINTER_NULL, NULL);
			return NULL;
		}
		if (1 == CMS_SignerInfo_cert_cmp(si, x)) {
			x_found = 1;
			break;
		}
	}

	// Check if we found the certificate
	if (!x_found) {
		PKI_DEBUG("No certificate corresponding to the SignerInfo %d was not found", idx);
		goto err;
	}

	// Duplicates the certificate and put it in a PKI_X509 structure
	ret = PKI_X509_new_dup_value(PKI_DATATYPE_X509_CERT, x, NULL);
	if (!ret) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		goto err;
	}

	// Free the stack
	sk_X509_pop_free(x_sk, X509_free);
	x_sk = NULL;

	if (!ret) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;		
	}

	// All Done
	return ret;

err:
	if (x_sk) sk_X509_pop_free(x_sk, X509_free);
	return NULL;
}


/*! \brief Clears the chain of certificate for the signer */

int PKI_X509_CMS_clear_certs(const PKI_X509_CMS * cms) {

	STACK_OF(X509) *x_sk = NULL;
		// Pointer to the stack of certificates

	// Input Checks
	if (!cms || !cms->value) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	// Gets the internal stack of certificates
	x_sk = CMS_get1_certs(cms->value);

	// Free all the certificates on the stack
	while (sk_X509_num(x_sk) > 0) {
		X509 *x = sk_X509_pop(x_sk);
		if (x) X509_free(x);
	}

	// All Done
	return PKI_OK;

}

/*!
 * \brief Returns a signed version of the PKI_X509_CMS by using the passed token
 */

int PKI_X509_CMS_add_signer_tk(PKI_X509_CMS         * cms,
				                       const PKI_TOKEN      * const tk, 
				                       const PKI_DIGEST_ALG * md,
				                       const int              flags) {

	// Input Checks
	if (!cms || !cms->value) return PKI_ERR;

	// Returns the result of the inner function
	return PKI_X509_CMS_add_signer(cms,
                                   tk->cert,
                                   tk->keypair,
                                   md,
                                   flags);
}

/*!
 * \brief Signs a PKI_X509_CMS (must be of SIGNED type)
 */

int PKI_X509_CMS_add_signer(const PKI_X509_CMS     * const cms,
			                const PKI_X509_CERT    * const signer,
			                const PKI_X509_KEYPAIR * const k,
			                const PKI_DIGEST_ALG   * md,
			                const int                flags ) {

	PKI_X509_CMS_TYPE cms_type = PKI_X509_CMS_TYPE_UNKNOWN;
		// CMS Type

	PKI_X509_CMS_SIGNER_INFO * si = NULL;
		// Signer Info

	unsigned int si_flags = CMS_PARTIAL;
	  // Signer Flags

	// Input Check
	if (!cms || !cms->value || !signer || !signer->value || !k || !k->value)
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// Let's get the CMS type
	if ((cms_type = PKI_X509_CMS_get_type(cms)) != PKI_X509_CMS_TYPE_SIGNED)
		return PKI_ERROR(PKI_ERR_X509_CMS_WRONG_TYPE, NULL);

	// Gets the Message Digest (MD)
	if (md == NULL) md = PKI_DIGEST_ALG_SHA256;

	// Process the flags parameter
	if (flags > 0) {

		// Overrides the init parameters with the passed ones
		si_flags = (unsigned int)flags;

	} else {

		// Checks for S/MIME capabilities flag
		if (cms->status & PKI_X509_CMS_FLAGS_NOSMIMECAP) 
			si_flags |= PKI_X509_CMS_FLAGS_NOSMIMECAP;

		// Checks for Attributes flag
		if (cms->status & PKI_X509_CMS_FLAGS_NOATTR)
			si_flags |= PKI_X509_CMS_FLAGS_NOATTR;

		// Checks for Certs flag
		if (cms->status & PKI_X509_CMS_FLAGS_NOCERTS)
			si_flags |= PKI_X509_CMS_FLAGS_NOCERTS;

		// Checks for CRLs flag
		if (cms->status & PKI_X509_CMS_FLAGS_NOCRL)
			si_flags |= PKI_X509_CMS_FLAGS_NOCRL;

		// Checks for KeyID flag
		if (cms->status & PKI_X509_CMS_FLAGS_USE_KEYID)
			si_flags |= PKI_X509_CMS_FLAGS_USE_KEYID;

	}

	// Let's just Add the Signer
	if ((si = CMS_add1_signer(cms->value, 
	                          signer->value,
							  k->value, 
							  md,
							  si_flags)) == NULL) {
		// Describes the Error
		PKI_DEBUG("Cannot Add Signer [%d::%s]",
			HSM_get_errno(NULL),
			HSM_get_errdesc(HSM_get_errno(NULL), NULL));
		// Returns the Error
		return PKI_ERROR(PKI_ERR_X509_CMS_SIGNER_ADD, NULL);
	}

	return PKI_OK;
}

/*! \brief Returns PKI_OK if the cms has signers already set, PKI_ERR
 *         otherwise
 */

int PKI_X509_CMS_has_signers(const PKI_X509_CMS * const cms ) {

  PKI_X509_CMS_TYPE cms_type = PKI_X509_CMS_TYPE_UNKNOWN;
    // CMS Type

	// Input Checks
	if (!cms || !cms->value) return PKI_ERR;


	// Gets the CMS Type
	cms_type = PKI_X509_CMS_get_type(cms);

	// Checks we have the right type
	switch (cms_type) {

		// For Signed types only
		case PKI_X509_CMS_TYPE_SIGNED: {
			// Gets the Reference to the SI (if any)
		  if (CMS_get0_SignerInfos(cms->value) != NULL) 
		  	return PKI_OK;
		} break;

		default: {
			// Nothing to be done, error
			return PKI_ERR;
		}
	}

	// If reaches here, it is not a supported format
	return PKI_ERR;
}

/*! \brief Returns PKI_OK if the cms has recipients already set, PKI_ERR
 *         otherwise
 */

int PKI_X509_CMS_has_recipients(const PKI_X509_CMS * const cms) {

	STACK_OF(CMS_RecipientInfo) * x_sk = NULL;
	PKI_X509_CMS_VALUE * val = NULL;

	// Input Check
	if (!cms || !(val = PKI_X509_get_value(cms))) return PKI_ERR;

	// Gets the stack of recipient info
	x_sk = CMS_get0_RecipientInfos(val);

	// Returns PKI_OK if we have any recipient info
	return (x_sk != NULL ? PKI_OK : PKI_ERR);
}

/*!
 * \brief Encode a PKI_X509_CMS by performing sign/encrypt operation
 */

int PKI_X509_CMS_encode(const PKI_X509_CMS * const cms,
			  unsigned char *data, 
			  size_t size ) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return -1;

	/*
	int type = NID_CMS_signed;
	const PKCS7_SIGNER_INFO * signerInfo = NULL;
	BIO *bio = NULL;

	if( !cms || !cms->value ) return ( PKI_ERR );

	type = PKI_X509_CMS_get_type ( cms );

	if (( type == PKI_X509_CMS_TYPE_ENCRYPTED ) 
			|| (type == PKI_X509_CMS_TYPE_SIGNEDANDENCRYPTED)) {

		if ( PKI_X509_CMS_has_recipients ( cms ) == PKI_ERR ) {
			PKI_log_debug ( "PKI_X509_CMS_encode()::Missing "
								"Recipients!");
			return PKI_ERR;
		}
	}

	if ( (type == PKI_X509_CMS_TYPE_SIGNED) ||
			(type == PKI_X509_CMS_TYPE_SIGNEDANDENCRYPTED )) {

		if(( signerInfo = PKI_X509_CMS_get_signer_info( cms,
							-1 )) == NULL ) {
			return ( PKI_ERR );
		}

		PKCS7_add_signed_attribute((PKCS7_SIGNER_INFO *)signerInfo,
					    NID_pkcs9_contentType,
					    V_ASN1_OBJECT,
					    OBJ_nid2obj(NID_CMS_data));
	}

	if((bio = PKCS7_dataInit(cms->value, NULL)) == NULL ) {
		PKI_log_err("PKI_X509_CMS_sign()::Error dataInit [%s]",
			ERR_error_string(ERR_get_error(),NULL));
		return ( PKI_ERR );
	}
	
	if( BIO_write( bio, data, (int) size ) <= 0 ) {
		PKI_log_err("PKI_X509_CMS_sign()::Error dataSign [%s]",
			ERR_error_string(ERR_get_error(),NULL));
		return ( PKI_ERR );
	}

	(void)BIO_flush(bio);

	if(!PKCS7_dataFinal( cms->value, bio )) {
		PKI_log_err("PKI_X509_CMS_sign()::Error End dataSign [%s]",
			ERR_error_string(ERR_get_error(),NULL));
		return ( PKI_ERR );
	};

	if( bio ) BIO_free_all ( bio );

	return ( PKI_OK );
	*/
}

/*!
 * \brief Returns the raw data contained in a PKI_X509_CMS (any type)
 */

PKI_MEM *PKI_X509_CMS_get_raw_data(const PKI_X509_CMS * const cms ) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return NULL;

	/*
	unsigned char *data = NULL;
	ssize_t len = -1;
	int type = -1;

	PKI_X509_CMS_VALUE *p7val = NULL;
	PKI_MEM *ret = NULL;

	if( !cms || !cms->value ) return ( NULL );

	p7val = cms->value;
	type = PKI_X509_CMS_get_type ( cms );

	switch (type)
	{
		case PKI_X509_CMS_TYPE_DATA:
			data = p7val->d.data->data;
			len  = p7val->d.data->length;
			break;

		case PKI_X509_CMS_TYPE_SIGNED:
			if (p7val->d.sign && p7val->d.sign->contents &&
				p7val->d.sign->contents->d.data)
			{
				data = p7val->d.sign->contents->d.data->data;
				len  = p7val->d.sign->contents->d.data->length;
			}
			break;

		case PKI_X509_CMS_TYPE_ENCRYPTED:
			if (p7val->d.enveloped && p7val->d.enveloped->enc_data &&
				p7val->d.enveloped->enc_data->enc_data)
			{
				data = p7val->d.enveloped->enc_data->enc_data->data;
				len  = p7val->d.enveloped->enc_data->enc_data->length;
			}
			break;

		case PKI_X509_CMS_TYPE_SIGNEDANDENCRYPTED:
			if (p7val->d.signed_and_enveloped &&
				p7val->d.signed_and_enveloped->enc_data &&
				p7val->d.signed_and_enveloped->enc_data->enc_data )
			{
				data = p7val->d.signed_and_enveloped->enc_data->enc_data->data;
				len = p7val->d.signed_and_enveloped->enc_data->enc_data->length;
			}
			break;

		default:
			PKI_log_debug ("Unknown PKCS7 type");
			return NULL;
	}

	if ((ret = PKI_MEM_new_null()) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	if (PKI_MEM_add(ret, (char *) data, (size_t) len) == PKI_ERR)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Memory Failure (ret=%p, data=%p, len=%d)",
				ret, data, len );
		PKI_MEM_free ( ret );
		return NULL;
	}

	//
  //      if((p7bio = PKCS7_dataInit(cms->value ,NULL)) != NULL ) {
	//	(void)BIO_flush(p7bio);
  //              ret = PKI_MEM_new_bio( p7bio, NULL );
	//	BIO_free_all ( p7bio );
  //      } else {
	//	PKI_log_debug("PKCS7::get_raw_data()::Can not get data [%s]",
	//		ERR_error_string(ERR_get_error(), NULL ));
	// }

	return ( ret );
	*/
}

/*!
 * \brief Decrypts (if needed) and returns the idata from a PKI_X509_CMS by using
 *        keypair and, if present, cert of the PKI_TOKEN argument.
 */

PKI_MEM *PKI_X509_CMS_get_data_tk(const PKI_X509_CMS * const cms,
				    const PKI_TOKEN * const tk ) {

	if (!cms || !tk ) return NULL;

	return PKI_X509_CMS_get_data(cms, tk->keypair, tk->cert);
}

/*!
 * \brief Decrypts (if needed) and returns the data from a PKI_X509_CMS
 */

PKI_MEM *PKI_X509_CMS_get_data(const PKI_X509_CMS * const cms,
				 const PKI_X509_KEYPAIR * const k,
				 const PKI_X509_CERT * const x ) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return NULL;

	/*
	PKI_ID type;

	if( !cms || !cms->value ) return ( NULL );

	type = PKI_X509_CMS_get_type ( cms );

	switch ( type ) {
		case PKI_X509_CMS_TYPE_ENCRYPTED:
		case PKI_X509_CMS_TYPE_SIGNEDANDENCRYPTED:
			PKI_log_debug("PKI_X509_CMS_get_data()::cms is encrypted!");
			return PKI_X509_CMS_decode ( cms, k, x );
			break;
		default:
			PKI_log_debug("PKI_X509_CMS_get_data()::cms not encrypted");
			return PKI_X509_CMS_get_raw_data ( cms );
	}
	*/
}

/*!
 * \brief Decrypts the data from a (must) encrypted PKI_X509_CMS
 */


PKI_MEM *PKI_X509_CMS_decode(const PKI_X509_CMS * const cms,
			       const PKI_X509_KEYPAIR * const k, 
			       const PKI_X509_CERT * const x ) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return NULL;

	/*
	BIO *bio = NULL;
	PKI_MEM *mem = NULL;
	PKI_ID type = 0;
	PKI_X509_CERT_VALUE *x_val = NULL;
	PKI_X509_KEYPAIR_VALUE *pkey = NULL;

	if ( !cms || !cms->value || !k || !k->value ) {
		PKI_log_debug("PKI_X509_CMS_decode()::Missing cms or pkey!");
		return ( NULL );
	};
 
	pkey = k->value;

	type = PKI_X509_CMS_get_type ( cms );

	switch ( type ) {
		case PKI_X509_CMS_TYPE_ENCRYPTED:
		case PKI_X509_CMS_TYPE_SIGNEDANDENCRYPTED:
			break;
		default:
			PKI_log_debug("PKI_X509_CMS_decode()::Wrong MSG type!");
                	return PKI_ERR;
        }

	if ( x ) x_val = x->value;

	if((bio = PKCS7_dataDecode(cms->value, pkey, NULL, x_val)) == NULL) {
		PKI_log_debug ( "PKI_X509_CMS_decode()::Decrypt error [%s]",
			ERR_error_string(ERR_get_error(), NULL ));
		return ( NULL );
	}

	if((mem = PKI_MEM_new_bio( (PKI_IO *) bio, NULL )) == NULL ) {
		PKI_log_debug("PKI_X509_CMS_decode()::Memory Error!");
		if( bio ) BIO_free_all ( bio );
		return ( NULL );
	}

	if (bio ) BIO_free_all ( bio );

	return ( mem );
	*/
}

/*! \brief Set the cipher in a encrypted (or signed and encrypted) PKCS7 */

int PKI_X509_CMS_set_cipher(PKI_X509_CMS       * const cms,
			      			          const PKI_CIPHER   * const cipher) {

	PKI_X509_CMS_TYPE type = PKI_X509_CMS_TYPE_UNKNOWN;
	  // Type of CMS

	PKI_X509_CMS_VALUE * tmp_val = NULL;
		// Temporary Pointer


	// Input Checks
	if (!cms || !cms->value || !cipher) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	// Aux Variable for signdness
	unsigned int cms_status = (unsigned int) cms->status;

	// Gets the CMS Type
	type = PKI_X509_CMS_get_type(cms->value);

	// Set the Ciphers depending on the type of
	// CMS that we are passing on
	switch (type) {

		case PKI_X509_CMS_TYPE_ENVELOPED: {

			// Allocates the new CMS with the new cipher
			if ((tmp_val = CMS_encrypt(NULL, 
									   NULL, 
									   cipher, 
				                       cms_status)) == NULL) {
				// Reports the error
				return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		  	}

			// Free the current value, if any
			if (cms->value) PKI_X509_CMS_VALUE_free(cms->value);

			// Assigns the internal value
			cms->value = tmp_val;

		} break;

		case PKI_X509_CMS_TYPE_SYM_ENCRYPTED: {

			// Allocates the new CMS with the new cipher
			if ((tmp_val = CMS_EncryptedData_encrypt(NULL,
				                                     PKI_CIPHER_AES(256, cbc), 
				                                     NULL,
				                                     0, 
				                                     cms_status)) == NULL) {
				// Reports the error
				return PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		  	}

			// Free the current value, if any
			if (cms->value) PKI_X509_CMS_VALUE_free(cms->value);

			// Assigns the internal value
			cms->value = tmp_val;

		} break;

		default: {
			PKI_ERROR(PKI_ERR_X509_CMS_WRONG_TYPE, NULL);
			return PKI_ERR;
		}
	}

	return PKI_OK;

}
	

/*! \brief Sets the recipients for a PKI_X509_CMS */

int PKI_X509_CMS_set_recipients(const PKI_X509_CMS *cms, 
				  const PKI_X509_CERT_STACK * const x_sk ) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return -1;

/*
	int i = 0;
	int type;

	if( !cms || !cms->value || !x_sk ) return ( PKI_ERR );

	type = PKI_X509_CMS_get_type ( cms );
	switch ( type ) {
		case PKI_X509_CMS_TYPE_ENCRYPTED:
		case PKI_X509_CMS_TYPE_SIGNEDANDENCRYPTED:
			break;
		default:
			return PKI_ERR;
	}

	for( i = 0; i < PKI_STACK_X509_CERT_elements ( x_sk ); i++ ) {
		PKI_X509_CERT *x = NULL;
		x = PKI_STACK_X509_CERT_get_num( x_sk, i );
		PKCS7_add_recipient( cms->value, x->value );
		PKI_X509_CMS_add_cert ( cms, x );
	}

	return ( PKI_OK );
*/

}

/*! \brief Adds a new recipient identified by a PKI_TOKEN */

int PKI_X509_CMS_add_recipient_tk(const PKI_X509_CMS * cms,
                                  const PKI_TOKEN    * const tk,
                                  const PKI_CIPHER   * const cipher,
                                  const int            flags) {

	return PKI_X509_CMS_add_recipient(cms, tk->cert, cipher, flags);

}

/*! \brief Adds a new recipient for the PKI_X509_CMS */

int PKI_X509_CMS_add_recipient(const PKI_X509_CMS  * cms,
                               const PKI_X509_CERT * const x,
                               const PKI_CIPHER    * const cipher,
                               const int             flags) {

	PKI_X509_CMS_TYPE cms_type = PKI_X509_CMS_TYPE_UNKNOWN;
		// CMS Type

	PKI_X509_CMS_RECIPIENT_INFO * ri = NULL;
		// Recipient Info

	unsigned int ri_flags = PKI_X509_CMS_FLAGS_PARTIAL;
	  // Recipient Flags

	// Input Check
	if (!cms || !cms->value || !x || !x->value)
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// Let's get the CMS type
	if ((cms_type = PKI_X509_CMS_get_type(cms)) != PKI_X509_CMS_TYPE_ENVELOPED)
		return PKI_ERROR(PKI_ERR_X509_CMS_WRONG_TYPE, NULL);

	// Checks the flags parameter	
	if (flags > 0) {

		// If the flags are passed directly,
		// let's override the status ones
		ri_flags = (unsigned int) flags;

	} else {

		// Checks for Certs flag
		if (cms->status & PKI_X509_CMS_FLAGS_NOCERTS)
			ri_flags |= PKI_X509_CMS_FLAGS_NOCERTS;

		// Checks for CRLs flag
		if (cms->status & PKI_X509_CMS_FLAGS_NOCRL)
			ri_flags |= PKI_X509_CMS_FLAGS_NOCRL;

		// Checks for KeyID flag
		if (cms->status & PKI_X509_CMS_FLAGS_USE_KEYID)
			ri_flags |= PKI_X509_CMS_FLAGS_USE_KEYID;
	}

	// Let's just Add the Signer
	if ((ri = CMS_add1_recipient_cert(cms->value, 
		                                x->value, ri_flags)) == NULL) {
		// Describes the Error
		PKI_DEBUG("Cannot Add Recipient [%d::%s]",
			HSM_get_errno(NULL),
			HSM_get_errdesc(HSM_get_errno(NULL), NULL));

		// Returns the Error
		return PKI_ERROR(PKI_ERR_X509_CMS_SIGNER_ADD, NULL);
	}

	return PKI_OK;
}

/* -------------------------------- Add Attributes ---------------------- */

int PKI_X509_CMS_add_signed_attribute(const PKI_X509_CMS * cms, 
					PKI_X509_ATTRIBUTE   * a) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return -1;

	/*
	PKCS7_SIGNER_INFO *signerInfo = NULL;

	if (!cms || !cms->value || !a) return PKI_ERR;

	if ((signerInfo = (PKCS7_SIGNER_INFO *)
			PKI_X509_CMS_get_signer_info (cms, -1)) == NULL ) {
		PKI_ERROR(PKI_ERR_GENERAL, "signerInfo not present in PKCS7");
		return PKI_ERR;
	}

	if (signerInfo->auth_attr == NULL) {
		signerInfo->auth_attr = PKI_STACK_X509_ATTRIBUTE_new_null();
	}

	return PKI_STACK_X509_ATTRIBUTE_add(signerInfo->auth_attr, a);
	*/
}

int PKI_X509_CMS_add_attribute(const PKI_X509_CMS * cms,
				 PKI_X509_ATTRIBUTE   * a) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return -1;

	/*
	PKCS7_SIGNER_INFO *signerInfo = NULL;

	if( !cms || !cms->value || !a ) return ( PKI_ERR );

	if ((signerInfo = (PKCS7_SIGNER_INFO *) 
			PKI_X509_CMS_get_signer_info ( cms, -1 )) == NULL ) {
		PKI_DEBUG("signerInfo not present in PKCS#7");
		return PKI_ERR;
	}

	if (signerInfo->unauth_attr == NULL) {
		signerInfo->unauth_attr = PKI_STACK_X509_ATTRIBUTE_new_null();
	}

	return PKI_STACK_X509_ATTRIBUTE_add( signerInfo->unauth_attr, a);
	*/
}

/* -------------------------------- Get Attributes ---------------------- */

const PKI_X509_ATTRIBUTE *PKI_X509_CMS_get_signed_attribute(
					              const PKI_X509_CMS * const cms,
					              PKI_ID                 id) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return NULL;

	/*
	const PKCS7_SIGNER_INFO *signerInfo = NULL;

    if (!cms || !cms->value) {
    	PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    	return NULL;
    }

    if ((signerInfo = PKI_X509_CMS_get_signer_info(cms, -1)) == NULL)
    	return NULL;

    if (signerInfo->auth_attr == NULL) return NULL;

	return PKI_STACK_X509_ATTRIBUTE_get(signerInfo->auth_attr, id);
	*/
}

const PKI_X509_ATTRIBUTE *PKI_X509_CMS_get_attribute(
					const PKI_X509_CMS * const cms, 
					PKI_ID id ) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return NULL;

	/*
	const PKCS7_SIGNER_INFO *signerInfo = NULL;

        if (!cms || !cms->value) return NULL;

        if ((signerInfo = PKI_X509_CMS_get_signer_info(cms, -1)) == NULL) {
		PKI_DEBUG("signerInfo missing in PKCS7");
                return NULL;
        }

        if (signerInfo->unauth_attr == NULL) return NULL;

	return PKI_STACK_X509_ATTRIBUTE_get(signerInfo->auth_attr, id);
	*/
}

const PKI_X509_ATTRIBUTE *PKI_X509_CMS_get_signed_attribute_by_name( 
					const PKI_X509_CMS * const cms,
					const char *name ) {
	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return NULL;

	/*
	const PKCS7_SIGNER_INFO *signerInfo = NULL;

        if (!cms || !cms->value) return NULL;

        if ((signerInfo = PKI_X509_CMS_get_signer_info(cms, -1)) == NULL) {
                PKI_DEBUG("signerInfo not present in PKCS7");
                return NULL;
        }

        if (signerInfo->auth_attr == NULL) return NULL;

	return PKI_STACK_X509_ATTRIBUTE_get_by_name(signerInfo->auth_attr, 
						    name);
	*/
}

const PKI_X509_ATTRIBUTE *PKI_X509_CMS_get_attribute_by_name(
					const PKI_X509_CMS * const cms, 
					const char *name) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return NULL;

	/*
	const PKCS7_SIGNER_INFO *signerInfo = NULL;

        if (!cms || !cms->value) return NULL;

        if ((signerInfo = PKI_X509_CMS_get_signer_info(cms, -1)) == NULL) {
                PKI_DEBUG("signerInfo not present in PKCS7");
                return NULL;
        }

        if (signerInfo->unauth_attr == NULL) return ( NULL );

	return PKI_STACK_X509_ATTRIBUTE_get_by_name(signerInfo->auth_attr, 
						    name);
	*/
}

/* ------------------------------- Delete Attributes ---------------------- */

/*! \brief Deletes a signed attribute (id) from a PKI_X509_CMS */

int PKI_X509_CMS_delete_signed_attribute(const PKI_X509_CMS *cms, 
					   PKI_ID id) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return -1;

	/*
	const PKCS7_SIGNER_INFO *signerInfo = NULL;

	if (!cms || !cms->value) return PKI_ERR;

	if ((signerInfo = PKI_X509_CMS_get_signer_info(cms, -1)) == NULL) {
		PKI_DEBUG("signerInfo not present in PKCS7");
		return PKI_ERR;
	}

	if (signerInfo->auth_attr == NULL) return PKI_OK;

	return PKI_STACK_X509_ATTRIBUTE_delete(signerInfo->auth_attr, id);
	*/
}

/*! \brief Deletes an attribute (id) from a PKI_X509_CMS */

int PKI_X509_CMS_delete_attribute(const PKI_X509_CMS *cms, PKI_ID id ) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return -1;

	/*
	const PKCS7_SIGNER_INFO *signerInfo = NULL;

	if (!cms || !cms->value) return PKI_ERR;

	if ((signerInfo = PKI_X509_CMS_get_signer_info(cms, -1)) == NULL ) {
		PKI_DEBUG("signerInfo not present in PKCS7");
		return ( PKI_ERR );
	}

	if (signerInfo->unauth_attr == NULL) return PKI_OK;

	return PKI_STACK_X509_ATTRIBUTE_delete(signerInfo->unauth_attr, id);
	*/
}

/* ---------------------------- TEXT Format ---------------------------- */

int PKI_X509_CMS_VALUE_print_bio ( PKI_IO *bio, 
				     const PKI_X509_CMS_VALUE *p7val ) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return -1;

	/*
	int type;
	int i,j;

	int cert_num = -1;
	int crl_num = -1;
	int signers_num = -1;
	char *tmp_str = NULL;

	PKI_X509_CMS *msg = NULL;
	PKI_X509_CERT *cert = NULL;
	PKI_DIGEST *digest = NULL;
	PKI_MEM *mem = NULL;

	const PKCS7_SIGNER_INFO *si = NULL;

	if (!bio || !p7val ) return PKI_ERR;

	if (( msg = PKI_X509_new_dup_value ( PKI_DATATYPE_X509_CMS,
				p7val, NULL )) == NULL ) {
		return PKI_ERR;
	}

	type = PKI_X509_CMS_get_type ( msg );

	BIO_printf( bio, "PKCS#7 Message:\r\n" );
	BIO_printf( bio, "    Message Type:\r\n        " );

	switch ( type ) {
		case PKI_X509_CMS_TYPE_ENCRYPTED:
			BIO_printf( bio, "Encrypted\r\n" );
			break;
		case PKI_X509_CMS_TYPE_SIGNED:
			BIO_printf( bio, "Signed\r\n" );
			break;
		case PKI_X509_CMS_TYPE_SIGNEDANDENCRYPTED:
			BIO_printf( bio, "Signed and Encrypted\r\n" );
			break;
		default:
			BIO_printf( bio, "Unknown (%d)\r\n", type );
			break;
	}

	BIO_printf( bio, "    Message Data:\r\n");
	if (( mem = PKI_X509_CMS_get_raw_data ( msg )) == NULL ) {
		BIO_printf( bio, "        None.\r\n");
	} else {
		int msg_type = 0;

		BIO_printf( bio, "        Size=%u bytes\r\n", 
						(unsigned int) mem->size );

		msg_type = PKI_X509_CMS_get_type ( msg );
		if ( msg_type == PKI_X509_CMS_TYPE_ENCRYPTED ||
				msg_type == 
					PKI_X509_CMS_TYPE_SIGNEDANDENCRYPTED){
			BIO_printf( bio, "        Encrypted=yes\r\n");
			BIO_printf( bio, "        Algorithm=%s\r\n",
				PKI_ALGOR_get_parsed (
					PKI_X509_CMS_get_encode_alg ( msg )));
		} else {
			BIO_printf( bio, "        Encrypted=no\r\n");
		}
		PKI_MEM_free ( mem );
	}

	i = 0;
	if (( si = PKI_X509_CMS_get_signer_info ( msg, i )) == NULL ) {
		BIO_printf(bio, "    Signature Info:\r\n" );
		BIO_printf(bio, "        No Signature found.\r\n" );
	}

	// Print the Signer Info
	BIO_printf( bio, "    Signer Info:\r\n");
	signers_num = PKI_X509_CMS_get_signers_num ( msg );
	for ( i = 0; i < signers_num; i++ ) {
		PKCS7_ISSUER_AND_SERIAL *ias = NULL;

		BIO_printf ( bio, "        [%d of %d] Signer Details:\r\n", 
							i+1, signers_num );

		if (( si = PKI_X509_CMS_get_signer_info ( msg, i )) == NULL )
			break;

		if((ias = si->issuer_and_serial) == NULL ) {
			BIO_printf ( bio, "            "
						"ERROR::Missing Info!\r\n");
		} else { 
			tmp_str = PKI_INTEGER_get_parsed ( ias->serial );
			BIO_printf ( bio, "            Serial=%s\r\n", tmp_str );
			PKI_Free ( tmp_str );

			tmp_str = PKI_X509_NAME_get_parsed ( ias->issuer );
			BIO_printf ( bio, "            Issuer=%s\r\n", tmp_str );
			PKI_Free ( tmp_str );
		}

		if ( si->digest_enc_alg ) {
			BIO_printf( bio, "            "
					"Encryption Algoritm=%s\r\n",
				PKI_ALGOR_get_parsed ( si->digest_enc_alg ));
		}

		if ( si->digest_alg ) {
			BIO_printf( bio, "            Digest Algorithm=%s\r\n",
				PKI_ALGOR_get_parsed ( si->digest_alg ));
		}

		BIO_printf( bio, "        Signed Attributes:\r\n");
		if ( si->auth_attr ) {
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
			LIBPKI_X509_ATTRIBUTE_FULL *a = NULL;
#else
			X509_ATTRIBUTE *a = NULL;
#endif
			int attr_num = 0;
			char * tmp_str = NULL;

			for ( attr_num = 0; attr_num < 
				PKI_STACK_X509_ATTRIBUTE_elements ( 
					si->auth_attr ); attr_num++ ) {

				a = PKI_STACK_X509_ATTRIBUTE_get_num ( 
					si->auth_attr, attr_num );

				if ( PKI_OID_get_id ( a->object ) == 
						 NID_pkcs9_messageDigest ) {
					tmp_str = PKI_X509_ATTRIBUTE_get_parsed 
									( a );
					
					BIO_printf( bio, "            "
							"Message Digest:");
					for ( j=0; j < strlen(tmp_str); j++ ) {
						if ( ( j % 60 ) == 0 ) {
							BIO_printf (bio, 
							    "\r\n                ");
						}
						BIO_printf(bio,"%c",tmp_str[j]);
					} BIO_printf( bio, "\r\n");
					// PKI_Free ( tmp_str );

				} else {
					BIO_printf( bio, "            %s=",
						PKI_X509_ATTRIBUTE_get_descr (
							 a ) );
					tmp_str=
					      PKI_X509_ATTRIBUTE_get_parsed(a);
					BIO_printf( bio, "%s\r\n", tmp_str );
					PKI_Free ( tmp_str );
				}
			
			}
		} else {
			BIO_printf( bio, "            None.\r\n");
		}

		BIO_printf( bio,"        Non Signed Attributes:\r\n");
		if ( si->unauth_attr ) {
			PKI_X509_ATTRIBUTE *a = NULL;
			int attr_num = 0;
			char * tmp_str = NULL;

			for ( attr_num = 0; attr_num < 
				PKI_STACK_X509_ATTRIBUTE_elements ( 
					si->auth_attr ); attr_num++ ) {

				a = PKI_STACK_X509_ATTRIBUTE_get_num ( 
					si->auth_attr, attr_num );

				BIO_printf( bio, "            %s=",
					PKI_X509_ATTRIBUTE_get_descr ( a ) );
			
				tmp_str = PKI_X509_ATTRIBUTE_get_parsed ( a );
				BIO_printf( bio, "%s\r\n", tmp_str );
				PKI_Free ( tmp_str );
			}
			BIO_printf( bio, "\r\n");
		} else {
			BIO_printf( bio, "            None.\r\n");
		}
	}
	
	BIO_printf( bio, "\r\n    Recipients Info:\r\n");
	if( PKI_X509_CMS_has_recipients ( msg ) == PKI_ERR ) {
		BIO_printf( bio, "        No Recipients\r\n");
	} else {
		int rec_num = 0;
		const PKI_X509_CERT *rec = NULL;

		rec_num = PKI_X509_CMS_get_recipients_num ( msg );
		for ( i=0; i < rec_num; i++ ) {
			rec = PKI_X509_CMS_get_recipient_cert ( msg, i );
			if ( !rec ) {
				const PKCS7_RECIP_INFO *ri = NULL;
				PKCS7_ISSUER_AND_SERIAL *ias = NULL;

				BIO_printf( bio, "        "
					"[%d of %d] Recipient Details:\r\n", 
						i+1, rec_num );

				ri = PKI_X509_CMS_get_recipient_info(msg,i);
				if (!ri) {
					BIO_printf(bio,"            <ERROR>");
					continue;
				}

				if((ias = ri->issuer_and_serial) != NULL ) {

					tmp_str = PKI_INTEGER_get_parsed (
						ias->serial );
					BIO_printf( bio, "            "
						"Serial=%s\r\n", tmp_str );
					PKI_Free ( tmp_str );
			
					tmp_str = PKI_X509_NAME_get_parsed (
						ias->issuer );
					BIO_printf( bio, "            "
						"Issuer=%s\r\n", tmp_str );
					PKI_Free ( tmp_str );

					BIO_printf( bio, "            "
						"Key Encoding Algorithm=%s\r\n",
						PKI_ALGOR_get_parsed (
							ri->key_enc_algor ));
				}

			} else {

				BIO_printf( bio, "        "
					"[%d] Recipient Certificate:\r\n", i );

				tmp_str = PKI_X509_CERT_get_parsed( cert, 
							PKI_X509_DATA_SUBJECT );

				BIO_printf( bio, "            "
						"Subject=%s\r\n", tmp_str);
				PKI_Free ( tmp_str );
			}
		}
	}

	// Now Let's Check the Certificates
	BIO_printf(bio, "\r\n    Certificates:\r\n");
	if ((cert_num = PKI_X509_CMS_get_certs_num ( msg )) > 0 ) {
		PKI_X509_CERT * cert = NULL;
		for (i = 0; i < cert_num; i++ ) {
			BIO_printf( bio, "        [%d of %d] Certificate:\r\n",
				 i+1, cert_num);
			if((cert = PKI_X509_CMS_get_cert ( msg, i )) == NULL ) {
				BIO_printf( bio, "            Error.\r\n");
				continue;
			};
			tmp_str = PKI_X509_CERT_get_parsed( cert, 
							PKI_X509_DATA_SERIAL );
			BIO_printf( bio, "            Serial=%s\r\n", 
								tmp_str );
			PKI_Free ( tmp_str );
			
			tmp_str = PKI_X509_CERT_get_parsed( cert, 
							PKI_X509_DATA_ISSUER );
			BIO_printf( bio, "            Issuer=%s\r\n", tmp_str );
			PKI_Free ( tmp_str );

			tmp_str = PKI_X509_CERT_get_parsed( cert, 
							PKI_X509_DATA_SUBJECT );

			BIO_printf( bio, "            Subject=%s\r\n", tmp_str);
			PKI_Free ( tmp_str );

			digest = PKI_X509_CERT_fingerprint( cert, 
						PKI_DIGEST_ALG_DEFAULT );
			tmp_str =  PKI_DIGEST_get_parsed ( digest );

			BIO_printf( bio, "            Fingerprint [%s]:",
				PKI_DIGEST_ALG_get_parsed ( 
					PKI_DIGEST_ALG_DEFAULT ));

			for ( j=0; j < strlen(tmp_str); j++ ) {
				if ( ( j % 60 ) == 0 ) {
					BIO_printf (bio,"\r\n                ");
				}
				BIO_printf( bio, "%c", tmp_str[j] );
			} BIO_printf( bio, "\r\n");

			PKI_DIGEST_free ( digest );
			PKI_Free ( tmp_str );

			PKI_X509_CERT_free ( cert );

			// X509_signature_print(bp, 
			// 	br->signatureAlgorithm, br->signature);

		}
	} else {
		BIO_printf( bio, "            None.\r\n");
	}

	// Now Let's Check out the CRLs
	BIO_printf(bio, "\r\n    Certificate Revocation Lists:\r\n");
	if((crl_num = PKI_X509_CMS_get_crls_num ( msg )) > 0 ) {
		PKI_X509_CRL * crl  = NULL;
		for ( i = 0; i < crl_num; i++ ) {
			BIO_printf( bio, "        [%d of %d] CRL Details:\r\n", 
				i+1, crl_num );

			if(( crl = PKI_X509_CMS_get_crl ( msg, i )) == NULL ) {
				BIO_printf(bio,"            ERROR::Missing Data\r\n");
				continue;
			}

			tmp_str = PKI_X509_CRL_get_parsed(crl,PKI_X509_DATA_VERSION);
			BIO_printf( bio, "            Version=%s\r\n", tmp_str );
			PKI_Free ( tmp_str );
		
			// tmp_str = PKI_X509_CRL_get_parsed(crl,PKI_X509_DATA_SERIAL);
			// BIO_printf( bio, "            Serial=%s\r\n", tmp_str );
			// PKI_Free ( tmp_str );
			
			tmp_str = PKI_X509_CRL_get_parsed(crl,PKI_X509_DATA_ISSUER);
			BIO_printf( bio, "            Issuer=%s\r\n", tmp_str );
			PKI_Free ( tmp_str );

			tmp_str = PKI_X509_CRL_get_parsed(crl,
							PKI_X509_DATA_ALGORITHM);
			BIO_printf( bio, "            Algorithm=%s\r\n", tmp_str );
			PKI_Free ( tmp_str );
			
			tmp_str = PKI_X509_CRL_get_parsed(crl,
							PKI_X509_DATA_NOTBEFORE);
			BIO_printf( bio, "            Not Before=%s\r\n", tmp_str );
			PKI_Free ( tmp_str );
			
			tmp_str = PKI_X509_CRL_get_parsed(crl,
							PKI_X509_DATA_NOTAFTER);
			BIO_printf( bio, "            Not After=%s\r\n", tmp_str );
			PKI_Free ( tmp_str );
			
			PKI_X509_CRL_free ( crl );
		}
	} else {
		BIO_printf( bio, "            None.\r\n");
	}
	BIO_printf(bio, "\r\n");

	return PKI_OK;
	*/
}
