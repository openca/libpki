/* openssl/pki_x509_cms.c */

#include <libpki/pki.h>
#include "internal/x509_data_st.h"

/* ------------------------------ internal (static ) ------------------------- */

static STACK_OF(X509) * __get_chain (const PKI_X509_CMS * const cms) {

	PKI_X509_CMS_VALUE * value = NULL;

	if( !cms || !(value = PKI_X509_get_value(cms))) return PKI_ERR;

	switch (PKI_X509_CMS_get_type(cms)) {

		// Signed CMS
		case PKI_X509_CMS_TYPE_SIGNED:
		case PKI_X509_CMS_TYPE_SIGNEDANDENCRYPTED: {
			return CMS_get1_certs(value);
		} break;

		default: {
			PKI_log_debug("CMS Type not suitable for Certificates retrieval.");
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
		case PKI_X509_CMS_TYPE_SIGNED:
		case PKI_X509_CMS_TYPE_SIGNEDANDENCRYPTED: {
			// Success Case
			return CMS_get1_crls(value);
		} break;

		default: {
			PKI_log_debug("CMS Type not suitable for CRL retrieval.");
		}
	}

	// No Success
	return NULL;
}


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

const PKI_X509_CMS_RECIPIENT_INFO * PKI_X509_CMS_get_recipient_info(
					const PKI_X509_CMS * const cms,
					int                    idx ) {

	STACK_OF(CMS_RecipientInfo) *r_sk = NULL;
	PKI_X509_CMS_RECIPIENT_INFO * ri = NULL;
	PKI_X509_CMS_VALUE * val = NULL;

	// Checks we have an internal value
	if (!cms || !(val = PKI_X509_get_value(cms)))
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

/*! \brief Returns a copy of the n-th recipient certificate */

const PKI_X509_CERT * PKI_X509_CMS_get_recipient_cert(
			    const PKI_X509_CMS * const cms,
				int                    idx ) {

	const PKI_X509_CMS_RECIPIENT_INFO *r_info = NULL;

	if ((r_info = PKI_X509_CMS_get_recipient_info(cms, idx)) == NULL)
		return NULL;

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return NULL;
}

/*! \brief Returns the encryption algorithm */

const PKI_ALGOR * PKI_X509_CMS_get_encode_alg(
				const PKI_X509_CMS * const cms) {

	PKI_ALGOR *ret = NULL;
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
		case PKI_X509_CMS_TYPE_ENCRYPTED: {
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
	if ((x_sk = CMS_get0_SignerInfos((CMS_ContentInfo *)cms)) == NULL)
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

PKI_X509_CMS_VALUE * CMS_new(void) {
	return M_ASN1_new_of(CMS_ContentInfo);
}

PKI_X509_CMS_VALUE * CMS_dup(PKI_X509_CMS_VALUE *cms) {
	return ASN1_item_dup((const ASN1_ITEM *)cms, NULL);
}

void CMS_free(PKI_X509_CMS_VALUE *cms) {
	M_ASN1_free_of(cms, CMS_ContentInfo);
}

/* ----------------------- PEM I/O Functions ------------------------- */

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

PKI_X509_CMS *PKI_X509_CMS_new(PKI_X509_CMS_TYPE type) {

	PKI_X509_CMS       * cms    = NULL;
	PKI_X509_CMS_VALUE * value = NULL;

	if((value = cms->cb->create()) == NULL ) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	/*
	if(!PKCS7_set_type(value, type)) {
		PKCS7_free(value);
		PKI_ERROR(PKI_ERR_X509_CMS_TYPE_UNKNOWN, NULL);
		return ( NULL );
	}

	switch(type) {

		// If encrypted, we need to set the cipher
		case PKI_X509_CMS_TYPE_ENCRYPTED:
		case PKI_X509_CMS_TYPE_SIGNEDANDENCRYPTED: {
			if (!PKI_X509_CMS_set_cipher(cms,
				                           (EVP_CIPHER *) PKI_CIPHER_AES(256,cbc))) {
				// Reports the error
				PKI_ERROR(PKI_ERR_X509_CMS_CIPHER, NULL);

				// Free the allocated memory
				PKCS7_free(value);

				// Nothing else to do
				return NULL;
			}
		} break;

		// If signed, just prepare the content
		case PKI_X509_CMS_TYPE_SIGNED: {
			// Sets the content in the PKCS7 structure
			PKCS7_content_new(value, NID_CMS_data);
		} break;

		default: {
			PKI_ERROR(PKI_ERR_X509_CMS_TYPE_UNKNOWN, NULL);
			PKCS7_free(value);

			return NULL;
		} break;
	}
	*/

	// Allocates the new structure with the generated value
	if ((cms = PKI_X509_new_value(PKI_DATATYPE_X509_CMS, value, NULL)) == NULL) {

		// Reports the error
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		CMS_ContentInfo_free(value);

		// Nothing to return
		return NULL;
	}

	return cms;
}

/*!
 * \brief Returns the type of the PKI_X509_CMS data (see PKI_X509_CMS_TYPE)
 */

PKI_X509_CMS_TYPE PKI_X509_CMS_get_type(const PKI_X509_CMS * const cms ) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");
	return 0;

	/*
	PKI_ID type = PKI_ID_UNKNOWN;
	PKI_X509_CMS_VALUE *value = NULL;

	if (!cms || !cms->value) {
		PKI_log_debug ( "PKI_X509_CMS_get_type()::No Message!");
		return PKI_X509_CMS_TYPE_UNKNOWN;
	}

	value = cms->value;

	if (!value->type) {
		PKI_log_debug ( "PKI_X509_CMS_get_type()::No Message Type!");
		return PKI_X509_CMS_TYPE_UNKNOWN;
	}

	// Gets the integer of the OID for the type
	type = PKI_OID_get_id(CMS_get0_type(value));

	// Checks it is a recognized type
	switch ( type ) {

		// Fall-through on purpose
		case PKI_X509_CMS_TYPE_UNKNOWN:
        case PKI_X509_CMS_TYPE_EMPTY:
        case PKI_X509_CMS_TYPE_SIGNED:
        case PKI_X509_CMS_TYPE_ENVELOPED:
        case PKI_X509_CMS_TYPE_SIGNEDANDENCRYPTED:
        case PKI_X509_CMS_TYPE_DATA:
        case PKI_X509_CMS_TYPE_DIGEST:
        case PKI_X509_CMS_TYPE_SMIME_COMPRESSED:
        case PKI_X509_CMS_TYPE_ENCRYPTED: {
        	// Nothing to do, recognized type
        	return type;
        } break;

		default: {
			return PKI_X509_CMS_TYPE_UNKNOWN;
		} break;
	}
}


int PKI_X509_CMS_add_crl(PKI_X509_CMS     * cms,
			               const PKI_X509_CRL * const crl ) {

	// Input Check
	if (!cms || !cms->value || !crl || !crl->value)
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// Adds the CRL to the PKCS7 value structure
	PKCS7_add_crl(cms->value, crl->value);

	// All Done
	return PKI_OK;
}

int PKI_X509_CMS_add_crl_stack(PKI_X509_CMS           * cms, 
				 const PKI_X509_CRL_STACK * const crl_sk ) {
	int i;

	if( !cms || !cms->value || !crl_sk ) {
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
	}

	for( i=0; i < PKI_STACK_X509_CRL_elements( crl_sk ); i++ ) {
		PKI_X509_CRL *crl = NULL;

		if ((crl = PKI_STACK_X509_CRL_get_num(crl_sk, i)) == NULL)
			continue;

		PKCS7_add_crl( cms->value, crl->value);
	}

	return PKI_OK;
	*/
}


/*! \brief Returns the number of CRLs present in the signature */

int PKI_X509_CMS_get_crls_num(const PKI_X509_CMS * const cms ) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return -1;

	/*
	const STACK_OF(X509_CRL) *x_sk = NULL;

	if ((x_sk = __get_crl(cms)) == NULL) return -1;

	return sk_X509_CRL_num((STACK_OF(X509_CRL) *) x_sk);
	*/
}


/*! \brief Returns a copy of the n-th CRL from the signature */

PKI_X509_CRL *PKI_X509_CMS_get_crl(const PKI_X509_CMS * const cms,
				     int idx) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return NULL;

	/*
	PKI_X509_CRL_VALUE *x = NULL;
	const STACK_OF(X509_CRL) *x_sk = NULL;

	if (!cms || !cms->value) return ( NULL );

	if ((x_sk = __get_crl(cms)) == NULL) return NULL;

	if ( idx < 0 ) idx = 0;

	if ((x = sk_X509_CRL_value(x_sk, idx)) == NULL) return NULL;

	return PKI_X509_new_dup_value(PKI_DATATYPE_X509_CRL, x, NULL);
	*/
}

/*! \brief Adds a certificate to the signature's certificate chain */

int PKI_X509_CMS_add_cert(const PKI_X509_CMS * cms, 
			    const PKI_X509_CERT  * const x) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return -1;

	/*
	if (!cms || !cms->value || !x || !x->value) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	PKCS7_add_certificate( cms->value, x->value );

	return( PKI_OK );
	*/
}

/*! \brief Adds a stack of certificates to the signature's certificate chain */

int PKI_X509_CMS_add_cert_stack(const PKI_X509_CMS      * cms, 
				  const PKI_X509_CERT_STACK * const x_sk) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return -1;

	/*
	int i;

	if( !cms || !cms->value || !x_sk ) {
		PKI_log_err( "PKI_X509_CMS_add_crl_stack()::Missing param!");
		return PKI_ERR;
	}

	for( i=0; i < PKI_STACK_X509_CERT_elements( x_sk ); i++ ) {
		PKI_X509_CERT *x = NULL;

		if(( x = PKI_STACK_X509_CERT_get_num( x_sk, i )) == NULL) {
			continue;
		}

		PKCS7_add_certificate( cms->value, x->value );
	}

	return ( PKI_OK );
	*/
}

/*! \brief Returns the number of certificates present in the signature chain */

int PKI_X509_CMS_get_certs_num(const PKI_X509_CMS * const cms ) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return -1;

	/*
	const STACK_OF(X509) *x_sk = NULL;

	if ((x_sk = __get_chain(cms)) == NULL) return -1;

	return sk_X509_num((STACK_OF(X509) *)x_sk);
	*/
}


/*! \brief Returns a copy of the n-th cert from a singed/signed&enc PKCS7 */

PKI_X509_CERT *PKI_X509_CMS_get_cert(const PKI_X509_CMS * const cms,
				       int idx) {

PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return NULL;

	/*
	PKI_X509_CERT_VALUE *x = NULL;
	const STACK_OF(X509) *x_sk = NULL;

	if (!cms || !cms->value) return NULL;

	if ((x_sk = __get_chain(cms)) == NULL) return NULL;

	if ( idx < 0 ) idx = 0;

	if ((x = sk_X509_value(x_sk, idx)) == NULL) return NULL;

	return PKI_X509_new_dup_value ( PKI_DATATYPE_X509_CERT, x, NULL );
	*/
}


/*! \brief Clears the chain of certificate for the signer */

int PKI_X509_CMS_clear_certs(const PKI_X509_CMS * cms) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return -1;

	/*
	STACK_OF(X509) *x_sk = NULL;
		// Pointer to the stack of certificates

	// Gets the pointer to the stack structure
	if ((x_sk = __get_chain(cms)) == NULL)
		return PKI_ERR;

	// Frees the certificates stack
	sk_X509_free(x_sk);

	// All Done
	return PKI_OK;
	*/
}

/*!
 * \brief Returns a signed version of the PKI_X509_CMS by using the passed token
 */

int PKI_X509_CMS_add_signer_tk(PKI_X509_CMS       * cms,
				 const PKI_TOKEN      * const tk, 
				 const PKI_DIGEST_ALG * md){

	if (!cms || !cms->value) return PKI_ERR;

	return PKI_X509_CMS_add_signer(cms,
					 tk->cert,
					 tk->keypair,
					 md);
}

/*!
 * \brief Signs a PKI_X509_CMS (must be of SIGNED type)
 */

int PKI_X509_CMS_add_signer(const PKI_X509_CMS   * cms,
			      const PKI_X509_CERT    * const signer,
			      const PKI_X509_KEYPAIR * const k,
			      const PKI_DIGEST_ALG   * md ) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return -1;

	/*
	PKCS7_SIGNER_INFO *signerInfo = NULL;

	if ( !cms || !signer || !k ) {
		if ( !cms ) PKI_log_debug ( "!cms");
		if ( !signer ) PKI_log_debug ( "!signer");
		if ( !k ) PKI_log_debug ( "!key");
		return PKI_ERR;
	}

	if ( !cms->value || !signer->value || !k->value ) {
		if ( !cms->value ) PKI_log_debug ( "!cms->value");
		if ( !signer->value ) PKI_log_debug ( "!signer->value");
		if ( !k->value ) PKI_log_debug ( "!key->value");
		return PKI_ERR;
	}

	if( !md ) md = PKI_DIGEST_ALG_DEFAULT;

	if((signerInfo = PKCS7_add_signature( cms->value, 
					signer->value, k->value, md)) == NULL) {
		return ( PKI_ERR );
	}
	PKCS7_add_certificate ( cms->value, signer->value );

	return ( PKI_OK );
	*/
}

/*! \brief Returns PKI_OK if the cms has signers already set, PKI_ERR
 *         otherwise
 */

int PKI_X509_CMS_has_signers(const PKI_X509_CMS * const cms ) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return -1;

	/*
	int type = 0;

	if ( !cms || !cms->value ) return ( PKI_ERR );

	type = PKI_X509_CMS_get_type ( cms );

	switch ( type ) {
		case PKI_X509_CMS_TYPE_SIGNED:
		case PKI_X509_CMS_TYPE_SIGNEDANDENCRYPTED:
			if(PKI_X509_CMS_get_signer_info(cms, -1)) 
				return (PKI_OK);
			break;
		default:
			return PKI_ERR;
	}

	return PKI_ERR;
	*/
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

int PKI_X509_CMS_set_cipher(const PKI_X509_CMS * cms,
			      const PKI_CIPHER     * const cipher) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return -1;

	/*
	int type;

	if( !cms || !cms->value || !cipher ) return ( PKI_ERR );

	type = PKI_X509_CMS_get_type ( cms );
	switch ( type ) {
		case PKI_X509_CMS_TYPE_ENCRYPTED:
		case PKI_X509_CMS_TYPE_SIGNEDANDENCRYPTED:
			break;
		default:
			return PKI_ERR;
	}

        if(!PKCS7_set_cipher(cms->value, cipher)) {
		PKI_log_debug("PKI_X509_CMS_set_cipher()::Error setting Cipher "
			"[%s]", ERR_error_string(ERR_get_error(), NULL));
		return ( PKI_ERR );
	}

	return PKI_OK;
	*/

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

/*! \brief Adds a new recipient for the PKI_X509_CMS */
int PKI_X509_CMS_add_recipient(const PKI_X509_CMS * cms,
				 const PKI_X509_CERT  * x ) {

	PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED,
		"PKI_X509_CMS_get_recipient_cert() Not Implemented, yet.");

	return -1;

	/*
	if (!cms || !cms->value || !x || !x->value) return PKI_ERR;

	PKCS7_add_recipient( cms->value, x->value );
	PKI_X509_CMS_add_cert(cms, x);

	return PKI_OK;
	*/
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
