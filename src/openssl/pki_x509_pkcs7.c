/* openssl/pki_x509_pkcs7.c */

#include <libpki/pki.h>

#include "internal/x509_data_st.h"

/* ------------------------------ internal (static ) ------------------------- */

static STACK_OF(X509) * __get_chain (const PKI_X509_PKCS7 * const p7) {

	STACK_OF(X509) *x_sk = NULL;
	int type = 0;

	PKI_X509_PKCS7_VALUE *value = NULL;

	if( !p7 || !p7->value ) return ( PKI_ERR );

	type = PKI_X509_PKCS7_get_type ( p7 );

	value = p7->value;

	switch ( type ) {
		case PKI_X509_PKCS7_TYPE_SIGNED:
			x_sk = value->d.sign->cert;
			break;
		case PKI_X509_PKCS7_TYPE_SIGNEDANDENCRYPTED:
			x_sk = value->d.signed_and_enveloped->cert;
			break;
		default:
			return NULL;
	}

	return x_sk;
}

static const STACK_OF(X509_CRL) *__get_crl (const PKI_X509_PKCS7 * const p7 ) {

	STACK_OF(X509_CRL) *x_sk = NULL;
	int type = 0;

	PKI_X509_PKCS7_VALUE *value = NULL;

	if( !p7 || !p7->value ) return ( PKI_ERR );

	type = PKI_X509_PKCS7_get_type ( p7 );

	value = p7->value;

	switch ( type ) {
		case PKI_X509_PKCS7_TYPE_SIGNED:
			x_sk = value->d.sign->crl;
			break;
		case PKI_X509_PKCS7_TYPE_SIGNEDANDENCRYPTED:
			x_sk = value->d.signed_and_enveloped->crl;
			break;
		default:
			return NULL;
	}

	return x_sk;
}



/*! \brief Returns the number of recipients */

int PKI_X509_PKCS7_get_recipients_num(const PKI_X509_PKCS7 * const p7 ) {

	STACK_OF(PKCS7_RECIP_INFO) *r_sk = NULL;
	PKI_X509_PKCS7_VALUE *p7val = NULL;

	int type = 0;
	int ret = 0;

	if ( !p7 || !p7->value ) return -1;

	if ( PKI_X509_PKCS7_has_recipients ( p7 ) == PKI_ERR ) {
		return 0;
	}

	p7val = p7->value;

        type = PKI_X509_PKCS7_get_type ( p7 );
        switch ( type ) {
                case PKI_X509_PKCS7_TYPE_ENCRYPTED:
                        r_sk = p7val->d.enveloped->recipientinfo;
                        break;
                case PKI_X509_PKCS7_TYPE_SIGNEDANDENCRYPTED:
                        r_sk = p7val->d.signed_and_enveloped->recipientinfo;
                        break;
                default:
                        r_sk = NULL;
        }

	if ( r_sk ) {
		ret = sk_PKCS7_RECIP_INFO_num ( r_sk );
	}

	return ret;
}

/*! \brief Returns the number of signers */

int PKI_X509_PKCS7_get_signers_num(const PKI_X509_PKCS7 * const p7) {

	int ret = -1;
	int type = -1;

	PKI_X509_PKCS7_VALUE *p7val = NULL;
	STACK_OF(PKCS7_SIGNER_INFO) *s_sk = NULL;

	if ( PKI_X509_PKCS7_has_signers ( p7 ) == PKI_ERR ) {
		return 0;
	}

	p7val = p7->value;

	type = PKI_X509_PKCS7_get_type ( p7 );

	switch ( type ) {
		case PKI_X509_PKCS7_TYPE_SIGNED:
			s_sk = p7val->d.sign->signer_info;
			break;
		case PKI_X509_PKCS7_TYPE_SIGNEDANDENCRYPTED:
			s_sk = p7val->d.signed_and_enveloped->signer_info;
			break;
		default:
			s_sk = NULL;
	}

	if ( s_sk ) {
		ret = sk_PKCS7_SIGNER_INFO_num ( s_sk );
	}

	return ret;
}

const PKCS7_RECIP_INFO * PKI_X509_PKCS7_get_recipient_info(
					const PKI_X509_PKCS7 * const p7,
					int                    idx ) {

	int type = 0;
	int recipients_num = 0;
	PKCS7_RECIP_INFO *ret = NULL;
	STACK_OF(PKCS7_RECIP_INFO) *r_sk = NULL;
	PKI_X509_PKCS7_VALUE *p7val = NULL;

	if ( !p7 || !p7->value ) return NULL;

	p7val = p7->value;

	if((recipients_num = PKI_X509_PKCS7_get_recipients_num ( p7 )) <= 0 ) {
		return NULL;
	}

	if ( recipients_num < idx ) return NULL;

	type = PKI_X509_PKCS7_get_type ( p7 );
	switch ( type ) {
		case PKI_X509_PKCS7_TYPE_ENCRYPTED:
			r_sk = p7val->d.enveloped->recipientinfo;
			break;
		case PKI_X509_PKCS7_TYPE_SIGNEDANDENCRYPTED:
			r_sk = p7val->d.signed_and_enveloped->recipientinfo;
			break;
		default:
			r_sk = NULL;
	}

	if ( r_sk ) {
		ret = sk_PKCS7_RECIP_INFO_value ( r_sk, idx );
	}

	return ret;
	
}

/*! \brief Returns a copy of the n-th recipient certificate */

const PKI_X509_CERT * PKI_X509_PKCS7_get_recipient_cert(
			    const PKI_X509_PKCS7 * const p7,
				int                    idx ) {

	const PKCS7_RECIP_INFO *r_info = NULL;

	if ((r_info = PKI_X509_PKCS7_get_recipient_info ( p7, idx )) == NULL)
		return NULL;

	return (const PKI_X509_CERT *)r_info->cert;
}

/*! \brief Returns the encryption algorithm */

const PKI_ALGOR * PKI_X509_PKCS7_get_encode_alg(
				const PKI_X509_PKCS7 * const p7) {

	PKI_ALGOR *ret = NULL;
	PKI_X509_PKCS7_VALUE *val = NULL;

	if( !p7 || !p7->value ) return NULL;

	val = p7->value;

	switch ( PKI_X509_PKCS7_get_type ( p7 ) ) {
		case PKI_X509_PKCS7_TYPE_ENCRYPTED:
			ret = val->d.enveloped->enc_data->algorithm;
			break;
		case PKI_X509_PKCS7_TYPE_SIGNEDANDENCRYPTED:
			ret = val->d.signed_and_enveloped->enc_data->algorithm;
			break;
		default:
			ret = NULL;
	}

	return ret;
}

const PKCS7_SIGNER_INFO * PKI_X509_PKCS7_get_signer_info(
					const PKI_X509_PKCS7 * const p7, 
					int                    idx ) {

	int type = 0;
	int cnt = 0;
	const STACK_OF(PKCS7_SIGNER_INFO) *sk = NULL;
	const PKCS7_SIGNER_INFO *ret = NULL;

	PKI_X509_PKCS7_VALUE *value = NULL;

	if ( !p7 || !p7->value ) return ( NULL );

	type = PKI_X509_PKCS7_get_type ( p7 );

	value = p7->value;

	switch (type) {

		case PKI_X509_PKCS7_TYPE_SIGNED: {
			if (value && value->d.sign) {
				sk = value->d.sign->signer_info;
			}
		} break;

		case PKI_X509_PKCS7_TYPE_SIGNEDANDENCRYPTED: {
			if (value && value->d.signed_and_enveloped) {
				sk = value->d.signed_and_enveloped->signer_info;
			}
		} break;

		default: {
			PKI_ERROR(PKI_ERR_X509_PKCS7_TYPE_UNKNOWN, NULL);
			return NULL;
		}
	}

	// Retrieves the Signer Info structure
	if((cnt = sk_PKCS7_SIGNER_INFO_num ( sk )) <= 0 ) {
		PKI_ERROR(PKI_ERR_X509_PKCS7_SIGNER_INFO_NULL, NULL);
		return ( NULL );
	}

	// If the requested is out of scope, nothing to return
	if (idx > cnt ) return NULL;

	// Retrieves the value
	if( idx >= 0 ) {
		ret = sk_PKCS7_SIGNER_INFO_value( sk, idx );
	} else {
		ret = sk_PKCS7_SIGNER_INFO_value( sk, cnt-1 );
	}
	
	// All Done
	return ret;
}

/* ----------------------- Exported Functions -------------------------*/

void PKI_X509_PKCS7_free_void ( void *p7 ) {

	PKI_X509_free ( (PKI_X509_PKCS7 *) p7 );
	return;
}

void PKI_X509_PKCS7_free ( PKI_X509_PKCS7 *p7 ) {

	if( p7 == NULL ) return;

	PKI_X509_free( p7 );

	return;
}

PKI_X509_PKCS7 *PKI_X509_PKCS7_new(PKI_X509_PKCS7_TYPE type) {

	PKI_X509_PKCS7       * p7    = NULL;
	PKI_X509_PKCS7_VALUE * value = NULL;

	if((value = p7->cb->create()) == NULL ) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	if(!PKCS7_set_type(value, type)) {
		PKCS7_free(value);
		PKI_ERROR(PKI_ERR_X509_PKCS7_TYPE_UNKNOWN, NULL);
		return ( NULL );
	}

	switch(type) {

		// If encrypted, we need to set the cipher
		case PKI_X509_PKCS7_TYPE_ENCRYPTED:
		case PKI_X509_PKCS7_TYPE_SIGNEDANDENCRYPTED: {
			if (!PKI_X509_PKCS7_set_cipher(p7,
				                           (EVP_CIPHER *) PKI_CIPHER_AES(256,cbc))) {
				// Reports the error
				PKI_ERROR(PKI_ERR_X509_PKCS7_CIPHER, NULL);

				// Free the allocated memory
				PKCS7_free(value);

				// Nothing else to do
				return NULL;
			}
		} break;

		// If signed, just prepare the content
		case PKI_X509_PKCS7_TYPE_SIGNED: {
			// Sets the content in the PKCS7 structure
			PKCS7_content_new(value, NID_pkcs7_data);
		} break;

		default: {
			PKI_ERROR(PKI_ERR_X509_PKCS7_TYPE_UNKNOWN, NULL);
			PKCS7_free(value);

			return NULL;
		} break;
	}

	// Allocates the new structure with the generated value
	if ((p7 = PKI_X509_new_value(PKI_DATATYPE_X509_PKCS7, value, NULL)) == NULL) {

		// Reports the error
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		PKCS7_free(value);

		// Nothing to return
		return NULL;
	}

	return p7;
}

/*!
 * \brief Returns the type of the PKI_X509_PKCS7 data (see PKI_X509_PKCS7_TYPE)
 */

PKI_X509_PKCS7_TYPE PKI_X509_PKCS7_get_type(const PKI_X509_PKCS7 * const p7 ) {

	PKI_ID type = PKI_ID_UNKNOWN;
	PKI_X509_PKCS7_VALUE *value = NULL;

	if(!p7 || !p7->value ) {
		PKI_log_debug ( "PKI_X509_PKCS7_get_type()::No Message!");
		return PKI_X509_PKCS7_TYPE_UNKNOWN;
	}

	value = p7->value;

	if(!value->type ) {
		PKI_log_debug ( "PKI_X509_PKCS7_get_type()::No Message Type!");
		return PKI_X509_PKCS7_TYPE_UNKNOWN;
	}

	type = PKI_OID_get_id( value->type );

	switch ( type ) {
		case NID_pkcs7_enveloped:
			return PKI_X509_PKCS7_TYPE_ENCRYPTED;
			break;
		case NID_pkcs7_signed:
			return PKI_X509_PKCS7_TYPE_SIGNED;
			break;
		case NID_pkcs7_signedAndEnveloped:
			return PKI_X509_PKCS7_TYPE_SIGNEDANDENCRYPTED;
			break;
		case NID_pkcs7_data:
			return PKI_X509_PKCS7_TYPE_DATA;
			break;
		default:
			return PKI_X509_PKCS7_TYPE_UNKNOWN;
	}
}


int PKI_X509_PKCS7_add_crl(PKI_X509_PKCS7     * p7,
			               const PKI_X509_CRL * const crl ) {

	// Input Check
	if (!p7 || !p7->value || !crl || !crl->value)
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	// Adds the CRL to the PKCS7 value structure
	PKCS7_add_crl(p7->value, crl->value);

	// All Done
	return PKI_OK;
}

int PKI_X509_PKCS7_add_crl_stack(PKI_X509_PKCS7           * p7, 
				 const PKI_X509_CRL_STACK * const crl_sk ) {
	int i;

	if( !p7 || !p7->value || !crl_sk ) {
		return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
	}

	for( i=0; i < PKI_STACK_X509_CRL_elements( crl_sk ); i++ ) {
		PKI_X509_CRL *crl = NULL;

		if ((crl = PKI_STACK_X509_CRL_get_num(crl_sk, i)) == NULL)
			continue;

		PKCS7_add_crl( p7->value, crl->value);
	}

	return PKI_OK;
}


/*! \brief Returns the number of CRLs present in the signature */

int PKI_X509_PKCS7_get_crls_num(const PKI_X509_PKCS7 * const p7 ) {

	const STACK_OF(X509_CRL) *x_sk = NULL;

	if ((x_sk = __get_crl(p7)) == NULL) return -1;

	return sk_X509_CRL_num((STACK_OF(X509_CRL) *) x_sk);
}


/*! \brief Returns a copy of the n-th CRL from the signature */

PKI_X509_CRL *PKI_X509_PKCS7_get_crl(const PKI_X509_PKCS7 * const p7,
				     int idx) {

	PKI_X509_CRL_VALUE *x = NULL;
	const STACK_OF(X509_CRL) *x_sk = NULL;

	if (!p7 || !p7->value) return ( NULL );

	if ((x_sk = __get_crl(p7)) == NULL) return NULL;

	if ( idx < 0 ) idx = 0;

	if ((x = sk_X509_CRL_value(x_sk, idx)) == NULL) return NULL;

	return PKI_X509_new_dup_value(PKI_DATATYPE_X509_CRL, x, NULL);

}

/*! \brief Adds a certificate to the signature's certificate chain */

int PKI_X509_PKCS7_add_cert(const PKI_X509_PKCS7 * p7, 
			    const PKI_X509_CERT  * const x) {

	if (!p7 || !p7->value || !x || !x->value) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
	}

	PKCS7_add_certificate( p7->value, x->value );

	return( PKI_OK );
}

/*! \brief Adds a stack of certificates to the signature's certificate chain */

int PKI_X509_PKCS7_add_cert_stack(const PKI_X509_PKCS7      * p7, 
				  const PKI_X509_CERT_STACK * const x_sk) {
	int i;

	if( !p7 || !p7->value || !x_sk ) {
		PKI_log_err( "PKI_X509_PKCS7_add_crl_stack()::Missing param!");
		return PKI_ERR;
	}

	for( i=0; i < PKI_STACK_X509_CERT_elements( x_sk ); i++ ) {
		PKI_X509_CERT *x = NULL;

		if(( x = PKI_STACK_X509_CERT_get_num( x_sk, i )) == NULL) {
			continue;
		}

		PKCS7_add_certificate( p7->value, x->value );
	}

	return ( PKI_OK );
}

/*! \brief Returns the number of certificates present in the signature chain */

int PKI_X509_PKCS7_get_certs_num(const PKI_X509_PKCS7 * const p7 ) {

	const STACK_OF(X509) *x_sk = NULL;

	if ((x_sk = __get_chain(p7)) == NULL) return -1;

	return sk_X509_num((STACK_OF(X509) *)x_sk);
}


/*! \brief Returns a copy of the n-th cert from a singed/signed&enc PKCS7 */

PKI_X509_CERT *PKI_X509_PKCS7_get_cert(const PKI_X509_PKCS7 * const p7,
				       int idx) {

	PKI_X509_CERT_VALUE *x = NULL;
	const STACK_OF(X509) *x_sk = NULL;

	if (!p7 || !p7->value) return NULL;

	if ((x_sk = __get_chain(p7)) == NULL) return NULL;

	if ( idx < 0 ) idx = 0;

	if ((x = sk_X509_value(x_sk, idx)) == NULL) return NULL;

	return PKI_X509_new_dup_value ( PKI_DATATYPE_X509_CERT, x, NULL );

}


/*! \brief Clears the chain of certificate for the signer */

int PKI_X509_PKCS7_clear_certs(const PKI_X509_PKCS7 * p7) {

	STACK_OF(X509) *x_sk = NULL;
		// Pointer to the stack of certificates

	// Gets the pointer to the stack structure
	if ((x_sk = __get_chain(p7)) == NULL)
		return PKI_ERR;

	// Frees the certificates stack
	sk_X509_free(x_sk);

	// All Done
	return PKI_OK;
}

/*!
 * \brief Returns a signed version of the PKI_X509_PKCS7 by using the passed token
 */

int PKI_X509_PKCS7_add_signer_tk(PKI_X509_PKCS7       * p7,
				 const PKI_TOKEN      * const tk, 
				 const PKI_DIGEST_ALG * md){

	if (!p7 || !p7->value) return PKI_ERR;

	return PKI_X509_PKCS7_add_signer(p7,
					 tk->cert,
					 tk->keypair,
					 md);
}

/*!
 * \brief Signs a PKI_X509_PKCS7 (must be of SIGNED type)
 */

int PKI_X509_PKCS7_add_signer(const PKI_X509_PKCS7   * p7,
			      const PKI_X509_CERT    * const signer,
			      const PKI_X509_KEYPAIR * const k,
			      const PKI_DIGEST_ALG   * md ) {

	PKCS7_SIGNER_INFO *signerInfo = NULL;

	if ( !p7 || !signer || !k ) {
		if ( !p7 ) PKI_log_debug ( "!p7");
		if ( !signer ) PKI_log_debug ( "!signer");
		if ( !k ) PKI_log_debug ( "!key");
		return PKI_ERR;
	}

	if ( !p7->value || !signer->value || !k->value ) {
		if ( !p7->value ) PKI_log_debug ( "!p7->value");
		if ( !signer->value ) PKI_log_debug ( "!signer->value");
		if ( !k->value ) PKI_log_debug ( "!key->value");
		return PKI_ERR;
	}

	if( !md ) md = PKI_DIGEST_ALG_DEFAULT;

	if((signerInfo = PKCS7_add_signature( p7->value, 
					signer->value, k->value, md)) == NULL) {
		return ( PKI_ERR );
	}
	PKCS7_add_certificate ( p7->value, signer->value );

	return ( PKI_OK );

}

/*! \brief Returns PKI_OK if the p7 has signers already set, PKI_ERR
 *         otherwise
 */

int PKI_X509_PKCS7_has_signers(const PKI_X509_PKCS7 * const p7 ) {

	int type = 0;

	if ( !p7 || !p7->value ) return ( PKI_ERR );

	type = PKI_X509_PKCS7_get_type ( p7 );

	switch ( type ) {
		case PKI_X509_PKCS7_TYPE_SIGNED:
		case PKI_X509_PKCS7_TYPE_SIGNEDANDENCRYPTED:
			if(PKI_X509_PKCS7_get_signer_info(p7, -1)) 
				return (PKI_OK);
			break;
		default:
			return PKI_ERR;
	}

	return PKI_ERR;

}

/*! \brief Returns PKI_OK if the p7 has recipients already set, PKI_ERR
 *         otherwise
 */

int PKI_X509_PKCS7_has_recipients(const PKI_X509_PKCS7 * const p7) {

	int type = 0;
	PKI_X509_PKCS7_VALUE *value = NULL;

	if( !p7 || !p7->value ) return ( PKI_ERR );

	type = PKI_X509_PKCS7_get_type ( p7 );

	value = p7->value;

	switch ( type ) {
		case PKI_X509_PKCS7_TYPE_ENCRYPTED:
			if( value->d.enveloped &&
					value->d.enveloped->recipientinfo) 
				return PKI_OK;
			break;
		case PKI_X509_PKCS7_TYPE_SIGNEDANDENCRYPTED:
			if( value->d.signed_and_enveloped &&
			      value->d.signed_and_enveloped->recipientinfo) 
					return PKI_OK;
			break;
		default:
			return PKI_ERR;
	}

	return PKI_ERR;
}

/*!
 * \brief Encode a PKI_X509_PKCS7 by performing sign/encrypt operation
 */

int PKI_X509_PKCS7_encode(const PKI_X509_PKCS7 * const p7,
			  unsigned char *data, 
			  size_t size ) {

	int type = NID_pkcs7_signed;
	const PKCS7_SIGNER_INFO * signerInfo = NULL;
	BIO *bio = NULL;

	if( !p7 || !p7->value ) return ( PKI_ERR );

	type = PKI_X509_PKCS7_get_type ( p7 );

	if (( type == PKI_X509_PKCS7_TYPE_ENCRYPTED ) 
			|| (type == PKI_X509_PKCS7_TYPE_SIGNEDANDENCRYPTED)) {

		if ( PKI_X509_PKCS7_has_recipients ( p7 ) == PKI_ERR ) {
			PKI_log_debug ( "PKI_X509_PKCS7_encode()::Missing "
								"Recipients!");
			return PKI_ERR;
		}
	}

	if ( (type == PKI_X509_PKCS7_TYPE_SIGNED) ||
			(type == PKI_X509_PKCS7_TYPE_SIGNEDANDENCRYPTED )) {

		if(( signerInfo = PKI_X509_PKCS7_get_signer_info( p7,
							-1 )) == NULL ) {
			return ( PKI_ERR );
		}

		PKCS7_add_signed_attribute((PKCS7_SIGNER_INFO *)signerInfo,
					    NID_pkcs9_contentType,
					    V_ASN1_OBJECT,
					    OBJ_nid2obj(NID_pkcs7_data));
	}

	if((bio = PKCS7_dataInit(p7->value, NULL)) == NULL ) {
		PKI_log_err("PKI_X509_PKCS7_sign()::Error dataInit [%s]",
			ERR_error_string(ERR_get_error(),NULL));
		return ( PKI_ERR );
	}
	
	if( BIO_write( bio, data, (int) size ) <= 0 ) {
		PKI_log_err("PKI_X509_PKCS7_sign()::Error dataSign [%s]",
			ERR_error_string(ERR_get_error(),NULL));
		return ( PKI_ERR );
	}

	(void)BIO_flush(bio);

	if(!PKCS7_dataFinal( p7->value, bio )) {
		PKI_log_err("PKI_X509_PKCS7_sign()::Error End dataSign [%s]",
			ERR_error_string(ERR_get_error(),NULL));
		return ( PKI_ERR );
	};

	if( bio ) BIO_free_all ( bio );

	return ( PKI_OK );

}

/*!
 * \brief Returns the raw data contained in a PKI_X509_PKCS7 (any type)
 */

PKI_MEM *PKI_X509_PKCS7_get_raw_data(const PKI_X509_PKCS7 * const p7 ) {

	unsigned char *data = NULL;
	ssize_t len = -1;
	int type = -1;

	PKI_X509_PKCS7_VALUE *p7val = NULL;
	PKI_MEM *ret = NULL;

	if( !p7 || !p7->value ) return ( NULL );

	p7val = p7->value;
	type = PKI_X509_PKCS7_get_type ( p7 );

	switch (type)
	{
		case PKI_X509_PKCS7_TYPE_DATA:
			data = p7val->d.data->data;
			len  = p7val->d.data->length;
			break;

		case PKI_X509_PKCS7_TYPE_SIGNED:
			if (p7val->d.sign && p7val->d.sign->contents &&
				p7val->d.sign->contents->d.data)
			{
				data = p7val->d.sign->contents->d.data->data;
				len  = p7val->d.sign->contents->d.data->length;
			}
			break;

		case PKI_X509_PKCS7_TYPE_ENCRYPTED:
			if (p7val->d.enveloped && p7val->d.enveloped->enc_data &&
				p7val->d.enveloped->enc_data->enc_data)
			{
				data = p7val->d.enveloped->enc_data->enc_data->data;
				len  = p7val->d.enveloped->enc_data->enc_data->length;
			}
			break;

		case PKI_X509_PKCS7_TYPE_SIGNEDANDENCRYPTED:
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

	/*
        if((p7bio = PKCS7_dataInit(p7->value ,NULL)) != NULL ) {
		(void)BIO_flush(p7bio);
                ret = PKI_MEM_new_bio( p7bio, NULL );
		BIO_free_all ( p7bio );
        } else {
		PKI_log_debug("PKCS7::get_raw_data()::Can not get data [%s]",
			ERR_error_string(ERR_get_error(), NULL ));
	}
	*/

	return ( ret );
	
}

/*!
 * \brief Decrypts (if needed) and returns the idata from a PKI_X509_PKCS7 by using
 *        keypair and, if present, cert of the PKI_TOKEN argument.
 */

PKI_MEM *PKI_X509_PKCS7_get_data_tk(const PKI_X509_PKCS7 * const p7,
				    const PKI_TOKEN * const tk ) {

	if (!p7 || !tk ) return NULL;

	return PKI_X509_PKCS7_get_data(p7, tk->keypair, tk->cert);
}

/*!
 * \brief Decrypts (if needed) and returns the data from a PKI_X509_PKCS7
 */

PKI_MEM *PKI_X509_PKCS7_get_data(const PKI_X509_PKCS7 * const p7,
				 const PKI_X509_KEYPAIR * const k,
				 const PKI_X509_CERT * const x ) {

	PKI_ID type;

	if( !p7 || !p7->value ) return ( NULL );

	type = PKI_X509_PKCS7_get_type ( p7 );

	switch ( type ) {
		case PKI_X509_PKCS7_TYPE_ENCRYPTED:
		case PKI_X509_PKCS7_TYPE_SIGNEDANDENCRYPTED:
			PKI_log_debug("PKI_X509_PKCS7_get_data()::P7 is encrypted!");
			return PKI_X509_PKCS7_decode ( p7, k, x );
			break;
		default:
			PKI_log_debug("PKI_X509_PKCS7_get_data()::P7 not encrypted");
			return PKI_X509_PKCS7_get_raw_data ( p7 );
	}
}

/*!
 * \brief Decrypts the data from a (must) encrypted PKI_X509_PKCS7
 */


PKI_MEM *PKI_X509_PKCS7_decode(const PKI_X509_PKCS7 * const p7,
			       const PKI_X509_KEYPAIR * const k, 
			       const PKI_X509_CERT * const x ) {

	BIO *bio = NULL;
	PKI_MEM *mem = NULL;
	PKI_ID type = 0;
	PKI_X509_CERT_VALUE *x_val = NULL;
	PKI_X509_KEYPAIR_VALUE *pkey = NULL;

	if ( !p7 || !p7->value || !k || !k->value ) {
		PKI_log_debug("PKI_X509_PKCS7_decode()::Missing p7 or pkey!");
		return ( NULL );
	};
 
	pkey = k->value;

	type = PKI_X509_PKCS7_get_type ( p7 );

	switch ( type ) {
		case PKI_X509_PKCS7_TYPE_ENCRYPTED:
		case PKI_X509_PKCS7_TYPE_SIGNEDANDENCRYPTED:
			break;
		default:
			PKI_log_debug("PKI_X509_PKCS7_decode()::Wrong MSG type!");
                	return PKI_ERR;
        }

	if ( x ) x_val = x->value;

	if((bio = PKCS7_dataDecode(p7->value, pkey, NULL, x_val)) == NULL) {
		PKI_log_debug ( "PKI_X509_PKCS7_decode()::Decrypt error [%s]",
			ERR_error_string(ERR_get_error(), NULL ));
		return ( NULL );
	}

	if((mem = PKI_MEM_new_bio( (PKI_IO *) bio, NULL )) == NULL ) {
		PKI_log_debug("PKI_X509_PKCS7_decode()::Memory Error!");
		if( bio ) BIO_free_all ( bio );
		return ( NULL );
	}

	if (bio ) BIO_free_all ( bio );

	return ( mem );
}

/*! \brief Set the cipher in a encrypted (or signed and encrypted) PKCS7 */

int PKI_X509_PKCS7_set_cipher(const PKI_X509_PKCS7 * p7,
			      const PKI_CIPHER     * const cipher) {

	int type;

	if( !p7 || !p7->value || !cipher ) return ( PKI_ERR );

	type = PKI_X509_PKCS7_get_type ( p7 );
	switch ( type ) {
		case PKI_X509_PKCS7_TYPE_ENCRYPTED:
		case PKI_X509_PKCS7_TYPE_SIGNEDANDENCRYPTED:
			break;
		default:
			return PKI_ERR;
	}

        if(!PKCS7_set_cipher(p7->value, cipher)) {
		PKI_log_debug("PKI_X509_PKCS7_set_cipher()::Error setting Cipher "
			"[%s]", ERR_error_string(ERR_get_error(), NULL));
		return ( PKI_ERR );
	}

	return PKI_OK;
}
	

/*! \brief Sets the recipients for a PKI_X509_PKCS7 */

int PKI_X509_PKCS7_set_recipients(const PKI_X509_PKCS7 *p7, 
				  const PKI_X509_CERT_STACK * const x_sk ) {

	int i = 0;
	int type;

	if( !p7 || !p7->value || !x_sk ) return ( PKI_ERR );

	type = PKI_X509_PKCS7_get_type ( p7 );
	switch ( type ) {
		case PKI_X509_PKCS7_TYPE_ENCRYPTED:
		case PKI_X509_PKCS7_TYPE_SIGNEDANDENCRYPTED:
			break;
		default:
			return PKI_ERR;
	}

	for( i = 0; i < PKI_STACK_X509_CERT_elements ( x_sk ); i++ ) {
		PKI_X509_CERT *x = NULL;
		x = PKI_STACK_X509_CERT_get_num( x_sk, i );
		PKCS7_add_recipient( p7->value, x->value );
		PKI_X509_PKCS7_add_cert ( p7, x );
	}

	return ( PKI_OK );
}

/*! \brief Adds a new recipient for the PKI_X509_PKCS7 */
int PKI_X509_PKCS7_add_recipient(const PKI_X509_PKCS7 * p7,
				 const PKI_X509_CERT  * x ) {

	if (!p7 || !p7->value || !x || !x->value) return PKI_ERR;

	PKCS7_add_recipient( p7->value, x->value );
	PKI_X509_PKCS7_add_cert(p7, x);

	return PKI_OK;
}

/* -------------------------------- Add Attributes ---------------------- */

int PKI_X509_PKCS7_add_signed_attribute(const PKI_X509_PKCS7 * p7, 
					PKI_X509_ATTRIBUTE   * a) {

	PKCS7_SIGNER_INFO *signerInfo = NULL;

	if (!p7 || !p7->value || !a) return PKI_ERR;

	if ((signerInfo = (PKCS7_SIGNER_INFO *)
			PKI_X509_PKCS7_get_signer_info (p7, -1)) == NULL ) {
		PKI_ERROR(PKI_ERR_GENERAL, "signerInfo not present in PKCS7");
		return PKI_ERR;
	}

	if (signerInfo->auth_attr == NULL) {
		signerInfo->auth_attr = PKI_STACK_X509_ATTRIBUTE_new_null();
	}

	return PKI_STACK_X509_ATTRIBUTE_add(signerInfo->auth_attr, a);

}

int PKI_X509_PKCS7_add_attribute(const PKI_X509_PKCS7 * p7,
				 PKI_X509_ATTRIBUTE   * a) {

	PKCS7_SIGNER_INFO *signerInfo = NULL;

	if( !p7 || !p7->value || !a ) return ( PKI_ERR );

	if ((signerInfo = (PKCS7_SIGNER_INFO *) 
			PKI_X509_PKCS7_get_signer_info ( p7, -1 )) == NULL ) {
		PKI_DEBUG("signerInfo not present in PKCS#7");
		return PKI_ERR;
	}

	if (signerInfo->unauth_attr == NULL) {
		signerInfo->unauth_attr = PKI_STACK_X509_ATTRIBUTE_new_null();
	}

	return PKI_STACK_X509_ATTRIBUTE_add( signerInfo->unauth_attr, a);

}

/* -------------------------------- Get Attributes ---------------------- */

const PKI_X509_ATTRIBUTE *PKI_X509_PKCS7_get_signed_attribute(
					              const PKI_X509_PKCS7 * const p7,
					              PKI_ID                 id) {

	const PKCS7_SIGNER_INFO *signerInfo = NULL;

    if (!p7 || !p7->value) {
    	PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
    	return NULL;
    }

    if ((signerInfo = PKI_X509_PKCS7_get_signer_info(p7, -1)) == NULL)
    	return NULL;

    if (signerInfo->auth_attr == NULL) return NULL;

	return PKI_STACK_X509_ATTRIBUTE_get(signerInfo->auth_attr, id);
}

const PKI_X509_ATTRIBUTE *PKI_X509_PKCS7_get_attribute(
					const PKI_X509_PKCS7 * const p7, 
					PKI_ID id ) {

	const PKCS7_SIGNER_INFO *signerInfo = NULL;

        if (!p7 || !p7->value) return NULL;

        if ((signerInfo = PKI_X509_PKCS7_get_signer_info(p7, -1)) == NULL) {
		PKI_DEBUG("signerInfo missing in PKCS7");
                return NULL;
        }

        if (signerInfo->unauth_attr == NULL) return NULL;

	return PKI_STACK_X509_ATTRIBUTE_get(signerInfo->auth_attr, id);
}

const PKI_X509_ATTRIBUTE *PKI_X509_PKCS7_get_signed_attribute_by_name( 
					const PKI_X509_PKCS7 * const p7,
					const char *name ) {

	const PKCS7_SIGNER_INFO *signerInfo = NULL;

        if (!p7 || !p7->value) return NULL;

        if ((signerInfo = PKI_X509_PKCS7_get_signer_info(p7, -1)) == NULL) {
                PKI_DEBUG("signerInfo not present in PKCS7");
                return NULL;
        }

        if (signerInfo->auth_attr == NULL) return NULL;

	return PKI_STACK_X509_ATTRIBUTE_get_by_name(signerInfo->auth_attr, 
						    name);
}

const PKI_X509_ATTRIBUTE *PKI_X509_PKCS7_get_attribute_by_name(
					const PKI_X509_PKCS7 * const p7, 
					const char *name) {

	const PKCS7_SIGNER_INFO *signerInfo = NULL;

        if (!p7 || !p7->value) return NULL;

        if ((signerInfo = PKI_X509_PKCS7_get_signer_info(p7, -1)) == NULL) {
                PKI_DEBUG("signerInfo not present in PKCS7");
                return NULL;
        }

        if (signerInfo->unauth_attr == NULL) return ( NULL );

	return PKI_STACK_X509_ATTRIBUTE_get_by_name(signerInfo->auth_attr, 
						    name);
}

/* ------------------------------- Delete Attributes ---------------------- */

/*! \brief Deletes a signed attribute (id) from a PKI_X509_PKCS7 */

int PKI_X509_PKCS7_delete_signed_attribute(const PKI_X509_PKCS7 *p7, 
					   PKI_ID id) {

	const PKCS7_SIGNER_INFO *signerInfo = NULL;

	if (!p7 || !p7->value) return PKI_ERR;

	if ((signerInfo = PKI_X509_PKCS7_get_signer_info(p7, -1)) == NULL) {
		PKI_DEBUG("signerInfo not present in PKCS7");
		return PKI_ERR;
	}

	if (signerInfo->auth_attr == NULL) return PKI_OK;

	return PKI_STACK_X509_ATTRIBUTE_delete(signerInfo->auth_attr, id);

}

/*! \brief Deletes an attribute (id) from a PKI_X509_PKCS7 */

int PKI_X509_PKCS7_delete_attribute(const PKI_X509_PKCS7 *p7, PKI_ID id ) {

	const PKCS7_SIGNER_INFO *signerInfo = NULL;

	if (!p7 || !p7->value) return PKI_ERR;

	if ((signerInfo = PKI_X509_PKCS7_get_signer_info(p7, -1)) == NULL ) {
		PKI_DEBUG("signerInfo not present in PKCS7");
		return ( PKI_ERR );
	}

	if (signerInfo->unauth_attr == NULL) return PKI_OK;

	return PKI_STACK_X509_ATTRIBUTE_delete(signerInfo->unauth_attr, id);

}

/* ---------------------------- TEXT Format ---------------------------- */

int PKI_X509_PKCS7_VALUE_print_bio ( PKI_IO *bio, 
				     const PKI_X509_PKCS7_VALUE *p7val ) {

	int type;
	int i,j;

	int cert_num = -1;
	int crl_num = -1;
	int signers_num = -1;
	char *tmp_str = NULL;

	PKI_X509_PKCS7 *msg = NULL;
	PKI_X509_CERT *cert = NULL;
	PKI_DIGEST *digest = NULL;
	PKI_MEM *mem = NULL;

	const PKCS7_SIGNER_INFO *si = NULL;

	if (!bio || !p7val ) return PKI_ERR;

	if (( msg = PKI_X509_new_dup_value ( PKI_DATATYPE_X509_PKCS7,
				p7val, NULL )) == NULL ) {
		return PKI_ERR;
	}

	type = PKI_X509_PKCS7_get_type ( msg );

	BIO_printf( bio, "PKCS#7 Message:\r\n" );
	BIO_printf( bio, "    Message Type:\r\n        " );

	switch ( type ) {
		case PKI_X509_PKCS7_TYPE_ENCRYPTED:
			BIO_printf( bio, "Encrypted\r\n" );
			break;
		case PKI_X509_PKCS7_TYPE_SIGNED:
			BIO_printf( bio, "Signed\r\n" );
			break;
		case PKI_X509_PKCS7_TYPE_SIGNEDANDENCRYPTED:
			BIO_printf( bio, "Signed and Encrypted\r\n" );
			break;
		default:
			BIO_printf( bio, "Unknown (%d)\r\n", type );
			break;
	}

	BIO_printf( bio, "    Message Data:\r\n");
	if (( mem = PKI_X509_PKCS7_get_raw_data ( msg )) == NULL ) {
		BIO_printf( bio, "        None.\r\n");
	} else {
		int msg_type = 0;

		BIO_printf( bio, "        Size=%u bytes\r\n", 
						(unsigned int) mem->size );

		msg_type = PKI_X509_PKCS7_get_type ( msg );
		if ( msg_type == PKI_X509_PKCS7_TYPE_ENCRYPTED ||
				msg_type == 
					PKI_X509_PKCS7_TYPE_SIGNEDANDENCRYPTED){
			BIO_printf( bio, "        Encrypted=yes\r\n");
			BIO_printf( bio, "        Algorithm=%s\r\n",
				PKI_ALGOR_get_parsed (
					PKI_X509_PKCS7_get_encode_alg ( msg )));
		} else {
			BIO_printf( bio, "        Encrypted=no\r\n");
		}
		PKI_MEM_free ( mem );
	}

	i = 0;
	if (( si = PKI_X509_PKCS7_get_signer_info ( msg, i )) == NULL ) {
		BIO_printf(bio, "    Signature Info:\r\n" );
		BIO_printf(bio, "        No Signature found.\r\n" );
	}

	// Print the Signer Info
	BIO_printf( bio, "    Signer Info:\r\n");
	signers_num = PKI_X509_PKCS7_get_signers_num ( msg );
	for ( i = 0; i < signers_num; i++ ) {
		PKCS7_ISSUER_AND_SERIAL *ias = NULL;

		BIO_printf ( bio, "        [%d of %d] Signer Details:\r\n", 
							i+1, signers_num );

		if (( si = PKI_X509_PKCS7_get_signer_info ( msg, i )) == NULL )
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
	if( PKI_X509_PKCS7_has_recipients ( msg ) == PKI_ERR ) {
		BIO_printf( bio, "        No Recipients\r\n");
	} else {
		int rec_num = 0;
		const PKI_X509_CERT *rec = NULL;

		rec_num = PKI_X509_PKCS7_get_recipients_num ( msg );
		for ( i=0; i < rec_num; i++ ) {
			rec = PKI_X509_PKCS7_get_recipient_cert ( msg, i );
			if ( !rec ) {
				const PKCS7_RECIP_INFO *ri = NULL;
				PKCS7_ISSUER_AND_SERIAL *ias = NULL;

				BIO_printf( bio, "        "
					"[%d of %d] Recipient Details:\r\n", 
						i+1, rec_num );

				ri = PKI_X509_PKCS7_get_recipient_info(msg,i);
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

	/* Now Let's Check the CRLs */

	BIO_printf(bio, "\r\n    Certificates:\r\n");
	if ((cert_num = PKI_X509_PKCS7_get_certs_num ( msg )) > 0 ) {
		PKI_X509_CERT * cert = NULL;
		for (i = 0; i < cert_num; i++ ) {
			BIO_printf( bio, "        [%d of %d] Certificate:\r\n",
				 i+1, cert_num);
			if((cert = PKI_X509_PKCS7_get_cert ( msg, i )) == NULL ) {
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

	BIO_printf(bio, "\r\n    Certificate Revocation Lists:\r\n");
	if((crl_num = PKI_X509_PKCS7_get_crls_num ( msg )) > 0 ) {
		PKI_X509_CRL * crl  = NULL;
		for ( i = 0; i < crl_num; i++ ) {
			BIO_printf( bio, "        [%d of %d] CRL Details:\r\n", 
				i+1, crl_num );

			if(( crl = PKI_X509_PKCS7_get_crl ( msg, i )) == NULL ) {
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
}
