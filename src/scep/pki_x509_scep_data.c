/* SCEP msg handling
 * (c) 2009 by Massimiliano Pala and OpenCA Labs
 * All Rights Reserved
 */

#include <libpki/pki.h>

/*! \brief Generates a new SCEP_DATA */

PKI_X509_SCEP_DATA * PKI_X509_SCEP_DATA_new ( void ) {

	return PKI_X509_PKCS7_new ( PKI_X509_PKCS7_TYPE_ENCRYPTED );
}

/*! \brief Frees the memory associated with a PKI_X509_SCEP_DATA */

void PKI_X509_SCEP_DATA_free ( PKI_X509_SCEP_DATA *data ) {

        PKI_X509_PKCS7_free ( data );

        return;
}


/*! \brief Adds a recipient to a SCEP_DATA */

int PKI_X509_SCEP_DATA_add_recipient ( PKI_X509_SCEP_DATA *data,
			PKI_X509_CERT *recipient ) {
	return PKI_X509_PKCS7_add_recipient ( data, recipient );
}

/*! \brief Adds a stack of recipients for a SCEP_DATA */

int PKI_X509_SCEP_DATA_set_recipients ( PKI_X509_SCEP_DATA *data,
			PKI_X509_CERT_STACK *sk  ) {
	return PKI_X509_PKCS7_set_recipients ( data, sk );
}

/*! \brief Sets the content of the SCEP_DATA via a PKI_X509 object */

int PKI_X509_SCEP_DATA_set_x509_obj ( PKI_X509_SCEP_DATA *data, PKI_X509 *obj )
{
	PKI_MEM *mem = NULL;
	int ret = PKI_ERR;

	if ( !data || !data->value || !obj || !obj->value )
		return PKI_ERR;

	if (( mem = PKI_X509_put_mem ( obj, PKI_DATA_FORMAT_ASN1, NULL, NULL )) == NULL )
		return PKI_ERROR(PKI_ERR_GENERAL, NULL);

	ret = PKI_X509_SCEP_DATA_set_raw_data ( data, mem->data, (ssize_t) mem->size );

	PKI_MEM_free ( mem );

	return ret;
}

/*! \brief Sets the content of the SCEP_DATA via a SCEP_ISSUER_AND_SUBJECT */

int PKI_X509_SCEP_DATA_set_ias ( PKI_X509_SCEP_DATA *scep_data, SCEP_ISSUER_AND_SUBJECT *ias )
{
	unsigned char *data = NULL;
	ssize_t size = 0;

	if ( !scep_data || !scep_data->value || !ias ) return PKI_ERR;

	if( (size = i2d_SCEP_ISSUER_AND_SUBJECT(ias, NULL)) <= 0 ) return PKI_ERR;

	if ((data = ( unsigned char * ) PKI_Malloc ( (size_t) size )) == NULL ) return PKI_ERR;

	if (i2d_SCEP_ISSUER_AND_SUBJECT( ias, &data ) <= 0 ) 
	{
		PKI_Free ( data );
		return PKI_ERR;
	}

	return PKI_X509_SCEP_DATA_set_raw_data ( scep_data, data, size );
}

/*! \brief Sets the content of the SCEP_DATA (raw data) */

int PKI_X509_SCEP_DATA_set_raw_data ( PKI_X509_SCEP_DATA *data,
			unsigned char *raw_val, ssize_t size ) {

	if ( !data || !data->value || !raw_val || size <= 0 )
			return PKI_ERR;

	return PKI_X509_PKCS7_encode ( data, raw_val, (size_t) size );
}

