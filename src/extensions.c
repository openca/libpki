/* X509 Profile Exts management for libpki */

#include <libpki/extensions.h>

/*?
 * \brief Adds extensions to a certificate according to the profile
 */

int PKI_X509_EXTENSIONS_cert_add_profile ( PKI_X509_PROFILE *conf, 
				PKI_CONFIG *oids, PKI_X509_CERT *x, PKI_TOKEN *tk ) {

	PKI_X509_EXTENSION *ext = NULL;

	int i = -1;
	int ext_num = -1;

	if ( !conf || !x || !x->value ) return PKI_ERR;

	ext_num = PKI_X509_PROFILE_get_exts_num ( conf );

	for (i = 0; i < ext_num; i++)
	{
		if ((ext = PKI_X509_PROFILE_get_ext_by_num(conf, i, tk)) != NULL)
		{
			PKI_X509_CERT_add_extension(x, ext);
		}
		else
		{
			PKI_log_debug ("Can not create EXTENSION number %d", i);
		}
	}

	return PKI_OK;
}


int PKI_X509_EXTENSIONS_req_add_profile ( PKI_X509_PROFILE *conf, 
				PKI_CONFIG *oids, PKI_X509_REQ *req, PKI_TOKEN *tk ) {

	PKI_X509_EXTENSION *ext = NULL;

	int i = -1;
	int ret = -1;
	int ext_num = -1;

	if (!conf || !req || !req->value) return PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);

	ext_num = PKI_X509_PROFILE_get_exts_num ( conf );

	for ( i = 0; i < ext_num; i++ )
	{
		if ((ext = PKI_X509_PROFILE_get_ext_by_num ( conf, i, tk )) != NULL)
		{
			ret = PKI_X509_REQ_add_extension(req, ext);
			PKI_log_debug("Extension %d added, result is %d", i, ret );
		}
		else PKI_log_debug ("Can not create EXTENSION number %d", i);
	}

	return PKI_OK;
}


/*!
 * \brief Adds extensions to a CRL according to the profile passed as argument
 */

int PKI_X509_EXTENSIONS_crl_add_profile ( PKI_X509_PROFILE *conf, 
				PKI_CONFIG *oids, PKI_X509_CRL *crl, PKI_TOKEN *tk ) {

	PKI_X509_EXTENSION *ext = NULL;

	int i = -1;
	int ext_num = -1;

	if ( !conf || !crl || !crl->value ) return PKI_ERR;

	ext_num = PKI_X509_PROFILE_get_exts_num ( conf );

	for ( i = 0; i < ext_num; i++ ) {
		if (( ext = PKI_X509_PROFILE_get_ext_by_num ( conf, i, tk )) != NULL ) {
			PKI_X509_CRL_add_extension ( crl, ext );
		} else {
			PKI_log_debug ("Can not create EXTENSION number %d", i);
		}
	}

	return PKI_OK;

}

