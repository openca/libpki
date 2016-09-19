/* X509 Profile Exts management for libpki */

#ifndef _LIBPKI_X509_EXTENSIONS_H
#define _LIBPKI_X509_EXTENSIONS_H

int PKI_X509_EXTENSIONS_cert_add_profile(PKI_X509_PROFILE *conf, 
				         PKI_CONFIG       *oids,
                                         PKI_X509_CERT    *x, 
                                         PKI_TOKEN        *tk );

int PKI_X509_EXTENSIONS_req_add_profile(PKI_X509_PROFILE *conf, 
				        PKI_CONFIG       *oids, 
                                        PKI_X509_REQ     *req,
                                        PKI_TOKEN        *tk );

int PKI_X509_EXTENSIONS_crl_add_profile(PKI_X509_PROFILE *conf, 
				        PKI_CONFIG       *oids, 
                                        PKI_X509_CRL     *crl,
                                        PKI_TOKEN        *tk );

/*
PKI_X509_EXTENSION *PKI_X509_EXTENSION_new_profile ( PKI_X509_PROFILE *profile,
			PKI_CONFIG *oids, PKI_CONFIG_ELEMENT *extNode );

PKI_X509_EXTENSION *PKI_X509_EXTENSION_value_new_profile ( 
			PKI_X509_PROFILE *profile, PKI_CONFIG *oids, 
				PKI_CONFIG_ELEMENT *extNode );
*/

#endif
