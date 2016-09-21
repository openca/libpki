/* X509 Profile Exts management for libpki */

#ifndef _LIBPKI_X509_EXTENSIONS_H
#define _LIBPKI_X509_EXTENSIONS_H

#ifndef _LIBPKI_X509_PROFILE_H
#include <libpki/pki_x509_profile.h>
#endif

#ifndef _LIBPKI_CONF_H
#include <libpki/pki_conf.h>
#endif

#ifndef _LIBPKI_PKI_X509_CERT_H
#include <libpki/pki_x509_cert.h>
#endif

#ifndef _LIBPKI_PKI_X509_REQ_H
#include <libpki/pki_x509_req.h>
#endif

#ifndef _LIBPKI_PKI_TOKEN_H
#include <libpki/pki_token.h>
#endif

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
