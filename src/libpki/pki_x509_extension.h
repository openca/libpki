/* Extensions - driver specific part */

#ifndef _LIBPKI_X509_EXTENSION_H
#define _LIBPKI_X509_EXTENSION_H

PKI_X509_EXTENSION *PKI_X509_EXTENSION_new( void );

void PKI_X509_EXTENSION_free ( PKI_X509_EXTENSION *ext );

PKI_X509_EXTENSION *PKI_X509_EXTENSION_value_new_profile ( 
		PKI_X509_PROFILE *profile, PKI_CONFIG *oids, 
			PKI_CONFIG_ELEMENT *extNode, PKI_TOKEN *tk );

#endif


