/* Extensions - driver specific part */

#ifndef _LIBPKI_X509_EXTENSION_H
#define _LIBPKI_X509_EXTENSION_H

PKI_X509_EXTENSION *PKI_X509_EXTENSION_new( void );

void PKI_X509_EXTENSION_free ( PKI_X509_EXTENSION *ext );

void PKI_X509_EXTENSION_free_void ( void *ext );

PKI_X509_EXTENSION *PKI_X509_EXTENSION_value_new_profile(
						const PKI_X509_PROFILE   * profile,
						const PKI_CONFIG         * oids,
						const PKI_CONFIG_ELEMENT * extNode,
						const PKI_TOKEN          * tk);

PKI_X509_EXTENSION_STACK *PKI_X509_CERT_ext_list(PKI_X509_CERT * x);

PKI_X509_EXTENSION_STACK *PKI_X509_CERT_VALUE_ext_list(PKI_X509_CERT_VALUE * x);


#endif


