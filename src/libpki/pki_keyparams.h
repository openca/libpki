/* openssl/pki_keyparams.c */

#ifndef _LIBPKI_PKI_KEYPARAMS_H
#define _LIBPKI_PKI_KEYPARAMS_H

/* Memory Management */
PKI_KEYPARAMS *PKI_KEYPARAMS_new( PKI_SCHEME_ID scheme, PKI_X509_PROFILE *prof);
void PKI_KEYPARAMS_free ( PKI_KEYPARAMS *kp );

/* Functions */
PKI_SCHEME_ID PKI_KEYPARAMS_get_type ( PKI_KEYPARAMS *kp );

#endif // _LIBPKI_PKI_KEYPARAMS_H
