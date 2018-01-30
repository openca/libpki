/* openssl/pki_keyparams.c */

#ifndef _LIBPKI_PKI_KEYPARAMS_H
#define _LIBPKI_PKI_KEYPARAMS_H

/* Memory Management */
PKI_KEYPARAMS *PKI_KEYPARAMS_new(PKI_SCHEME_ID scheme,
				 const PKI_X509_PROFILE *prof);

void PKI_KEYPARAMS_free(PKI_KEYPARAMS *kp);
 
/* Functions */
PKI_SCHEME_ID PKI_KEYPARAMS_get_type(const PKI_KEYPARAMS *kp );
int PKI_KEYPARAMS_set_scheme(PKI_KEYPARAMS * kp, PKI_SCHEME_ID schemeId);
int PKI_KEYPARAMS_set_curve(PKI_KEYPARAMS * kp, const char * curveName);
int PKI_KEYPARAMS_set_bits(PKI_KEYPARAMS * kp, int bits);

#endif // _LIBPKI_PKI_KEYPARAMS_H
