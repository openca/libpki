
#ifndef __LIBPKI_PKI_ALGORITHM_H__
#define __LIBPKI_PKI_ALGORITHM_H__

#ifdef ENABLE_OPENSSL
# ifndef __LIBPKI_OPENSSL_DATA_ST__
#  include <libpki/openssl/data_st.h>
# endif
#endif

PKI_ALGORITHM * PKI_ALGORITHM_new ();
void PKI_ALGORITHM_free ( PKI_ALGORITHM *a );
PKI_ALGORITHM * PKI_ALGORITHM_new_type ( int type );
PKI_ALGORITHM * PKI_ALGORITHM_new_digest ( PKI_DIGEST_ALG *alg );

#endif

