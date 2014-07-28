/* ENGINE Object Management Functions */

#ifndef _LIBPKI_HEADERS_ENGINE_H
#define _LIBPKI_HEADERS_ENGINE_H

PKI_ENGINE *PKI_KMF_ENGINE_new ( char *e_id );
int PKI_KMF_ENGINE_free ( PKI_ENGINE *e );
int PKI_KMF_ENGINE_init ( PKI_ENGINE *e, PKI_STACK *pre, PKI_STACK *post );

#endif
