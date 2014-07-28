/* PKI_X509 object management */

#ifndef _LIBPKI_PKI_X509_H
#define _LIBPKI_PKI_X509_H

const PKI_X509_CALLBACKS *PKI_X509_CALLBACKS_get ( PKI_DATATYPE type, struct hsm_st *hsm );

PKI_X509 *PKI_X509_new ( PKI_DATATYPE type, struct hsm_st *hsm );
PKI_X509 *PKI_X509_new_value(PKI_DATATYPE type, void *data, struct hsm_st *hsm);
PKI_X509 *PKI_X509_new_dup_value(PKI_DATATYPE type, void *data, struct hsm_st *hsm);

void PKI_X509_free_void ( void *x );
void PKI_X509_free ( PKI_X509 *x );

int PKI_X509_set_modified ( PKI_X509 *x );

int PKI_X509_set_hsm ( PKI_X509 *x, struct hsm_st *hsm );
struct hsm_st *PKI_X509_get_hsm ( PKI_X509 *x );
int PKI_X509_set_reference ( PKI_X509 *x, URL *url );
URL *PKI_X509_get_reference ( PKI_X509 *x );

PKI_X509 * PKI_X509_dup ( PKI_X509 *x );
void * PKI_X509_dup_value ( PKI_X509 *x );

void * PKI_X509_get_value ( PKI_X509 *x );
int PKI_X509_set_value ( PKI_X509 *x, void *data );
PKI_DATATYPE PKI_X509_get_type ( PKI_X509 *x );
const char * PKI_X509_get_type_parsed ( PKI_X509 *obj );

int PKI_X509_is_signed( PKI_X509 *obj );

void * PKI_X509_get_data ( PKI_X509 *x, PKI_X509_DATA type );
void * PKI_X509_get_parsed ( PKI_X509 *x, PKI_X509_DATA type );
int PKI_X509_print_parsed ( PKI_X509 *x, PKI_X509_DATA type, int fd );

int PKI_X509_delete ( PKI_X509 *x );

#endif
