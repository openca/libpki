/* PKI_X509 object management */

#ifndef _LIBPKI_PKI_X509_H
#define _LIBPKI_PKI_X509_H

#include <libpki/pki_x509_data_st.h>

#ifndef _LIBPKI_HSM_MAIN_H
#include <libpki/drivers/hsm_main.h>
#endif

// Stack Declarations
DECLARE_LIBPKI_STACK_FN_DUP(PKI_X509)

// ===================
// Function Prototypes
// ===================

const PKI_X509_CALLBACKS *PKI_X509_CALLBACKS_get ( PKI_DATATYPE type, struct hsm_st *hsm );

PKI_X509 *PKI_X509_new ( PKI_DATATYPE type, struct hsm_st *hsm );
PKI_X509 *PKI_X509_new_value(PKI_DATATYPE type, void *data, struct hsm_st *hsm);
PKI_X509 *PKI_X509_new_dup_value(PKI_DATATYPE type, const void *data, struct hsm_st *hsm);

void PKI_X509_free_void ( void *x );
void PKI_X509_free ( PKI_X509 *x );

int PKI_X509_set_modified ( PKI_X509 *x );

int PKI_X509_set_hsm ( PKI_X509 *x, struct hsm_st *hsm );
struct hsm_st *PKI_X509_get_hsm (const PKI_X509 *x );
int PKI_X509_set_reference ( PKI_X509 *x, URL *url );
URL *PKI_X509_get_reference (const PKI_X509 *x );

PKI_X509 * PKI_X509_dup (const PKI_X509 *x );
void * PKI_X509_dup_value (const PKI_X509 *x );

void * PKI_X509_get_value (const PKI_X509 *x );
int PKI_X509_set_value ( PKI_X509 *x, void *data );
PKI_DATATYPE PKI_X509_get_type (const PKI_X509 *x );
const char * PKI_X509_get_type_parsed (const PKI_X509 *obj );

int PKI_X509_is_signed(const PKI_X509 *obj );

PKI_MEM * PKI_X509_VALUE_get_tbs_asn1(const void * v, 
		                      const PKI_DATATYPE     type);

/*! \brief Returns the DER encoded version of the toBeSigned portion of the PKI_X509_VALUE structure */
PKI_MEM * PKI_X509_get_tbs_asn1(const PKI_X509 *x);

void * PKI_X509_get_data (const PKI_X509 *x, PKI_X509_DATA type );

/*! \brief Returns the parsed (char *, int *, etc.) version of the data in a PKI_X509 object */
void * PKI_X509_get_parsed (const PKI_X509 *x, PKI_X509_DATA type );

/*! \brief Prints the parsed data from a PKI_X509 object to a file descriptor */
int PKI_X509_print_parsed (const PKI_X509 *x, PKI_X509_DATA type, int fd );

/*! \brief Deletes the hard copy (eg., file, hsm file, etc.) of a PKI_X509 object. */
int PKI_X509_delete ( PKI_X509 *x );

/*! \brief Attaches (transfers ownership) the value to the PKI_X509 object. */
int PKI_X509_attach(PKI_X509 * x, PKI_DATATYPE type, void * data, HSM * hsm);

/*! \brief Detaches (sets to NULL) and returns the internal value. */
int PKI_X509_detach(PKI_X509 * x, void ** data, PKI_DATATYPE * type, HSM **hsm);

/*! \brief Sets the Aux Data into an PKI_X509 structure */
int PKI_X509_aux_data_set (PKI_X509 * x,
	                         void     * data, 
	                         void       (*data_free_func)(void *),
	                         void     * (*data_dup_func )(void *));

void * PKI_X509_aux_data_get(PKI_X509 * x);

void * PKI_X509_aux_data_dup(PKI_X509 * x);

int PKI_X509_aux_data_del(PKI_X509 * x);

int PKI_X509_set_status(PKI_X509 *x, int status);

int PKI_X509_get_status(PKI_X509 *x);

#endif
