/* src/libpki/pki_x509_attribute.h */

#ifndef _LIBPKI_X509_ATTRIBUTE_H_
#define _LIBPKI_X509_ATTRIBUTE_H_

#ifndef _LIBPKI_STACK_TYPES_H
#include <libpki/stack_types.h>
#endif

#ifndef _LIBPKI_PKI_X509_TYPES_H
#include <libpki/pki_x509_types.h>
#endif

#ifndef _LIBPKI_STRING_H
#include <libpki/pki_string.h>
#endif

// ============================
// Definition of X509_ATTRIBUTE
// ============================

#define PKI_X509_ATTRIBUTE	X509_ATTRIBUTE

// =========================================
// Definition of the STACK of X509_ATTRIBUTE
// =========================================

#define PKI_X509_ATTRIBUTE_STACK 	STACK_OF(X509_ATTRIBUTE)

#define PKI_STACK_X509_ATTRIBUTE_elements(a) sk_X509_ATTRIBUTE_num ( a )
#define PKI_STACK_X509_ATTRIBUTE_get_num(a,b) sk_X509_ATTRIBUTE_value (a, b)
#define PKI_STACK_X509_ATTRIBUTE_pop(a) sk_X509_ATTRIBUTE_pop(a)
#define PKI_STACK_X509_ATTRIBUTE_pop_free(a) sk_X509_ATTRIBUTE_pop_free(a)
#define PKI_STACK_X509_ATTRIBUTE_new_null() sk_X509_ATTRIBUTE_new_null()
#define PKI_STACK_X509_ATTRIBUTE_push(a,b) sk_X509_ATTRIBUTE_push(a,b)

// =========================
// X509_ATTRIBUTE Management
// =========================

/* --------------------- PKI_X509_ATTRIBUTE_STACK ---------------------- */
void PKI_X509_ATTRIBUTE_free ( PKI_X509_ATTRIBUTE *a );
void PKI_X509_ATTRIBUTE_free_null ( void *a );

PKI_X509_ATTRIBUTE *PKI_X509_ATTRIBUTE_new_null ( void );

PKI_X509_ATTRIBUTE *PKI_X509_ATTRIBUTE_new( PKI_ID attribute_id,
					    int data_type,
					    const unsigned char *value,
					    size_t size );

PKI_X509_ATTRIBUTE *PKI_X509_ATTRIBUTE_new_name(const char *name,
						int data_type,
						const char *value,
						size_t size );

void PKI_STACK_X509_ATTRIBUTE_free ( PKI_X509_ATTRIBUTE_STACK *sk );
void PKI_STACK_X509_ATTRIBUTE_free_all ( PKI_X509_ATTRIBUTE_STACK *sk );

int PKI_STACK_X509_ATTRIBUTE_add(const PKI_X509_ATTRIBUTE_STACK * a_sk,
				 PKI_X509_ATTRIBUTE             * a );

const PKI_X509_ATTRIBUTE *PKI_STACK_X509_ATTRIBUTE_get(
			const PKI_X509_ATTRIBUTE_STACK * const a_sk,
			PKI_ID attribute_id );

const PKI_X509_ATTRIBUTE *PKI_STACK_X509_ATTRIBUTE_get_by_num ( 
			const PKI_X509_ATTRIBUTE_STACK * const a_sk,
			int num );

const PKI_X509_ATTRIBUTE *PKI_STACK_X509_ATTRIBUTE_get_by_name (
			const PKI_X509_ATTRIBUTE_STACK * const a_sk, 
			const char * const name );

int PKI_STACK_X509_ATTRIBUTE_delete(const PKI_X509_ATTRIBUTE_STACK * a_sk,
				    PKI_ID                           attr );

int PKI_STACK_X509_ATTRIBUTE_delete_by_num(
			const PKI_X509_ATTRIBUTE_STACK * a_sk,
			int                              num);

int PKI_STACK_X509_ATTRIBUTE_delete_by_name (
			const PKI_X509_ATTRIBUTE_STACK * a_sk, 
			const char                     * const name );

int PKI_STACK_X509_ATTRIBUTE_replace(const PKI_X509_ATTRIBUTE_STACK * a_sk, 
				     PKI_X509_ATTRIBUTE             * a);

const char *PKI_X509_ATTRIBUTE_get_descr ( const PKI_X509_ATTRIBUTE * const a );
const PKI_STRING *PKI_X509_ATTRIBUTE_get_value ( const PKI_X509_ATTRIBUTE * const a );
char *PKI_X509_ATTRIBUTE_get_parsed (const PKI_X509_ATTRIBUTE * const a );

#endif
