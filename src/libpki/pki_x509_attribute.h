/* src/libpki/PKI_X509_ATTRIBUTE_VALUE.h */

#ifndef _LIBPKI_X509_ATTRIBUTE_H_
#define _LIBPKI_X509_ATTRIBUTE_H_
# pragma once

#include <libpki/pki_x509_data_st.h>
#include <libpki/stack.h>

BEGIN_C_DECLS

						// ======================
						// Data Types Definitions
						// ======================

// // Attribute Definition
typedef struct x509_attributes_st  PKI_X509_ATTRIBUTE_VALUE;

DECLARE_STACK_OF(PKI_X509_ATTRIBUTE_VALUE)

						// ======================
						// Data Types Definitions
						// ======================
// Stack Declaration
DECLARE_OSSL_STACK_FN(X509_ATTRIBUTE)

						// ====================
						// Functions Prototypes
						// ====================

// void PKI_STACK_X509_ATTRIBUTE_VALUE_free ( PKI_X509_ATTRIBUTE_STACK *sk );
// void PKI_STACK_X509_ATTRIBUTE_VALUE_free_all ( PKI_X509_ATTRIBUTE_STACK *sk );
// int PKI_STACK_X509_ATTRIBUTE_VALUE_add(const PKI_X509_ATTRIBUTE_STACK * a_sk,
// 				 PKI_X509_ATTRIBUTE_VALUE             * a );

// const PKI_X509_ATTRIBUTE_VALUE *PKI_STACK_X509_ATTRIBUTE_VALUE_get(
// 			const PKI_X509_ATTRIBUTE_STACK * const a_sk,
// 			PKI_ID attribute_id );

// const PKI_X509_ATTRIBUTE_VALUE *PKI_STACK_X509_ATTRIBUTE_VALUE_get_by_num ( 
// 			const PKI_X509_ATTRIBUTE_STACK * const a_sk,
// 			int num );

// const PKI_X509_ATTRIBUTE_VALUE *PKI_STACK_X509_ATTRIBUTE_VALUE_get_by_name (
// 			const PKI_X509_ATTRIBUTE_STACK * const a_sk, 
// 			const char * const name );

// int PKI_STACK_X509_ATTRIBUTE_VALUE_delete(const PKI_X509_ATTRIBUTE_STACK * a_sk,
// 				    PKI_ID                           attr );

// int PKI_STACK_X509_ATTRIBUTE_VALUE_delete_by_num(
// 			const PKI_X509_ATTRIBUTE_STACK * a_sk,
// 			int                              num);

// int PKI_STACK_X509_ATTRIBUTE_VALUE_delete_by_name (
// 			const PKI_X509_ATTRIBUTE_STACK * a_sk, 
// 			const char                     * const name );

// int PKI_STACK_X509_ATTRIBUTE_VALUE_replace(const PKI_X509_ATTRIBUTE_STACK * a_sk, 
// 				     PKI_X509_ATTRIBUTE_VALUE             * a);

// void PKI_X509_ATTRIBUTE_VALUE_free ( PKI_X509_ATTRIBUTE_VALUE *a );
// void PKI_X509_ATTRIBUTE_VALUE_free_null ( void *a );

// PKI_X509_ATTRIBUTE_VALUE *PKI_X509_ATTRIBUTE_VALUE_new_null ( void );

// PKI_X509_ATTRIBUTE_VALUE *PKI_X509_ATTRIBUTE_VALUE_new( PKI_ID attribute_id,
// 					    int data_type,
// 					    const unsigned char *value,
// 					    size_t size );

// PKI_X509_ATTRIBUTE_VALUE *PKI_X509_ATTRIBUTE_VALUE_new_name(const char *name,
// 						int data_type,
// 						const char *value,
// 						size_t size );

// const char *PKI_X509_ATTRIBUTE_get_descr ( const PKI_X509_ATTRIBUTE_VALUE * const a );
// const PKI_STRING *PKI_X509_ATTRIBUTE_get_value ( const PKI_X509_ATTRIBUTE_VALUE * const a );
// char *PKI_X509_ATTRIBUTE_get_parsed (const PKI_X509_ATTRIBUTE_VALUE * const a );

END_C_DECLS

#endif // End of _LIBPKI_X509_ATTRIBUTE_H_
