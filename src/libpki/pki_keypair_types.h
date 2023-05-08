/* src/libpki/pki_keypair_types.h */

#ifndef _LIBPKI_PKI_KEYPAIR_TYPES_H
#define _LIBPKI_PKI_KEYPAIR_TYPES_H

#ifndef _LIBPKI_STACK_TYPES_H
#include <libpki/stack_types.h>
#endif

#ifndef _LIBPKI_HEADER_DATA_ST_H
#include <libpki/openssl/data_st.h>
#endif

#ifndef _LIBPKI_PKI_DATATYPES_H
#include <libpki/pki_datatypes.h>
#endif

#ifndef _LIBPKI_PKI_X509_TYPES_H
#include <libpki/pki_x509_types.h>
#endif

// ===========================================
// PKI_X509_KEYPAIR and PKI_X509_KEYPAIR_VALUE
// ===========================================

#define PKI_X509_KEYPAIR_VALUE  EVP_PKEY
#define PKI_X509_KEYPAIR        PKI_X509

// ========================
// Keypair Stack Definition
// ========================

//! \brief PKI_X509_KEYPAIR_STACK is the stack of PKI_X509_KEYPAIR
#define PKI_X509_KEYPAIR_STACK 		PKI_STACK

/* define for PKI_X509_KEYPAIR stacks - implement object type casting */
#define PKI_STACK_X509_KEYPAIR_new() (PKI_X509_KEYPAIR_STACK *) PKI_STACK_new((void (*)(void *))PKI_X509_KEYPAIR_free)
#define PKI_STACK_X509_KEYPAIR_free( p ) PKI_STACK_free ( (PKI_STACK *) p)
#define PKI_STACK_X509_KEYPAIR_free_all( p ) PKI_STACK_free_all ( (PKI_STACK *) p)
#define PKI_STACK_X509_KEYPAIR_push(p, obj) PKI_STACK_push((PKI_STACK *)p, (void *)obj)
#define PKI_STACK_X509_KEYPAIR_pop(p) (PKI_X509_KEYPAIR *) PKI_STACK_pop( (PKI_STACK *) p )
#define PKI_STACK_X509_KEYPAIR_get_num(p,n) (PKI_X509_KEYPAIR *) PKI_STACK_get_num( (PKI_STACK *)p, n)
#define PKI_STACK_X509_KEYPAIR_ins_num(p,n,obj) PKI_STACK_ins_num((PKI_STACK *)p,n,(void *)obj)
#define PKI_STACK_X509_KEYPAIR_del_num(p,n) PKI_STACK_del_num((PKI_STACK *)p, n)
#define PKI_STACK_X509_KEYPAIR_elements(p) PKI_STACK_elements((PKI_STACK *)p)

// ===============
// Data Structures
// ===============

typedef struct pki_keyparams_st {
	int bits;
	PKI_SCHEME_ID scheme;
	// RSA scheme parameters
	struct {
		int exponent;
	} rsa;
	// DSA scheme parameters

#ifdef OPENSSL_NO_DSA
	struct {} dsa;
#endif

#ifdef ENABLE_ECDSA
	// EC scheme parameters
	struct {
		int curve;
		PKI_EC_KEY_FORM form;
		int asn1flags;
	} ec;
#endif // ENABLE_ECDSA

#ifdef ENABLE_OQS
	struct {
		PKI_ALGOR_ID algId;
	} oqs;
#endif // ENABLE_OQS

#ifdef ENABLE_COMPOSITE
	struct {
		PKI_X509_KEYPAIR_STACK * k_stack;
		ASN1_INTEGER * k_of_n;
	} comp;
#endif

} PKI_KEYPARAMS;

#endif // _LIBPKI_PKI_KEYPARAMS_H
