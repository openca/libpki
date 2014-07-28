/* PKI_STRING management for libpki */

#ifndef _LIBPKI_STRING_H
#define _LIBPKI_STRING_H

#include <openssl/asn1.h>
#include <openssl/objects.h>

/* Basic Definitions */
#define PKI_STRING 			ASN1_STRING
#define PKI_BIT_STRING 			ASN1_BIT_STRING

typedef enum {
	/* Unknown */
	PKI_STRING_UNKNOWN = -1,
	/* ASCII Strings */
	PKI_STRING_IA5 = V_ASN1_IA5STRING,
	/* UTF8 Strings */
	PKI_STRING_UTF8 = V_ASN1_UTF8STRING,
	/* BIT Strings */
	PKI_STRING_BIT = V_ASN1_BIT_STRING,
	/* Two Bytes Chars */
	PKI_STRING_BMP = V_ASN1_BMPSTRING,
	/* OCTECT STRING */
	PKI_STRING_OCTET = V_ASN1_OCTET_STRING,
	/* T61 Strings - Don't use in PKIX standards */
	PKI_STRING_T61 = V_ASN1_T61STRING,
	PKI_STRING_PRINTABLE = V_ASN1_PRINTABLESTRING,
	PKI_STRING_NUMERIC = V_ASN1_NUMERICSTRING,
	PKI_STRING_VISIBLE = V_ASN1_VISIBLESTRING,
	PKI_STRING_GENERAL = V_ASN1_GENERALSTRING,
	PKI_STRING_UNIVERSAL = V_ASN1_UNIVERSALSTRING,
} PKI_STRING_DATATYPE;

/* Manipulating functions */
PKI_STRING * PKI_STRING_new_null ( int type );
PKI_STRING * PKI_STRING_new( int type, char * val, ssize_t size );
PKI_STRING * PKI_STRING_dup ( PKI_STRING *a );
void PKI_STRING_free( PKI_STRING *s );

int PKI_STRING_set( PKI_STRING *s, char *content, ssize_t size );
int PKI_STRING_get_type( PKI_STRING *s );
char * PKI_STRING_get_parsed( PKI_STRING *s );
char * PKI_STRING_get_utf8( PKI_STRING *s );
PKI_DIGEST * PKI_STRING_get_digest( PKI_STRING *s, PKI_DIGEST_ALG *digest);

/* Printing to fd or stdout */
int PKI_STRING_print( PKI_STRING *s );
int PKI_STRING_print_fp( FILE *fp, PKI_STRING *s );

#endif


