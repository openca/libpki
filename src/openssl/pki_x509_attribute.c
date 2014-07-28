/* src/openssl/pki_x509_attribute.c */

#include <libpki/pki.h>

/*! \brief Frees the memory associated with a PKI_X509_ATTRIBUTE */

void PKI_X509_ATTRIBUTE_free ( PKI_X509_ATTRIBUTE *a ) {

	if( a ) PKI_Free ( a );

	return;
}

void PKI_X509_ATTRIBUTE_free_null ( void *a ) {
	if( a ) PKI_Free ( (PKI_X509_ATTRIBUTE *) a );

	return;
}

/*! \brief Returns an empty PKI_X509_ATTRIBUTE */

PKI_X509_ATTRIBUTE *PKI_X509_ATTRIBUTE_new_null ( void ) {

	return ( X509_ATTRIBUTE_new() );
}

PKI_X509_ATTRIBUTE *PKI_X509_ATTRIBUTE_new( PKI_ID attribute_id,
			int data_type, unsigned char *value, size_t size ) {

	return ( X509_ATTRIBUTE_create_by_NID( NULL, attribute_id, data_type,
			(const char *) value, (int) size ));
}

/*! \brief Returns a PKI_X509_ATTRIBUTE from a string description */

PKI_X509_ATTRIBUTE *PKI_X509_ATTRIBUTE_new_name( char *name,
		int data_type, char *value, size_t size ) {

	return ( X509_ATTRIBUTE_create_by_txt( NULL, name, data_type,
			(unsigned char *) value, (int) size ));
}

/*! \brief Frees the memory associated with a stack of PKI_X509_ATTRIBUTE */

void PKI_STACK_X509_ATTRIBUTE_free ( PKI_X509_ATTRIBUTE_STACK *sk ) {
	if( !sk ) return;

	sk_X509_ATTRIBUTE_free ( sk );
	return;
}

void PKI_STACK_X509_ATTRIBUTE_free_all ( PKI_X509_ATTRIBUTE_STACK *sk ) {

	PKI_X509_ATTRIBUTE *a = NULL;

	if( !sk ) return;

	while ((a = PKI_STACK_X509_ATTRIBUTE_pop ( sk )) != NULL ) {
		PKI_X509_ATTRIBUTE_free ( a );
	}

	sk_X509_ATTRIBUTE_free ( sk );

	return;
}

PKI_X509_ATTRIBUTE *PKI_STACK_X509_ATTRIBUTE_get(PKI_X509_ATTRIBUTE_STACK *a_sk,
				PKI_ID attribute_id ) {

	PKI_X509_ATTRIBUTE *ret = NULL;
	int pos = 0;

	pos = X509at_get_attr_by_NID ( a_sk, attribute_id, 0);
	if( pos >= 0 ) {
		ret = X509at_get_attr( a_sk, pos );
	}

	return ( ret );
}

PKI_X509_ATTRIBUTE *PKI_STACK_X509_ATTRIBUTE_get_by_num ( 
				PKI_X509_ATTRIBUTE_STACK *a_sk, int num ) {

	if ( !a_sk || num >= sk_X509_ATTRIBUTE_num ( a_sk )) 
		return NULL;

	return X509at_get_attr ( a_sk, num );
}

PKI_X509_ATTRIBUTE *PKI_STACK_X509_ATTRIBUTE_get_by_name (
			PKI_X509_ATTRIBUTE_STACK *a_sk, char *name ) {

	int pos = -1;
	PKI_OID *obj = NULL;
	PKI_ID id = 0;

	PKI_X509_ATTRIBUTE *ret = NULL;

	if( !a_sk ) {
		return ( PKI_ERR );
	}

	if((obj = PKI_OID_get ( name )) == NULL ) {
		PKI_log_debug("PKI_X509_ATTRIBUTE_get_by_name()::Attribute %s "
			"not recognized!", name );
		return ( NULL );
	}

	if(( pos = X509at_get_attr_by_NID ( a_sk, id, 0 )) >= 0 ) {
		ret = X509at_get_attr( a_sk, pos );
	};

	return ( ret );
}

int PKI_STACK_X509_ATTRIBUTE_delete ( PKI_X509_ATTRIBUTE_STACK *a_sk, 
							PKI_ID attr ) {
	int pos = -1;
	int found = 0;

	if( !a_sk ) {
		return ( PKI_ERR );
	}

	while((pos = X509at_get_attr_by_NID(a_sk, attr, -1)) >= 0 ) {
		found++;
		if(!X509at_delete_attr( a_sk, pos )) {
			return PKI_ERR;
		}
	}

	if ( found == 0 ) return PKI_ERR;

	return PKI_OK;
		
}

int PKI_STACK_X509_ATTRIBUTE_delete_by_num (PKI_X509_ATTRIBUTE_STACK *a_sk, int num){

	if ( !a_sk ) return PKI_ERR;

	if ( sk_X509_ATTRIBUTE_num ( a_sk ) <= num )  return PKI_ERR;

	X509at_delete_attr ( a_sk, num );

	return PKI_OK;
}

int PKI_STACK_X509_ATTRIBUTE_num ( PKI_X509_ATTRIBUTE_STACK *a_sk ) {
	if (!a_sk) return -1;

	return sk_X509_ATTRIBUTE_num ( a_sk );
}

int PKI_STACK_X509_ATTRIBUTE_delete_by_name ( PKI_X509_ATTRIBUTE_STACK *a_sk, 
								char *name ) {

	PKI_OID *obj = NULL;
	PKI_ID id = 0;

	if( !name || !a_sk ) return ( PKI_ERR );

	if((obj = PKI_OID_get ( name )) == NULL ) {
		return ( PKI_ERR );
	}

	id = PKI_OID_get_id( obj );

	return PKI_STACK_X509_ATTRIBUTE_delete ( a_sk, id );
}

int PKI_STACK_X509_ATTRIBUTE_add ( PKI_X509_ATTRIBUTE_STACK *a_sk,
					PKI_X509_ATTRIBUTE *a ) {
	if(!sk_X509_ATTRIBUTE_push ( a_sk, a ))
		return ( PKI_ERR );

	return PKI_OK;
}

int PKI_STACK_X509_ATTRIBUTE_replace ( PKI_X509_ATTRIBUTE_STACK *a_sk, 
						PKI_X509_ATTRIBUTE *a ) {

	PKI_OID *obj = NULL;
	PKI_ID id = 0;

	/* Check Input */
	if( !a_sk || !a ) {
		return PKI_ERR;
	}

	/* Verify we have a valid OID */
	if((obj = a->object) == NULL ) {
		return PKI_ERR;
	}

	/* Get the ID */
	if((id = PKI_OID_get_id ( obj )) == PKI_ID_UNKNOWN ) {
		return ( PKI_ERR );
	}

	/* Delete the attribute from the stack */
	PKI_STACK_X509_ATTRIBUTE_delete ( a_sk, id );

	return PKI_STACK_X509_ATTRIBUTE_add ( a_sk, a );
}

const char *PKI_X509_ATTRIBUTE_get_descr ( PKI_X509_ATTRIBUTE *a ) {
	if ( !a || !a->object ) return "Unknown";

	return PKI_OID_get_descr ( a->object );
}

PKI_STRING *PKI_X509_ATTRIBUTE_get_value ( PKI_X509_ATTRIBUTE *a ) {

	ASN1_TYPE *a_type = NULL;
	int string_type = 0;

	if( !a ) return ( NULL );

	if((a_type = X509_ATTRIBUTE_get0_type( a, 0 )) == NULL ) {
		return ( NULL );
	}

	/* Check that the value and the type are set */
	/*
        if ((a->value.set == NULL ) ||
		(sk_ASN1_TYPE_num(a->value.set) == 0)) {
                        goto err;
        }

	if((a_type = sk_ASN1_TYPE_value(attr->value.set,0)) == NULL) {
		PKI_log_debug("PKI_X509_ATTRIBUTE_value()::Value not set!");
                return NULL;
        }
	*/

	PKI_log_debug("ATTRIBUTE TYPE=>%s SINGLE=>%d", 
			PKI_OID_get_descr ( a->object ), a->single);

	string_type = ASN1_TYPE_get( a_type );
	switch ( string_type) {
		case V_ASN1_OCTET_STRING:
			return a_type->value.asn1_string;
			/*
			len = (size_t) ASN1_STRING_length( a_type->value.octet_string);
			mem = PKI_MEM_new ( len );
        		memcpy(mem->data, 
				ASN1_STRING_data(a_type->value.octet_string),
                        	len);
			*/
			break;
		case V_ASN1_PRINTABLESTRING:
			return a_type->value.asn1_string;
			/*
			len = (size_t) ASN1_STRING_length(a_type->value.asn1_string);
        		mem = PKI_MEM_new ( len + 1 );
        		memcpy(mem->data, 
				ASN1_STRING_data(a_type->value.asn1_string),
                        	len);
        		mem->data[len] = '\0';
			*/
			break;
		case V_ASN1_BIT_STRING:
			return a_type->value.bit_string;
			/*
			len = (size_t) ASN1_STRING_length( a_type->value.octet_string);
			mem = PKI_MEM_new ( len );
        		memcpy(mem->data, 
				ASN1_STRING_data(a_type->value.octet_string),
                        	len);
			*/
			break;
		default:
			PKI_log_debug("Type Not supported, yet!");
			return ( NULL );
	}

	return NULL;
}

char *PKI_X509_ATTRIBUTE_get_parsed ( PKI_X509_ATTRIBUTE *a ) {

	int attr_type = 0;
	char *ret = NULL;

	ASN1_TYPE *a_type = NULL;
	// PKI_MEM *mem = NULL;
	// PKI_STRING *val = NULL;
	char *tmp_str = NULL;

	if ( !a ) return NULL;

	if((a_type = X509_ATTRIBUTE_get0_type( a, 0 )) == NULL ) {
		return strdup("<Unavailable>");
	}

	attr_type = ASN1_TYPE_get( a_type );

	switch ( attr_type ) {
                case V_ASN1_OBJECT:
				ret = (char *) strdup ( PKI_OID_get_descr( 
						a_type->value.object));
			break;
                case V_ASN1_BOOLEAN:
				// ret = strdup ( a_type->value.boolean->value );
				ret = strdup ("BOOLEAN");
			break;
                case V_ASN1_INTEGER:
				ret = PKI_INTEGER_get_parsed (
					a_type->value.integer);
			break;
                // case V_ASN1_STRING:
		// 		ret = PKI_STRING_get_parsed( 
		// 				a->single->asn1_string);
		// 	break;
                case V_ASN1_BIT_STRING:
				ret = PKI_STRING_get_parsed (
						a_type->value.bit_string);
			break;
                case V_ASN1_OCTET_STRING:
				ret = PKI_STRING_get_parsed (
						a_type->value.octet_string);
			break;
                case V_ASN1_PRINTABLESTRING:
				ret = PKI_STRING_get_parsed (
						a_type->value.printablestring);
			break;
                case V_ASN1_T61STRING:
				ret = PKI_STRING_get_parsed (
						a_type->value.t61string);
			break;
                case V_ASN1_IA5STRING:
				ret = PKI_STRING_get_parsed (
						a_type->value.ia5string);
			break;
                case V_ASN1_GENERALSTRING:
				ret = PKI_STRING_get_parsed (
						a_type->value.generalstring);
			break;
                case V_ASN1_BMPSTRING:
				ret = PKI_STRING_get_parsed (
						a_type->value.bmpstring);
			break;
                case V_ASN1_UNIVERSALSTRING:
				ret = PKI_STRING_get_parsed (
						a_type->value.universalstring);
			break;
                case V_ASN1_VISIBLESTRING:
				ret = PKI_STRING_get_parsed (
						a_type->value.visiblestring);
			break;
                case V_ASN1_UTF8STRING:
				ret = PKI_STRING_get_parsed (
						a_type->value.utf8string);
			break;
                case V_ASN1_UTCTIME:
				ret = PKI_TIME_get_parsed (
						a_type->value.utctime );
			break;
                case V_ASN1_GENERALIZEDTIME:
				ret = PKI_TIME_get_parsed (
						a_type->value.generalizedtime );
			break;
                /* set and sequence are left complete and still
 *                  * contain the set or sequence bytes */
                case V_ASN1_ENUMERATED: // enumerated;
                // case V_ASN1_STRING:	// set;
                // case V_ASN1_STRING:	// sequence;
                // case V_ASN1_VALUE:	// asn1_value;
		default:
			tmp_str = PKI_Malloc ( 100 );
			ret = tmp_str;
	}

	if ( !ret ) ret = strdup ("<Unknown>");

	return ret;
	/*
	if( ASN1_TYPE_get( a_type ) == V_ASN1_PRINTABLESTRING ) {
		ret = strdup ( mem->data );
		PKI_MEM_free ( mem );
		return ret;
	}

	size = mem->size * 3;
	if ((ret = PKI_Malloc ( size )) == NULL ) {
		PKI_log_debug ("Memory Failure!");
		PKI_MEM_free ( mem );
		return NULL;
	}

	count = 0;
	for ( i = 0; i < mem->size; i++ ) {
		sprintf( &ret[count], "%2.2x:", mem->data[i] );
		count += 3;
	} ret[size] = '\x0';

	PKI_MEM_free ( mem );

	return ret;
	*/
}

