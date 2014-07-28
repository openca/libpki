/* OID management for libpki */

#include <libpki/pki.h>

PKI_CONFIG * PKI_OID_load ( char *uri ) {
	PKI_CONFIG *oidConf = NULL;

	if(( oidConf = PKI_CONFIG_load ( uri )) == NULL ) {
		return NULL;
	}

	return oidConf;
}


/*!
 * \brief Create a new OID object
 *
 * Create a new OID by using its name. It returns a PKI_OID
 * pointer if successful, otherwise it returns NULL
 */

PKI_OID *PKI_OID_new( char *oid, char *name, char *descr ) {
	PKI_OID *ret = NULL;
	int nid = NID_undef;

	if( !oid && !name && !descr ) return NULL;

	/* Check if the object already exists */
	if( ((nid = OBJ_sn2nid(name)) != NID_undef) ||
		((nid = OBJ_ln2nid(name)) != NID_undef) )
			ret = OBJ_nid2obj(nid);

	if(!ret) {
		/* If it does not exists, then create it */
		(void) OBJ_create( oid, name, descr );

		if( ((nid = OBJ_sn2nid(name)) != NID_undef) ||
			((nid = OBJ_ln2nid(name)) != NID_undef) )
				ret = OBJ_nid2obj(nid);
	}

	/* If successful it returns the new Object, otherwise it
	   return NULL */
	return ( ret );
}

/*! \brief Returns the OID associated with a PKI_ID */

PKI_OID *PKI_OID_new_id ( PKI_ID id ) {
	PKI_OID *oid = NULL;

	oid = OBJ_nid2obj(id);

	return ( oid );
}

/*!
 * \brief Free memory associated with a PKI_OID structure
 *
 * This function frees the memory associated with the provided
 * pointer to a PKI_OID structure.
 */

void PKI_OID_free ( PKI_OID *oid ) {

	if( !oid ) return;

	ASN1_OBJECT_free ( oid );

	return;
}

void PKI_OID_free_void ( void *buf ) {
	if( !buf ) return;
	PKI_OID_free( (PKI_OID *) buf);
}

/*! \brief See PKI_OID_new_text. */

PKI_OID *PKI_OID_get( char *name ) {
	return PKI_OID_new_text ( name );
}

/*!
 * \brief Retrieve a pointer to an OID
 *
 * This function retrieves an OID pointer from the passed name.
 * Check also the configuration options.
 */

PKI_OID *PKI_OID_new_text ( char *name ) {

	PKI_OID *ret = NULL;

	if ( !name ) return ( NULL );

	ret = OBJ_txt2obj ( name, 0 );

	/* Check if the object already exists */
	/*
	if( ((nid = OBJ_sn2nid(name)) != NID_undef) ||
		((nid = OBJ_ln2nid(name)) != NID_undef) )
			ret = OBJ_nid2obj(nid);
	*/

	return( ret );
}

/*!
 * \brief Returns a duplicate of the passed PKI_OID structure
 */

PKI_OID *PKI_OID_dup( PKI_OID *a ) {
	PKI_OID *ret = NULL;

	if( !a ) return ( NULL );

	ret = OBJ_dup( a );
	return ( ret );
}

/*!
 * \brief Compares two PKI_OID and returns 0 if they match
 */

int PKI_OID_cmp( PKI_OID *a, PKI_OID *b ) {

	if ( !a || !b ) {
		return(-1);
	}

	return ( OBJ_cmp ( a, b ));
}

/*! \brief Returns the PKI_ID of the object if recognized */

PKI_ID PKI_OID_get_id ( PKI_OID *a ) {

	PKI_ID ret = PKI_ID_UNKNOWN;

	if ( !a ) return ( ret );

	ret = OBJ_obj2nid ( a );

	if( ret == NID_undef ) {
		return PKI_ID_UNKNOWN;
	}

	return ret;
}

/*! \brief Return the description associated with a PKI_OID object */

const char * PKI_OID_get_descr ( PKI_OID *a ) {

	int nid;

        if( !a ) return ("Unknown");

        nid = PKI_OID_get_id( a );

        if( nid != NID_undef ) {
                return ( OBJ_nid2ln( nid ) );
        }

	return ("Unknown");
}

/*! \brief Returns a new allocated string representation of an OID */

char * PKI_OID_get_str ( PKI_OID *a ) {

	char *ret = NULL;
	BUF_MEM *buf_mem = NULL;
	BIO *mem = NULL;

	/* Check the Input */
	if( !a ) return NULL;

	if((mem = BIO_new(BIO_s_mem())) == NULL ) {
		return ( NULL );
	}

	i2a_ASN1_OBJECT( mem, a );

	/* Copy the data from the BIO to the PKI_MEM structure */
	BIO_get_mem_ptr(mem, &buf_mem);

	if( ( ret = PKI_Malloc ( (size_t) (buf_mem->length + 1))) == NULL ) {
		BIO_free_all( mem );
		return ( NULL );
	}

	memcpy(ret, buf_mem->data, (size_t) buf_mem->length );
	ret[buf_mem->length] = '\x0';

	BIO_free_all ( mem );

	return ( ret );
}
