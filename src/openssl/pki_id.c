/* ID management for libpki */

#include <libpki/pki.h>

/*!
 * \brief Create a new ID object
 *
 * Create a new ID by using its name. It returns an int
 * if successful, otherwise it returns NULL
 */

PKI_ID PKI_ID_get_by_name ( char *name ) {

	int ret = PKI_ID_UNKNOWN;

	if( !name ) return ( PKI_ID_UNKNOWN );

	/* Check if the object already exists */
	if( (ret = OBJ_sn2nid(name)) == PKI_ID_UNKNOWN) {
		ret = OBJ_ln2nid(name);
	}

	return ( ret );
}

/*!
 * \brief Checks if a PKI IDentifier exists
 *
 * This function retrieves an ID generated from the passed ID, if the ID
 * does not exist in the library database, it returns PKI_ID_UNKNOWN.
 *
 * Basically it checks if it exists or not.
 */

PKI_ID PKI_ID_get( PKI_ID id ) {

	PKI_OID *obj = NULL;

	/* Check if the object already exists */
	if( (obj = OBJ_nid2obj( id )) == NULL ) {
		return ( PKI_ID_UNKNOWN );
	}

	/* Free the memory */
	ASN1_OBJECT_free ( obj );

	/* The ID exists, let's return it */
	return ( id );
}

const char * PKI_ID_get_txt( PKI_ID id ) {

	return ( OBJ_nid2sn( id ) );
	
}

