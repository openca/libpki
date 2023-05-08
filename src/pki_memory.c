/* OpenCA libpki package
* (c) 2000-2007 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#include <libpki/pki_memory.h>

// =====================
// Core Memory Functions
// =====================

/*! \brief Allocates size bytes of memory, zeroize it, and returns the pointer
 *         to the beginning of the memory region
 */

void *PKI_Malloc( size_t size )
{
	void *ret = NULL;

	// Checks we have a sensitive size to malloc
	if ( size == 0 ) return NULL;

	// Allocates and zeroize memory (this might prevent
	// some cross-process / cross-thread information leaking)
#ifdef HAVE_CALLOC
	ret = calloc(1, size);
#else
	if ((ret = (void *) malloc( size )) != NULL)
		memset(ret, 0, size );
#endif

	// Returns the pointer to the allocated memory
	return (ret);
}

/*! \brief Frees memory associated with a pointer (allocated with PKI_Malloc) */

void PKI_Free( void *ret )
{
	// Checks we have a valid pointer
	if( ret == NULL ) return;
	
	// Frees the associated memory
	free ( ret );

	return;
}

/*! \brief Frees and Zeroizes memory associated with a pointer */

void PKI_ZFree ( void *pnt, size_t size ) {

	/* Check the Input */
	if (!pnt) return;

	/* If No size is provided, normal PKI_Free() is used */
	if ( size <= 0 ) return PKI_Free ( pnt );

	/* Zeroize the Memory */
	memset( pnt, '\xFF', size );

	/* Free The Memory */
	PKI_Free ( pnt );

	return;
}

/*! \brief Frees and Zeroizes memory associated with a string */

void PKI_ZFree_str ( char *str ) {

	if ( str == NULL ) return;

	/* Wipe the String's Memory */
	memset( str, '\xFF', strlen(str));

	PKI_Free ( str );

	return;
}

