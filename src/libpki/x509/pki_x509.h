/* PKI_X509 object management */

#ifndef _LIBPKI_HSM_MAIN_H
#include <libpki/crypto/hsm/hsm.h>
#endif

#ifndef _LIBPKI_CRYPTO_TYPES_H
#include <libpki/x509/types.h>
#endif

#ifndef _LIBPKI_PKI_X509_H
#define _LIBPKI_PKI_X509_H


// ===================
// Function Prototypes
// ===================

/*! \brief Allocates A New X509 structure
 *
 * This function allocates a new PKI_X509 structure and returns a pointer to it.
 * The type parameter is used to specify the type of the PKI_X509 object to be
 * created. The hsm parameter is used to specify the HSM to be used with the
 * PKI_X509 object. If the hsm parameter is NULL, the default HSM will be used.
 * 
 * @param type The type of the PKI_X509 object to be created
 * @param hsm The HSM to be used with the PKI_X509 object
 * @return A pointer to the newly created PKI_X509 object
 */
PKI_X509 *PKI_X509_new(PKI_TYPE type, PKI_X509 *hsm);

/*! \brief Allocates A New PKI_X509 structure by using the passed value
 *
 * This function allocates a new PKI_X509 structure and returns a pointer to it.
 * The type parameter is used to specify the type of the PKI_X509 object to be
 * created. The data parameter is used to specify the value to be used with the
 * PKI_X509 object. The hsm parameter is used to specify the HSM to be used with
 * the PKI_X509 object. If the hsm parameter is NULL, the default HSM will be used.
 * 
 * @param type The type of the PKI_X509 object to be created
 * @param data The value to be used with the PKI_X509 object
 * @param hsm The HSM to be used with the PKI_X509 object
 * @return A pointer to the newly created PKI_X509 object
 */
PKI_X509 *PKI_X509_new_value(PKI_TYPE type, void *data, HSM *hsm);

/*! \brief Allocates A New PKI_X509 structure by duplicating the passed value
 *
 * This function allocates a new PKI_X509 structure and returns a pointer to it.
 * The type parameter is used to specify the type of the PKI_X509 object to be
 * created. The data parameter is used to specify the value to be used with the
 * PKI_X509 object. The hsm parameter is used to specify the HSM to be used with
 * the PKI_X509 object. If the hsm parameter is NULL, the default HSM will be used.
 * 
 * @param type The type of the PKI_X509 object to be created
 * @param data The value to be used with the PKI_X509 object
 * @param hsm The HSM to be used with the PKI_X509 object
 * @return A pointer to the newly created PKI_X509 object
 * @see PKI_X509_new_value
 */
PKI_X509 *PKI_X509_new_dup_value(PKI_TYPE type, const void *data, HSM *hsm);

/*! \brief Frees the PKI_X509 object
 *
 * This function frees the PKI_X509 object and all of its associated memory.
 * 
 * @param x A pointer to the PKI_X509 object to be freed
 */
void PKI_X509_free_void(void *x);

/*! \brief Frees the PKI_X509 object
 *
 * This function frees the PKI_X509 object and all of its associated memory.
 * 
 * @param x A pointer to the PKI_X509 object to be freed
 */
void PKI_X509_free(PKI_X509 *x);

/*! \brief Sets the HSM for the PKI_X509 object
 *
 * This function sets the HSM for the PKI_X509 object.
 * 
 * @param x A pointer to the PKI_X509 object
 * @param hsm A pointer to the HSM object
 * @return PKI_OK if successful, PKI_ERR otherwise
 */
int PKI_X509_set_hsm ( PKI_X509 *x, struct hsm_st *hsm );

/*! \brief Returns the HSM for the PKI_X509 object
 *
 * This function returns the HSM for the PKI_X509 object.
 * 
 * @param x A pointer to the PKI_X509 object
 * @return A pointer to the HSM object
 */
struct hsm_st *PKI_X509_get_hsm (const PKI_X509 *x );

/*! \brief Sets the reference URL for the PKI_X509 object
 *
 * This function sets the reference URL for the PKI_X509 object.
 * 
 * @param x A pointer to the PKI_X509 object
 * @param url A pointer to the URL object
 * @return PKI_OK if successful, PKI_ERR otherwise
 */
int PKI_X509_set_reference ( PKI_X509 *x, URL *url );

/*! \brief Returns the reference URL for the PKI_X509 object
 *
 * This function returns the reference URL for the PKI_X509 object.
 * 
 * @param x A pointer to the PKI_X509 object
 * @return A pointer to the URL object
 */
URL *PKI_X509_get_reference (const PKI_X509 *x );

/*! \brief Duplicates the PKI_X509 object
 *
 * This function duplicates the PKI_X509 object and returns a pointer to the new object.
 * 
 * @param x A pointer to the PKI_X509 object to be duplicated
 * @return A pointer to the duplicated PKI_X509 object
 */
PKI_X509 * PKI_X509_dup (const PKI_X509 *x );

/*! \brief Duplicates the value of the PKI_X509 object
 *
 * This function duplicates the value of the PKI_X509 object and returns a pointer to the new object.
 * 
 * @param x A pointer to the PKI_X509 object
 * @return A pointer to the duplicated value
 */
void * PKI_X509_dup_value (const PKI_X509 *x );

/*! \brief Sets the value of the PKI_X509 object
 *
 * This function sets the value of the PKI_X509 object.
 * 
 * @param x A pointer to the PKI_X509 object
 * @param data A pointer to the value to be set
 * @return PKI_OK if successful, PKI_ERR otherwise
 */
void * PKI_X509_get_value (const PKI_X509 *x );

/*! \brief Sets the value of the PKI_X509 object
 *
 * This function sets the value of the PKI_X509 object.
 * 
 * @param x A pointer to the PKI_X509 object
 * @param data A pointer to the value to be set
 * @return PKI_OK if successful, PKI_ERR otherwise
 */
int PKI_X509_set_value ( PKI_X509 *x, void *data );

/*! \brief Returns the type of the PKI_X509 object
 *
 * This function returns the type of the PKI_X509 object.
 * 
 * @param x A pointer to the PKI_X509 object
 * @return The type of the PKI_X509 object
 */
PKI_TYPE PKI_X509_get_type (const PKI_X509 *x );

/*! \brief Returns the type of the PKI_X509 object as a string
 *
 * This function returns the type of the PKI_X509 object as a string.
 * 
 * @param x A pointer to the PKI_X509 object
 * @return The type of the PKI_X509 object as a string
 */
const char * PKI_X509_get_type_parsed (const PKI_X509 *x );

/*! \brief Returns the pointer to the requested data in the PKI_X509 object
 *
 * This function returns the pointer to the requested data in the PKI_X509 object.
 * 
 * @param x A pointer to the PKI_X509 object
 * @return The type of the PKI_X509 data to be returned
 * @return The pointer to the requested data in the PKI_X509 object
 * @see PKI_X509_DATA
 */
void * PKI_X509_get0 (const PKI_X509 *x, PKI_X509_DATA type );

/*! \brief Returns a copy of the specified data in the PKI_X509 object
 *
 * This function returns a copy of the specified data in the PKI_X509 object.
 * The caller will be responsible for freeing the returned data.
 * 
 * @param x A pointer to the PKI_X509 object
 * @return A copy of the specified data in the PKI_X509 object
 * @see PKI_X509_DATA
 */
void * PKI_X509_get (const PKI_X509 *x, PKI_X509_DATA type );

/*! \brief Returns the parsed data from a PKI_X509 object
 *
 * This function returns the parsed data from a PKI_X509 object.
 * The caller will be responsible for freeing the returned data.
 * 
 * @param x A pointer to the PKI_X509 object
 * @param type The type of the PKI_X509 data to be returned
 * @return The parsed data from the PKI_X509 object
 * @see PKI_X509_DATA
 */
void * PKI_X509_get_parsed (const PKI_X509 *x, PKI_X509_DATA type );

/*! \brief Prints the parsed data from a PKI_X509 object
 *
 * This function prints the parsed data from a PKI_X509 object.
 * 
 * @param x A pointer to the PKI_X509 object
 * @param type The type of the PKI_X509 data to be printed
 * @param fd The file descriptor to which the data will be printed
 * @return PKI_OK if successful, PKI_ERR otherwise
 * @see PKI_X509_DATA
 */
int PKI_X509_print_parsed (const PKI_X509 *x, PKI_X509_DATA type, int fd );

/*! \brief Deletes the PKI_X509 object pointed by the reference field
 *
 * This function deletes the PKI_X509 object by calling the corresponding
 * calback function in the associated HSM. If the HSM is not set, the default
 * callback function will be used.
 * 
 * @param x A pointer to the PKI_X509 object to be deleted
 * @return PKI_OK if successful, PKI_ERR otherwise
 */
int PKI_X509_delete(PKI_X509 *x);

/*! \brief Take ownership of the passed data and set it into the PKI_X509 object
 *
 * This function takes ownership of the passed data and sets it into the PKI_X509 object.
 * 
 * @param x A pointer to the PKI_X509 object
 * @param type The type of the PKI_X509 data to be set
 * @param data A pointer to the data to be set
 * @param hsm A pointer to the HSM object
 * @return PKI_OK if successful, PKI_ERR otherwise
 * @see PKI_X509_DATA
 */
int PKI_X509_attach(PKI_X509 * x, PKI_TYPE type, void * data, HSM * hsm);

/*! \brief Detach the data from the PKI_X509 object and return it
 *
 * This function detaches the data from the PKI_X509 object and returns it.
 * The caller will be responsible for freeing the returned data.
 * 
 * @param x A pointer to the PKI_X509 object
 * @param data A pointer to the data to be returned
 * @param type The type of the PKI_X509 data to be returned
 * @param hsm A pointer to the HSM object
 * @return PKI_OK if successful, PKI_ERR otherwise
 * @see PKI_X509_DATA
 */
int PKI_X509_detach(PKI_X509 * x, void ** data, PKI_TYPE * type, HSM **hsm);

/*! \brief Set the AUX data into the PKI_X509 object
 *
 * This function sets auxillary data into the PKI_X509 object
 * that is preserved across the PKI_X509 object's lifecycle.
 * 
 * @param x A pointer to the PKI_X509 object
 * @param data A pointer to the data to be set
 * @param data_free_func A pointer to the function that will free the data
 * @param data_dup_func A pointer to the function that will duplicate the data
 * @return PKI_OK if successful, PKI_ERR otherwise
 */
int PKI_X509_aux_data_set (PKI_X509 * x,
	                         void     * data, 
	                         void       (*data_free_func)(void *),
	                         void     * (*data_dup_func )(void *));

/*! \brief Get the AUX data from the PKI_X509 object
 *
 * This function gets auxillary data from the PKI_X509 object
 * that is preserved across the PKI_X509 object's lifecycle.
 * 
 * @param x A pointer to the PKI_X509 object
 * @return A pointer to the auxillary data
 */
void * PKI_X509_aux_data_get(PKI_X509 * x);

/*! \brief Duplicate the AUX data from the PKI_X509 object
 *
 * This function duplicates the auxillary data from the PKI_X509 object
 * that is preserved across the PKI_X509 object's lifecycle.
 * 
 * @param x A pointer to the PKI_X509 object
 * @return A pointer to the duplicated auxillary data
 */
void * PKI_X509_aux_data_dup(PKI_X509 * x);

/*! \brief Delete the AUX data from the PKI_X509 object
 *
 * This function deletes the auxillary data from the PKI_X509 object
 * that is preserved across the PKI_X509 object's lifecycle.
 * 
 * @param x A pointer to the PKI_X509 object
 * @return PKI_OK if successful, PKI_ERR otherwise
 */
int PKI_X509_aux_data_del(PKI_X509 * x);

// /*! \brief Set the status of the PKI_X509 object
//  *
//  * This function sets the status of the PKI_X509 object.
//  * 
//  * @param x A pointer to the PKI_X509 object
//  * @param status The status to be set
//  * @return PKI_OK if successful, PKI_ERR otherwise
//  */
// int PKI_X509_set_status(PKI_X509 *x, int status);

// /*! \brief Get the status of the PKI_X509 object
//  *
//  * This function gets the status of the PKI_X509 object.
//  * 
//  * @param x A pointer to the PKI_X509 object
//  * @return The status of the PKI_X509 object
//  */
// int PKI_X509_get_status(PKI_X509 *x);

#endif
