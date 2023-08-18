/* Initialization functions */

#include <libpki/pki.h>

#ifdef _LIBPKI_OID_DEFS_H
#include <libpki/openssl/pki_oid_defs.h>
#endif 

#ifdef ENABLE_OQS
# include <libpki/openssl/pqc/pqc_init.h>
#endif

#ifdef ENABLE_COMPOSITE
# include <libpki/openssl/composite/composite_init.h>
#endif

#if OPENSSL_VERSION_NUMBER > 0x3000000fL
#include <openssl/provider.h>
#endif

#ifndef _LIBPKI_ERR_H
#include <libpki/pki_err.h>
#endif

#ifdef ENABLE_COMPOSITE

# ifndef _LIBPKI_COMPOSITE_PKEY_METH_H
#  include <libpki/openssl/composite/composite_pmeth.h>
# endif

#endif // ENABLE_COMPOSITE

#ifdef ENABLE_COMBINED

# ifndef OPENSSL_COMBINED_PKEY_METH_H
#  include <libpki/combined/combined_pmeth.h>
# endif

#ifndef OPENSSL_COMBINED_ASN1_METH_H
#include <libpki/combined/combined_ameth.h>
#endif

#endif // ENABLE_COMBINED

const long LIBPKI_OS_DETAILS = LIBPKI_OS_CLASS | 
		LIBPKI_OS_BITS | LIBPKI_OS_VENDOR;

#include <sys/types.h>
#include <dirent.h>

// Global Vars
static int _libpki_init = 0;
static int _libpki_fips_mode = 0;

// Composite Methods
extern EVP_PKEY_ASN1_METHOD composite_asn1_meth;
extern EVP_PKEY_METHOD composite_pkey_meth;

#if OPENSSL_VERSION_NUMBER < 0x00908000L
int NID_proxyCertInfo = -1;
#endif

#if OPENSSL_VERSION_NUMBER > 0x30000000L
OSSL_PROVIDER * ossl_providers[4] = {
	NULL, // OSSL_PROVIDER_load(OSSL_LIB_CTX_new(), "default"),
	NULL, // OSSL_PROVIDER_load(OSSL_LIB_CTX_new(), "legacy"),
	NULL, // OSSL_PROVIDER_load(OSSL_LIB_CTX_new(), "oqsprovider"),
	NULL
};
#endif

// OpenSSL Library Context
#if OPENSSL_VERSION_NUMBER > 0x30000000L
static OSSL_LIB_CTX * _ossl_lib_ctx = NULL;
#endif


// ================================
// MACRO for Algorithm Registration
// ================================

#ifdef ENABLE_COMBINED
static int _init_combined() {
	
	int combined_id = -1;

	// Let's create the Initial OID for Composite Crypto
	// Retrieves the COMBINED id
	int combined_id = OBJ_txt2nid(OPENCA_ALG_PKEY_ALT_OID);

	// Assigns the generated IDs
	EVP_PKEY_asn1_meth_set_id(&composite_asn1_meth, combined_id);

	// We Need to initialize the ASN1 conversion method
	// https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_ASN1_METHOD.html
	if (!EVP_PKEY_asn1_add0(&combined_asn1_meth)) return 0;

	// We also Need to initialize the PKEY method for the algorithm
	// https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_METHOD.html
	if (!EVP_PKEY_meth_add0(&combined_pkey_meth)) return 0;
	
	// All Done, Success.
	return 1;
}
#endif

/*!
 * \brief Initialize libpki internal structures.
 */
int PKI_init_all( void ) {

	// Initialize OpenSSL so that it adds all 
	// the needed algor and digest
	if( _libpki_init == 0 ) {

		// Enables Logging/Debugging during init
		PKI_log_init (PKI_LOG_TYPE_STDERR, PKI_LOG_INFO,
					  NULL,
                      PKI_LOG_FLAGS_ENABLE_DEBUG,
					  NULL );

		// OpenSSL init
		X509V3_add_standard_extensions();
		OpenSSL_add_all_algorithms();
		OpenSSL_add_all_digests();
		OpenSSL_add_all_ciphers();

		// Pthread Initialization
		OpenSSL_pthread_init();

#if OPENSSL_VERSION_NUMBER < 0x30000000
		ERR_load_ERR_strings();
		ERR_load_crypto_strings();
#endif

		// PKI Discovery Services
		PRQP_init_all_services();

		// SCEP Init
		PKI_X509_SCEP_init();

		// Parser for Config files
		xmlInitParser();

		// Initializes the SSL layer
		SSL_library_init();

		// Initializes the OID layer
		PKI_X509_OID_init();

#if OPENSSL_VERSION_NUMBER >= 0x3000000fL
		// Initializes the OQS Provider layer
		PKI_init_providers();
#endif
#ifdef ENABLE_OQS
		// Post-Quantum Crypto Implementation
		PKI_PQC_init();
#endif
#ifdef ENABLE_COMPOSITE
		// Generic Composite Crypto (both AND and OR)
		PKI_COMPOSITE_init();
		// // Explicit Composite Crypto
		PKI_EXPLICIT_COMPOSITE_init();
#endif
#ifdef ENABLE_COMBINED
		// Multikey Crypto (multi-keys OR)
		_init_combined();
#endif
	}

	/* Enable Proxy Certificates Support */
	PKI_set_env( "OPENSSL_ALLOW_PROXY", "1");

	/* Set the initialization bit */
	_libpki_init = 1;

	/* Check Application and LibPKI coherence */
	if( (LIBPKI_OS_CLASS | LIBPKI_OS_BITS | LIBPKI_OS_VENDOR ) !=
							LIBPKI_OS_DETAILS ) {
		PKI_log_err ("WARNING::LibPKI and Application OS details are "
				"different [%d/%d]", LIBPKI_OS_DETAILS,
				LIBPKI_OS_CLASS | LIBPKI_OS_BITS | 
					LIBPKI_OS_VENDOR);
	};

#ifdef HAVE_MYSQL
	/* MySQL Initialization */
	/* see http://dev.mysql.com/doc/refman/5.0/en/mysql-library-init.html */
	if (mysql_library_init(0, NULL, NULL) != 0)
	{
		/* Let's just log the error - is this a FATAL error ? For now.. no. */
		PKI_log_err("Cound not initialize MySQL library!");
	}
#endif

	/* If FIPS mode is available, let's enforce it by default */
	/*
	if (!PKI_set_fips_mode(1))
	{
		int err_code = HSM_get_errno(NULL);
		PKI_log_err("ERROR: %d while setting Fips Mode: %s", err_code, 
			HSM_get_errdesc(err_code, NULL));
	}
	*/

	return ( PKI_OK );
}

/*!
 * \brief Finalization libpki internal structures.
 */

void PKI_final_all( void )
{
	if ( _libpki_init != 0)
	{
		xmlCleanupParser();
		ERR_free_strings();
		EVP_cleanup();
		OpenSSL_pthread_cleanup();
		OBJ_cleanup();
		EVP_cleanup();
		CRYPTO_cleanup_all_ex_data();
		PKI_cleanup_providers();
#if HAVE_MYSQL
		mysql_library_end();
#endif
	}
}


/*
 * \!brief Sets the underlying crypto library into FIPS mode. Returns 0 in case of failure.
 */
int PKI_set_fips_mode(int k)
{
	// Now let's set the fips mode in the default HSM, if we can not set it, then
	// there is no chance we can operate in FIPS mode - let's report the error.
	// Otherwise, let's use the _libpki_fips_mode variable to keep track of the
	// intended mode for correctly initializing new HSMs
	if (HSM_set_fips_mode(NULL, k) == PKI_ERR)
	{
		PKI_ERROR(PKI_ERR_GENERAL, "Can not set the default (software) HSM in FIPS mode!");

		_libpki_fips_mode = 0;
		return PKI_ERR;
	}

	// Set the internal variable to '1' to indicate that the underlying crypto
	// provided is to operate in FIPS mode only
	_libpki_fips_mode = 1;

	return PKI_OK;
}

/*
 * !\brief Returns true (!0) if libpki is to enforce FIPS mode in HSMs
 */
int PKI_is_fips_mode()
{
	// Checks if the _libpki_fips_mode is set. If this is the case, check that the
	// default crypto provider is also in FIPS mode, if not, let's report that we
	// are not in fips mode (PKI_ERR).
	//
	// If the _libpki_fips_mode is set, instead, check also the default provider
	// so that we get a direct reply from the crypto provider
	if (_libpki_fips_mode != 0) return HSM_is_fips_mode(NULL);
	
	return PKI_ERR;
}

/*! \brief Returns the status of the library (check for initialization) */

int PKI_get_init_status ( void ) {

	if( _libpki_init == 0 ) {
		return PKI_STATUS_NOT_INIT;
	}

	return PKI_STATUS_INIT;
}

/* \brief Returns a stack of the names of all the available tokens */

PKI_STACK * PKI_list_all_tokens ( char *dir ) {

	char *name = NULL;

	PKI_STACK *dir_list = NULL;
	PKI_STACK *list = NULL;
	int i = 0;

	if((dir_list = PKI_CONFIG_get_search_paths( dir )) == NULL ) {
		return ( NULL );
	}

	if((list = PKI_STACK_new_null()) == NULL ) {
		return ( NULL );
	}

	for ( i=0; i <PKI_STACK_elements( dir_list ); i++ ) {
		if((name = PKI_STACK_get_num ( dir_list, i )) != NULL ) {
			PKI_list_all_tokens_dir ( name, list );
		}
		PKI_Free ( name );
	}

	if( dir_list ) PKI_STACK_free ( dir_list );

	return ( list );
}

PKI_STACK * PKI_list_all_tokens_dir ( char * dir, PKI_STACK *list ) {

        struct dirent *dd = NULL;
	DIR *dirp = NULL;
	URL *url = NULL;

	char *token_dir = NULL;
	size_t token_dir_size = 0;

	PKI_STACK *ret = NULL;

	if( !dir ) return ( NULL );

	if(( url = URL_new ( dir )) == NULL ) {
		return (NULL);
	}

	if( url->proto != URI_PROTO_FILE ) {
		if( url ) URL_free (url );
		return (NULL);
	}

	if( !list ) {
		if((ret = PKI_STACK_new_null()) == NULL ) {
			if( url ) URL_free (url );
			return( NULL );
		}
	} else {
		ret = list;
	}

	token_dir_size = strlen(url->addr) + 1 +
				strlen( PKI_DEFAULT_TOKEN_DIR ) + 1;

	token_dir = PKI_Malloc ( token_dir_size );
	snprintf( token_dir, token_dir_size, "%s/%s",
			url->addr, PKI_DEFAULT_TOKEN_DIR );

	PKI_log_debug("PKI_list_all_tokens_dir()::Opening dir %s", token_dir);

	if((dirp = opendir( token_dir )) == NULL ) {

		snprintf( token_dir, token_dir_size, "%s", url->addr );

		PKI_log_debug("PKI_list_all_tokens_dir()::Opening dir %s", token_dir);
		if((dirp = opendir( token_dir)) == NULL ) {
			if( url ) URL_free (url );
			if( token_dir ) PKI_Free ( token_dir );
			return ( ret );
		}
	}

	while(( dd = readdir( dirp )) != NULL ) {
		long len;
		char *filename = NULL;
		PKI_TOKEN *tk = NULL;

		filename = dd->d_name;
		len = (long) strlen( filename );

		if( (len < 4) || (strcmp( ".xml", filename +len -4 ))) {
			continue;
		} else {
			char fullpath[BUFF_MAX_SIZE];
			size_t fullsize = 0;

			PKI_CONFIG *tmp_cfg = NULL;
			char *tmp_name = NULL;

			snprintf(fullpath, BUFF_MAX_SIZE,
				"%s/%s", token_dir, filename );

			if((fullsize = strlen(token_dir) + 
				strlen( filename ) + 1) > 
						BUFF_MAX_SIZE) {
				continue;
			}
				
			if((tmp_cfg = PKI_CONFIG_load( fullpath )) ==
								NULL ) {
				continue;
			}

			if((tmp_name = PKI_CONFIG_get_value( tmp_cfg,
						"/*/name")) != NULL) {

				if((tk = PKI_TOKEN_new_null()) != NULL ) {
					if((PKI_TOKEN_init( tk, token_dir, tmp_name )) != PKI_ERR ) {
						PKI_STACK_push( list, strdup(tmp_name));
					}
					PKI_TOKEN_free( tk );
				}
			}

		}
	}
	closedir( dirp );

	if( url ) URL_free (url);
	if( token_dir ) PKI_Free ( token_dir );

	return ( ret );
}


/* \brief Returns a stack of all the available PKI_TOKENS */

PKI_TOKEN_STACK *PKI_get_all_tokens ( char *dir ) {
	char *name = NULL;

	PKI_STACK *dir_list = NULL;
	PKI_TOKEN_STACK *list = NULL;
	int i = 0;

	if((dir_list = PKI_CONFIG_get_search_paths( dir )) == NULL ) {
		return ( NULL );
	}

	if ((list = PKI_STACK_TOKEN_new()) == NULL) {
		return ( NULL );
	}

	for ( i=0; i <PKI_STACK_elements( dir_list ); i++ ) {
		if((name = PKI_STACK_get_num ( dir_list, i )) != NULL ) {
			PKI_get_all_tokens_dir ( name, list );
		}
		PKI_Free ( name );
	}

	if( dir_list ) PKI_STACK_free ( dir_list );

	return ( list );
}

PKI_TOKEN_STACK *PKI_get_all_tokens_dir ( char *dir, PKI_TOKEN_STACK *list ) {

	struct dirent *dd = NULL;
	DIR *dirp = NULL;
	URL *url = NULL;

	char *token_dir = NULL;
	size_t token_dir_size = 0;

	PKI_TOKEN_STACK *ret = NULL;

	if( !dir ) return ( NULL );

	if(( url = URL_new ( dir )) == NULL ) {
		return (NULL);
	}

	if( url->proto != URI_PROTO_FILE ) {
		if( url ) URL_free (url );
		return (NULL);
	}

	if( !list ) {
		if((ret = PKI_STACK_TOKEN_new()) == NULL ) {
			if( url ) URL_free (url );
			return( NULL );
		}
	} else {
		ret = list;
	}

	token_dir_size = strlen(url->addr) + 1 +
				strlen( PKI_DEFAULT_TOKEN_DIR ) + 1;

	token_dir = PKI_Malloc ( token_dir_size );
	snprintf( token_dir, token_dir_size, "%s/%s",
			url->addr, PKI_DEFAULT_TOKEN_DIR );

	PKI_log_debug("PKI_list_all_tokens_dir()::Opening dir %s", token_dir);

	if((dirp = opendir( token_dir )) == NULL ) {

		snprintf( token_dir, token_dir_size, "%s", url->addr );

		PKI_log_debug("PKI_list_all_tokens_dir()::Opening dir %s", token_dir);
		if((dirp = opendir( token_dir)) == NULL ) {
			if( url ) URL_free (url );
			if( token_dir ) PKI_Free ( token_dir );
			return ( ret );
		}
	}

	while(( dd = readdir( dirp )) != NULL ) {
		long len;
		char *filename = NULL;
		PKI_TOKEN *tk = NULL;

		filename = dd->d_name;
		len = (long) strlen( filename );

		if( (len < 4) || (strcmp( ".xml", filename +len -4 ))) {
			continue;
		} else {
			char fullpath[BUFF_MAX_SIZE];
			size_t fullsize = 0;

			PKI_CONFIG *tmp_cfg = NULL;
			char *tmp_name = NULL;

			snprintf(fullpath, BUFF_MAX_SIZE,
				"%s/%s", token_dir, filename );

			if((fullsize = strlen(token_dir) + 
				strlen( filename ) + 1) > 
						BUFF_MAX_SIZE) {
				continue;
			}
				
			if((tmp_cfg = PKI_CONFIG_load( fullpath )) ==
								NULL ) {
				continue;
			}

			if((tmp_name = PKI_CONFIG_get_value( tmp_cfg,
						"/*/name")) != NULL) {

				if((tk = PKI_TOKEN_new_null()) != NULL ) {
					if((PKI_TOKEN_init( tk, dir, tmp_name )) != PKI_ERR ) {
						PKI_STACK_TOKEN_push( list, tk);
					} else {
						PKI_TOKEN_free( tk );
					}
				}
			}

		}
	}
	closedir( dirp );

	if( url ) URL_free (url);
	if( token_dir ) PKI_Free ( token_dir );

	return ( ret );
}

/*! \brief Returns a stack of all the available Identities */
PKI_ID_INFO_STACK * PKI_list_all_id ( void ) {
	PKI_log_debug("%s:%d::Sorry, code still missing!",__FILE__,__LINE__);
	return ( NULL );
}

int PKI_init_providers(void) {

	OSSL_PROVIDER* provider = NULL;
		// Internal pointer

	OSSL_LIB_CTX * lib_ctx = PKI_init_get_ossl_library_ctx();
		// OpenSSL Library Context

	// Loads the Default Provider
	if (ossl_providers[0] == NULL) {
		provider = OSSL_PROVIDER_load(lib_ctx, "default");
		if (provider == NULL) {
			fprintf(stderr, "Failed to load Default provider\n");
			return 0;
		}
	}

	// Loads the Legacy Provider
	if (ossl_providers[1] == NULL) {
		provider = OSSL_PROVIDER_load(lib_ctx, "legacy");
		if (provider == NULL) {
			fprintf(stderr, "Failed to load Default provider\n");
			return 0;
		}
	}

#ifdef ENABLE_OQSPROV

	// Loads the OQS Provider
	if (ossl_providers[2] == NULL) {
		provider = OSSL_PROVIDER_load(lib_ctx, "oqsprovider");
		if (provider == NULL) {
			fprintf(stderr, "Failed to load Default provider\n");
			return 0;
		}
	}

#endif

	// All Done
	return 1;
}

int PKI_cleanup_providers(void) {

	// Unloads all the providers
	for (int i = 0; ossl_providers[i] != NULL; i++) {
		OSSL_PROVIDER_unload(ossl_providers[i]);
	}

	// All Done
	return 1;
}

#if OPENSSL_VERSION_NUMBER > 0x3000000fL
OSSL_LIB_CTX * PKI_init_get_ossl_library_ctx() {
	if (_ossl_lib_ctx == NULL) {
		_ossl_lib_ctx = OSSL_LIB_CTX_new();
	}
	if (!_ossl_lib_ctx) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}
	return _ossl_lib_ctx;
}
#else
void * PKI_init_get_ossl_library_ctx() {
	PKI_DEBUG("Function not implemented for OpenSSL < 3.0.0");
	return NULL;
}
#endif