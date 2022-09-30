/* Initialization functions */

#include <libpki/pki.h>

#ifdef _LIBPKI_OID_DEFS_H
#include <libpki/openssl/pki_oid_defs.h>
#endif 

#ifdef ENABLE_COMPOSITE

#ifndef OPENSSL_COMPOSITE_PKEY_METH_H
#include <libpki/composite/composite_pmeth.h>
#endif

#ifndef OPENSSL_COMPOSITE_ASN1_METH_H
#include <libpki/composite/composite_ameth.h>
#endif

#endif // ENABLE_COMPOSITE

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

#if OPENSSL_VERSION_NUMBER < 0x00908000
int NID_proxyCertInfo = -1;
#endif

// static char *libpki_oids[] = {
// 	// OpenCA PEN
// 	"1.3.6.1.4.1.18227", "openca", "OpenCA Labs Private Enterprise Name",
// 	/* MS Extension - Used for Profile Requesting in Cert Reqs */
// 	"1.3.6.1.4.1.311.20.2", "certificateTemplate", "Certificate Template",
// 	/* OID - {{1.3.6.1.4.1.18227 (OpenCA)} . 50 (Extensions)} */
// 	"1.3.6.1.4.1.18227.50.1", "loa", "Level of Assurance",
// 	"1.3.6.1.4.1.18227.50.2", "certificateUsage", "Certificate Usage",
// 	NULL, NULL, NULL
// };

// typedef struct obj_alias_st {
// 	int nid;
// 	const char *name;
// 	const char *oid;
// } LIBPKI_OBJ_ALIAS;

// #ifdef ENABLE_ECDSA
// static struct obj_alias_st nist_curves_alias[] = {
// 	/* prime field curves */
// 	{ NID_P192, "P192", "1.2.840.10045.3.1.1" },
// 	{ NID_P224, "P224", "1.3.132.0.33" },
// 	{ NID_P256, "P256", "1.2.840.10045.3.1.7" },
// 	{ NID_P384, "P384", "1.3.132.0.34" },
// 	{ NID_P521, "P521", "1.3.132.0.35" },

// 	/* characteristic two field curves */
// 	{ NID_K163, "K163", "1.3.132.0.1" },
// 	{ NID_K233, "K233", "1.3.132.0.26" },
// 	{ NID_K283, "K283", "1.3.132.0.16" },
// 	{ NID_K409, "K409", "1.3.132.0.36" },
// 	{ NID_K571, "K571", "1.3.132.0.38" },

// 	{ NID_B163, "B163", "1.3.132.0.15" },
// 	{ NID_B233, "B233", "1.3.132.0.27" },
// 	{ NID_B283, "B283", "1.3.132.0.17" },
// 	{ NID_B409, "B409", "1.3.132.0.37" },
// 	{ NID_B571, "B571", "1.3.132.0.39" },

// 	{ -1, NULL, NULL },
// };
// #endif

// static int __create_object_with_id ( const char *oid, const char *sn, 
// 		const char *ln, int id) {
// 	int ret = PKI_OK;
// 	unsigned char *buf;
// 	int i;

// 	ASN1_OBJECT *obj=NULL;

// 	if ( id < 0 ) {
// 		id = OBJ_new_nid(1);
// 	};

//     if((i = a2d_ASN1_OBJECT(NULL,0,oid,-1)) <= 0 ) {
// 		return PKI_ERR;
// 	};

//     if((buf=(unsigned char *)OPENSSL_malloc((size_t)i)) == NULL) {
//         return PKI_ERR;
// 	}

//     if((i=a2d_ASN1_OBJECT(buf,i,oid,-1)) == 0 ) {
//         goto err;
// 	}

//     if((obj=(ASN1_OBJECT *)ASN1_OBJECT_create(id,buf,i,sn,ln)) == 0 ) {
//         goto err;
// 	}

//     ret = OBJ_add_object(obj);

// err:
//     ASN1_OBJECT_free(obj);
//     OPENSSL_free(buf);

// 	if( ret == 0 ) return PKI_ERR;

// 	return PKI_OK;
// }

// static int __init_add_libpki_oids ( void ) {
// 	int i, ret;

// 	i = 0;

// 	while( libpki_oids[i] && libpki_oids[i+1] && libpki_oids[i+2] ) {
// 		if((ret = OBJ_create(libpki_oids[i], libpki_oids[i+1], 
// 				libpki_oids[i+2])) == NID_undef) {
// 			return 0;
// 		}
// 		i = i+3;
// 	}

// 	/* Special Case for proxyCertInfo NID */
// #if OPENSSL_VERSION_NUMBER < 0x00908000
// 	NID_proxyCertInfo = OBJ_create( "1.3.6.1.5.5.7.1.14", 
// 			"proxyCertInfo", "Proxy Certificate Information");
// #endif

// #ifdef ENABLE_ECDSA
// 	for ( i = 0; nist_curves_alias[i].name; i++ ) {
// 		PKI_OID *oid = NULL;
// 		char buf[2048];

// 		if( nist_curves_alias[i].oid ) {
// 			oid = PKI_OID_get( (char *) nist_curves_alias[i].oid );
// 		} else {
// 			oid = PKI_OID_new_id( nist_curves_alias[i].nid );
// 		}
		
// 		if (!oid) continue;

// 		OBJ_obj2txt(buf, sizeof(buf), oid, 1);
// 		PKI_OID_free ( oid );

// 		if( __create_object_with_id ( buf, nist_curves_alias[i].name, 
// 				nist_curves_alias[i].name, 
// 				nist_curves_alias[i].nid ) == PKI_ERR ) {
// 				// Error while adding "easy" names for NIST curves
// 		};
// 	};
// #endif

// 	return PKI_OK;
// }

#ifdef ENABLE_COMPOSITE
static int _init_composite() {

	// int composite_id = -1;

	// typedef struct comp_digest_st {
	// 	int sigid;
	// 	int dgst;
	// } COMP_DIGEST;

	// COMP_DIGEST comp_digest[8] = { 0x0 };

	// // Let's create the Initial OID for Composite Crypto
	// if ((composite_id = OBJ_create(PKI_X509_COMPOSITE_KEY_OID, PKI_X509_COMPOSITE_KEY_NAME, PKI_X509_COMPOSITE_KEY_DESC)) == NID_undef) {
	// 	// Error Condition
	// 	return 0;
	// };

	// // Signature Algoritms OIDs
	// comp_digest[0].sigid = OBJ_create("1.3.6.1.4.1.18277.2.2.1", "compositeWithNoHash", "Composite Signature With No Hash");
	// comp_digest[0].dgst = NID_undef;
	// comp_digest[1].sigid = OBJ_create("1.3.6.1.4.1.18277.2.2.2", "compositeWithSha256", "Composite Signature With SHA2-256");
	// comp_digest[1].dgst = PKI_ALGOR_ID_SHA256;
	// comp_digest[2].sigid = OBJ_create("1.3.6.1.4.1.18277.2.2.3", "compositeWithSha384", "Composite Signature With SHA2-384");
	// comp_digest[2].dgst = PKI_ALGOR_ID_SHA384;
	// comp_digest[3].sigid = OBJ_create("1.3.6.1.4.1.18277.2.2.4", "compositeWithSha512", "Composite Signature With SHA2-512");
	// comp_digest[3].dgst = PKI_ALGOR_ID_SHA512;
	// comp_digest[4].sigid = OBJ_create("1.3.6.1.4.1.18277.2.2.5", "compositeWithSha3At256", "Composite Signature With SHA3-256");
	// comp_digest[4].dgst = NID_sha3_256;
	// comp_digest[5].sigid = OBJ_create("1.3.6.1.4.1.18277.2.2.6", "compositeWithSha3At384", "Composite Signature With SHA3-384");
	// comp_digest[5].dgst = NID_sha3_384;
	// comp_digest[6].sigid = OBJ_create("1.3.6.1.4.1.18277.2.2.7", "compositeWithSha3At512", "Composite Signature With SHA3-512");
	// comp_digest[6].dgst = NID_sha3_512;
	// comp_digest[7].sigid = 0;
	// comp_digest[7].sigid = 0;

	// // Signature Algorithms
	// int idx = 0;
	// while (comp_digest[idx].sigid != NID_undef) {
	// 	OBJ_add_sigid(comp_digest[idx].sigid, comp_digest[idx].dgst, composite_id);
	// 	// printf("[DEBUG] %d: Adding Sig Algor (%d => hash: %d, pkey: %d)\n",
	// 	// 	idx, comp_digest[idx].sigid, comp_digest[idx].dgst, NID_composite);
	// 	idx++;
	// }

	// TODO:
	// =====
	//
	// Update the way we add the composite ASN1 method. Currently we use the
	// auxillary function (see composite_ameth.c) to set the method's pkey id.
	//
	// The Right way to add a new method would be to first generate a new
	// one and then set the different callbacks, such as:
	//
	//   composite_asn1_method = EVP_PKEY_asn1_meth_new(NID_composite);
	//   EVP_PKEY_asn1_meth_set_XXX(composite_asn1_method, .... );

	// Retrieves the COMPOSITE id
	int composite_id = OBJ_txt2nid(OPENCA_ALG_PKEY_COMP_OID);

	// Assigns the generated IDs
	EVP_PKEY_asn1_meth_set_id(&composite_asn1_meth, composite_id);

	// We also Need to initialize the PKEY method for the algorithm
	// https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_METHOD.html
	if (!EVP_PKEY_meth_add0(&composite_pkey_meth)) return 0;

	// We Need to initialize the ASN1 conversion method
	// https://www.openssl.org/docs/man1.1.1/man3/EVP_PKEY_ASN1_METHOD.html
	if (!EVP_PKEY_asn1_add0(&composite_asn1_meth)) return 0;
	
	// All Done, Success.
	return 1;
}
#endif

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
	
	printf("[DEBUG] Combined EVP_PKEY_asn1 and EVP_PKEY methods added successfully!\n");

	// All Done, Success.
	return 1;
}
#endif

#ifdef ENABLE_COMBINED
SSL3_CK_DH_DSS_DES_192_CBC3_SHA

#endif

// static int _list_all_tokens_dir ( char * dir, PKI_STACK *list );

/*!
 * \brief Initialize libpki internal structures.
 */
int PKI_init_all( void ) {

	// Initialize OpenSSL so that it adds all 
	// the needed algor and digest
	if( _libpki_init == 0 ) {
		X509V3_add_standard_extensions();
		OpenSSL_add_all_algorithms();
		OpenSSL_add_all_digests();
		OpenSSL_add_all_ciphers();
		OpenSSL_pthread_init();

		ERR_load_ERR_strings();
		ERR_load_crypto_strings();

		PRQP_init_all_services();
		PKI_X509_SCEP_init();
		xmlInitParser();

		SSL_library_init();

		// __init_add_libpki_oids ();

		// Initializes the extra OIDs
		PKI_X509_OID_init();

#ifdef ENABLE_COMPOSITE
		_init_composite();
#endif
#ifdef ENABLE_COMBINED
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

