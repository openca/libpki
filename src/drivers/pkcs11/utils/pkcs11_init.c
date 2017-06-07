
/* General Include for LibPKI */
#include <libpki/pki.h>

/* Dynamic library loading function */
#include <dlfcn.h>

int _strncpyClip( char *dst, char *orig, size_t size ) {

	char *i = NULL;

	if( !dst || !orig || size <= 0 ) return (PKI_ERR);

	i = dst + size - 1;
	strncpy( dst, orig, size );
	while( i > dst ) {
		if( *i == ' ' ) {
			*i = '\x0';
		} else {
			break;
		}
		i--;
	}
	
	return ( PKI_OK );
}

/* ------- Function to get a PKCS11_HANDLER from the HSM -------- */

PKCS11_HANDLER * _hsm_get_pkcs11_handler ( void * hsm_void ) {

	PKCS11_HANDLER *lib = NULL;
	HSM * hsm = NULL;

	hsm = (HSM *) hsm_void;

	if ( ( hsm == NULL ) || ( hsm->driver == NULL )) return ( NULL );

	if (( lib = hsm->driver ) == NULL ) {
		return ( NULL );
	}

	if ( ( lib->sh_lib == NULL ) || ( lib->callbacks == NULL )) {
		return ( NULL );
	}

	return ( lib );
}

PKCS11_HANDLER * _pki_pkcs11_load_module( const char *filename, 
						PKI_CONFIG * conf ) {

	PKCS11_HANDLER *ret = NULL;
	CK_RV rv = CKR_OK;
	CK_RV (* PKI_C_GetFunctionList )(CK_FUNCTION_LIST_PTR_PTR);
	char *error = NULL;

	if( (conf == NULL) || (filename == NULL) ) {
		PKI_log_err("Missing params for pkcs11 init!");
		return ( NULL );
	};

	if(( ret = PKI_Malloc ( sizeof( PKCS11_HANDLER ))) == NULL ) {
		PKI_log_debug ( "ERROR::Memory allocation" );
		return ( NULL );
	};

	dlerror(); /* Clears previous errors */
	if((ret->sh_lib = dlopen( filename, RTLD_NOW )) == NULL ) {
		PKI_log_err("Can not load lib file (%s)::%s", filename,
			dlerror());

		PKI_Free ( ret );
		return ( NULL );
	}

	/* Now we want to get the pointer to get the list of available
 	 * callbacks */
	// (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))
	// *(void **) (&PKI_C_GetFunctionList) = 
	// 				dlsym(handle, "C_GetFunctionList");

	PKI_C_GetFunctionList = dlsym(ret->sh_lib, "C_GetFunctionList");

	if((error = dlerror()) != NULL ) {
		PKI_log_debug("ERROR:Missing C_GetFunctionList in %s (%s)", 
							filename, error);
		goto err;
	}

	if(( rv = PKI_C_GetFunctionList(&(ret->callbacks))) != CKR_OK ) {
		PKI_log_debug("ERROR::Can not get list of funcs from %s",
								filename );
		goto err;
	}

	if( ret->callbacks == NULL ) {
		PKI_log_debug("ERROR::Can not get list of funcs from %s",
								filename );
		goto err;
	};

	return ( ret );

err:
	if( ret && ret->sh_lib ) {
		dlclose( ret->sh_lib );
	};
	if ( ret ) {
		PKI_Free ( ret );
	}

	return (NULL);
}


int _hsm_pkcs11_get_token_info( unsigned long slot_id, 
			HSM_TOKEN_INFO *tk_info, PKCS11_HANDLER *lib ) {

	CK_ULONG slot_num = 0;
	CK_TOKEN_INFO info;
	CK_RV rv = CKR_OK;

	if ( (tk_info == NULL) || ( lib == NULL )) {
		return ( PKI_ERR );
	}

	slot_num = (CK_ULONG) slot_id;
	if((rv = lib->callbacks->C_GetTokenInfo(slot_num, &info)) != CKR_OK ) {
		PKI_log_debug("Can not get Info from PKCS11 library" );
		return ( PKI_ERR );
	};

	_strncpyClip(tk_info->label, (char *)info.label, LABEL_SIZE );
	_strncpyClip(tk_info->manufacturerID, (char *)info.manufacturerID, 
						MANUFACTURER_ID_SIZE );
	_strncpyClip(tk_info->model, (char *)info.model, MODEL_SIZE );
	_strncpyClip(tk_info->serialNumber, (char *)info.serialNumber, 
						SERIAL_NUMBER_SIZE );

	/* Session Information */
	tk_info->max_sessions = info.ulMaxSessionCount ;
	tk_info->curr_sessions = info.ulSessionCount ;

	/* PIN details */
	tk_info->max_pin_len = info.ulMaxPinLen ;
	tk_info->min_pin_len = info.ulMinPinLen ;

	/* Memory */
	tk_info->memory_pub_tot = info.ulTotalPublicMemory ;
	tk_info->memory_pub_free = info.ulFreePublicMemory ;
	tk_info->memory_priv_tot = info.ulTotalPrivateMemory ;
	tk_info->memory_priv_free = info.ulFreePrivateMemory ;

	/* Version Numbers */
	tk_info->hw_version_major = info.hardwareVersion.major ;
	tk_info->hw_version_minor = info.hardwareVersion.minor ;
	tk_info->fw_version_major = info.firmwareVersion.major ;
	tk_info->fw_version_minor = info.firmwareVersion.minor ;

	/* Time */
	_strncpyClip( tk_info->utcTime, (char *)info.utcTime, 16 );

	if( info.flags & CKF_RNG ) {
		tk_info->has_rng = 1;
	}

	// if( info.flags & CFK_CLOCK_ON_TOKEN ) {
		tk_info->has_clock = 1;
	// }

	if( info.flags & CKF_LOGIN_REQUIRED ) {
		tk_info->login_required = 1;
	}

	/*
	PKI_log_debug( "TOKEN INFO: Label (%s)", tk_info->label );
	PKI_log_debug( "TOKEN INFO: Manufacturer ID (%s)", 
						tk_info->manufacturerID);
	PKI_log_debug( "TOKEN INFO: Model (%s)", tk_info->model );
	PKI_log_debug( "TOKEN INFO: SerialNumber (%s)", tk_info->serialNumber);

	PKI_log_debug( "TOKEN INFO: Sessions (%d/%d)", tk_info->max_sessions,
				tk_info->curr_sessions );
	PKI_log_debug( "TOKEN INFO: Free Public Memory (%d/%d)", 
				tk_info->memory_pub_free,
				tk_info->memory_pub_tot );
	PKI_log_debug( "TOKEN INFO: Free Private Memory (%d/%d)", 
				tk_info->memory_priv_free,
				tk_info->memory_priv_tot );
	PKI_log_debug( "TOKEN INFO: HW Version (v%d.%d)", 
				tk_info->hw_version_major,
				tk_info->hw_version_minor );
	PKI_log_debug( "TOKEN INFO: FW Version (v%d.%d)", 
				tk_info->fw_version_major,
				tk_info->fw_version_minor );
	*/

	/* Get the Info about the Token */
	return ( PKI_OK );
}

CK_OBJECT_HANDLE * HSM_PKCS11_get_obj( CK_ATTRIBUTE *templ,
		int size, PKCS11_HANDLER *lib, CK_SESSION_HANDLE *session ) {

	CK_OBJECT_HANDLE * ret = NULL;
	CK_ULONG	 ulObjectCount;

	CK_RV rv;
	int rc = 0;

	if( !lib || !session || !templ ) return ( NULL );

	rc = pthread_mutex_lock ( &lib->pkcs11_mutex );
	PKI_log_debug("%d::HSM_PKCS11_get_obj()::RC=%d", __LINE__, rc );
	while ((rv = lib->callbacks->C_FindObjectsInit( *session, 
			templ, (size_t) size)) == CKR_OPERATION_ACTIVE ) {
		rc =pthread_cond_wait ( &lib->pkcs11_cond, &lib->pkcs11_mutex );
		PKI_log_debug("%d::HSM_PKCS11_get_obj()::RC=%d", __LINE__, rc );
	}

	if( rv != CKR_OK ) {
		PKI_log_debug("HSM_PKCS11_get_obj::Error in "
					"Find Initialization (0x%8.8X)", rv );

		pthread_cond_signal( &lib->pkcs11_cond );
		pthread_mutex_unlock( &lib->pkcs11_mutex );

		return ( NULL );
	}

	/*
		while (rv == CKR_OPERATION_ACTIVE ) {
			pthread_mutex_lock( &lib->pkcs11_mutex );
			mutex_acquired = 1;

			if((rv = lib->callbacks->C_FindObjectsInit( *session, 
					templ, size)) != 
						CKR_OPERATION_ACTIVE ) {
				PKI_log_debug("HSM_PKCS11_get_obj::Error in "
					"Find Initialization (0x%8.8X)", rv );

				break;
			}

			pthread_cond_signal( &lib->pkcs11_cond );
			pthread_mutex_unlock( &lib->pkcs11_mutex );
			mutex_acquired = 0;

		}

		if( rv != CKR_OK ) {
			PKI_log_debug("HSM_PKCS11_get_obj::Error in "
					"Find Initialization (0x%8.8X)", rv );

			if( mutex_acquired == 1 ) {
				pthread_cond_signal( &lib->pkcs11_cond );
				pthread_mutex_unlock( &lib->pkcs11_mutex );
			}
			return ( NULL );
		}
	*/

	if((ret = (CK_OBJECT_HANDLE *) PKI_Malloc ( sizeof( 
					CK_OBJECT_HANDLE ))) == NULL ) {

		rv = lib->callbacks->C_FindObjectsFinal( *session );

		pthread_cond_signal( &lib->pkcs11_cond );
		pthread_mutex_unlock( &lib->pkcs11_mutex );

		return ( NULL );
	}

	rv = lib->callbacks->C_FindObjects(*session, ret, 1, &ulObjectCount );

	if( rv != CKR_OK || ulObjectCount == 0 ) {
		PKI_log_debug("HSM_PKCS11_get_obj():: Not Found (rv=0x%8.8X - "
				"ulObjectCount = %lu", rv, ulObjectCount );
		if ( ret ) PKI_Free ( ret );

		rv = lib->callbacks->C_FindObjectsFinal( *session );

		pthread_cond_signal( &lib->pkcs11_cond );
		pthread_mutex_unlock( &lib->pkcs11_mutex );
		return ( NULL );
	}

	rv = lib->callbacks->C_FindObjectsFinal( *session );

	pthread_cond_signal( &lib->pkcs11_cond );
	pthread_mutex_unlock( &lib->pkcs11_mutex );

	return ( ret );
}

int HSM_PKCS11_get_contents_info( unsigned long slot_id, PKI_CRED *cred,
							void *driver ) {

	PKCS11_HANDLER *lib = NULL;

	CK_OBJECT_HANDLE hObject;
	CK_ULONG	 ulObjectCount;

	CK_ULONG obj_type_val;
	CK_BBOOL bool_val;

	char * obj_type = NULL;
	CK_RV rv;

	CK_SESSION_HANDLE *session = NULL;

	CK_OBJECT_CLASS priv = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE attr[] = {
		{ CKA_CLASS, &priv, sizeof(priv) },
	};

	int objID = 0;

	if( !driver ) return (PKI_ERR);

	if(( lib = _hsm_get_pkcs11_handler ( driver)) == NULL ) {
		return ( PKI_ERR );
	}

	session = &lib->session;
	if( HSM_PKCS11_session_new( slot_id, session, 
			CKF_SERIAL_SESSION | CKF_RW_SESSION, lib ) != PKI_OK ) {
		return ( PKI_ERR );
	}

	if( HSM_PKCS11_login ( driver, cred ) == PKI_ERR ) {
		return ( PKI_ERR );
	}

	if((rv = lib->callbacks->C_FindObjectsInit(*session, attr, 0)) 
								!= CKR_OK ) {
		PKI_log_debug("hsm_pkcs11_get_contents_info()::Error in Find "
						"Initialization" );
		return ( PKI_ERR );
	}

	while ( 1 ) {
		char *buf = NULL;

		rv = lib->callbacks->C_FindObjects(*session, &hObject, 
							1, &ulObjectCount );

		if( rv != CKR_OK || ulObjectCount == 0 ) {
			PKI_log_debug("[Find] - Find Exiting (rv=0x%8.8X - "
				"ulObjectCount = %lu", rv, ulObjectCount );
			break;
		}

		if( objID == 0 ) printf("  List of Token Objects:\n\n");

		if((HSM_PKCS11_get_attr_ckulong( &hObject, session,
				CKA_CLASS, &obj_type_val, lib )) == PKI_OK ) {

			switch ( obj_type_val ) {
				case CKO_PRIVATE_KEY:
					obj_type = "Private Key";
					break;
				case CKO_PUBLIC_KEY:
					obj_type = "Public Key";
					break;
				case CKO_SECRET_KEY:
					obj_type = "Secret Key";
					break;
				case CKO_CERTIFICATE:
					obj_type = "Certificate";
					break;
				case CKO_DATA:
					obj_type = "Raw Data";
					break;
				case CKO_VENDOR_DEFINED:
					obj_type = "Vendor Defined";
					break;
				default:
					obj_type = "Unknown";
			}
		}

		objID++;
		printf("  * New Object (%d): %s\n", objID, obj_type);
		if((HSM_PKCS11_get_attr_bool( &hObject, session,
			CKA_PRIVATE, &bool_val, lib )) == PKI_OK ) {
			printf( "    Private ....................: %s\n", 
						bool_val ? "Yes" : "No" );
		}

		if((HSM_PKCS11_get_attr_bool( &hObject, session,
			CKA_PRIVATE, &bool_val, lib )) == PKI_OK ) {
			printf( "    Modifiable .................: %s\n", 
						bool_val ? "Yes" : "No" );
		}

		if((HSM_PKCS11_get_attr_sn( &hObject, session,
			CKA_LABEL, &buf, lib )) > 0) {
#if (LIBPKI_OS_BITS == LIBPKI_OS32)
			printf( "    Label ......................: %s (%u)\n", 
#else
			printf( "    Label ......................: %s (%lu)\n", 
#endif
				( buf != NULL ) ? buf : "n/a" , strlen(buf));
			PKI_Free ( buf );
			buf = NULL;
		} else {
			printf( "    Label ......................: ERROR!\n");
		}

		if( obj_type_val == CKO_PUBLIC_KEY ) {
			BIGNUM *bn = NULL;

			printf( "    Public Exponent ............: 0x");
			if( HSM_PKCS11_get_attr_bn( &hObject, session,
				CKA_PUBLIC_EXPONENT, &bn, lib ) == PKI_OK ) {
				BN_print_fp( stdout, bn );
				if( bn ) BN_free ( bn );
				bn = NULL;
			} else {
				printf ("Error!");
			}

			printf( "\n"); 

			printf( "    ID .........................: ");
			if(HSM_PKCS11_get_attr_bn( &hObject, session,
				CKA_ID, &bn, lib ) == PKI_OK ) {
				BN_print_fp( stdout, bn );
				if( bn ) BN_free ( bn );
				bn = NULL;
			} else {
				printf ("Error!");
			}
			printf( "\n"); 

			/*
			HSM_PKCS11_get_attr_sn( &hObject, session,
				CKA_ID, (char **) &label, lib );
			printf( "    ID (hex bytes) .............: ");

			line = 0;
			len = strlen ( label );
			for( i=0; i < len; i++ ) {
				printf("%c", label[i]);
				line++;
				if( line > 23 )  {
					printf("\n                                  "); 
					line = 0;
				}
			} printf("\n");
			if ( label ) PKI_Free ( label );
			*/

		} else if ( obj_type_val == CKO_PRIVATE_KEY ) {
			BIGNUM *bn = NULL;

			printf( "    Object Type ................: Private Key\n");
			printf( "    Public Exponent ............: 0x");
			if( HSM_PKCS11_get_attr_bn( &hObject, session,
				CKA_PUBLIC_EXPONENT, &bn, lib ) == PKI_OK ) {
				BN_print_fp( stdout, bn );
				if( bn ) BN_free ( bn );
				bn = NULL;
			} else {
				printf("Error!");
			}
			printf( "\n"); 

			printf( "    ID .........................: ");
			if( HSM_PKCS11_get_attr_bn( &hObject, session,
				CKA_ID, &bn, lib ) == PKI_OK ) {
				BN_print_fp( stdout, bn );
				if( bn ) BN_free ( bn );
				bn = NULL;
			} else {
				printf("Error!");
			}
			printf( "\n"); 

			/*
			HSM_PKCS11_get_attr_sn( &hObject, session,
				CKA_ID, (char **) &label, lib );
			printf( "    ID (hex bytes) .............: ");

			line = 0;
			len = strlen(label);
			for( i = 0; i < len; i++ ) {
				printf("%c", label[i]);
				line++;
				if( line > 23 )  {
					printf("\n                                  "); 
					line = 0;
				}
			} printf("\n");
			if ( label ) PKI_Free ( label );
			*/

		} else if ( obj_type_val == CKO_CERTIFICATE ) {
			BIGNUM *bn = NULL;

			if( HSM_PKCS11_get_attr_bn( &hObject, session,
				CKA_ID, &bn, lib ) == PKI_OK ) {
				printf( "    ID (%2.2d) ....................: ",
						BN_num_bytes(bn) );
				BN_print_fp( stdout, bn );
				if( bn ) BN_free ( bn );
				bn = NULL;
			} else {
				printf( "    ID (0) ....................: Error!");
			}

			printf( "\n"); 

			bn = NULL;

		} else if ( obj_type_val == CKO_SECRET_KEY ) {
		} else if ( obj_type_val == CKO_VENDOR_DEFINED ) {
		} else {
		}

		HSM_PKCS11_get_attr_bool( &hObject, session,
						CKA_TOKEN, &bool_val, lib);
		printf( "    Object on Token ............: %s\n", 
						bool_val ? "Yes" : "No" );
		HSM_PKCS11_get_attr_bool( &hObject, session,
						CKA_LOCAL, &bool_val, lib);
		printf( "    On Board Generated .........: %s\n", 
						bool_val ? "Yes" : "No" );
		HSM_PKCS11_get_attr_bool( &hObject, session,
					CKA_NEVER_EXTRACTABLE, &bool_val, lib);
		printf( "    Object Never Extractable ...: %s\n", 
						bool_val ? "Yes" : "No" );
		HSM_PKCS11_get_attr_bool( &hObject, session,
					CKA_EXTRACTABLE, &bool_val, lib);
		printf( "    Object Extractable .........: %s\n", 
						bool_val ? "Yes" : "No" );
		HSM_PKCS11_get_attr_bool( &hObject, session,
					CKA_ALWAYS_SENSITIVE, &bool_val, lib);
		printf( "    Object Always Sensitive ....: %s\n", 
						bool_val ? "Yes" : "No" );
		printf("\n");
	}

	if ( objID == 0 ) printf ( "  No Objects on Token\n\n" );

	if((rv = lib->callbacks->C_FindObjectsFinal(*session)) != CKR_OK ) {
		PKI_log_debug ("_hsm_pkcs11_get_keys_info()::Error in Find "
						"Finalize");
		return ( PKI_ERR );
	}

	HSM_PKCS11_session_close( session, lib );

	return (PKI_OK);
}

int HSM_PKCS11_session_new( unsigned long slot_id, CK_SESSION_HANDLE *hSession,
					int flags, PKCS11_HANDLER *lib ) {

	CK_RV rv;

	CK_SESSION_INFO session_info;

	// Input checks
	if (!hSession || !lib) return PKI_ERR;
	
	// Default flags
	if (flags == 0) flags = CKF_SERIAL_SESSION;

	// Clears the memory
	memset(&session_info, 0, sizeof(CK_SESSION_INFO));

	// Gets the Session Info
	if(( rv = lib->callbacks->C_GetSessionInfo(*hSession, &session_info)) 
								== CKR_OK ) {

		// If flags are the same, we are successful
		if (session_info.flags == flags) return PKI_OK;

		// If flags are not the same, let's log the condition
		PKI_log_debug("%s()::Session flags returned "
			"from C_GetSessionInfo() differ from given argument: "
			"Prev=0x%8.8X, Curr=0x%8.8X", __PRETTY_FUNCTION__,
			session_info.flags, flags);
	} else {
		PKI_log_debug("%s()::C_GetSessionInfo failed: Error: [0x%8.8X]",
			      __PRETTY_FUNCTION__, rv);
	}


	// If we reach this point, then the current session is either
	// not valid or has different flags set
	if((rv = lib->callbacks->C_OpenSession (slot_id, 
			(CK_FLAGS) flags, NULL, NULL, hSession)) != CKR_OK ) {
		PKI_log_debug("%s()::Failed opening a new session "
			      "(flags = 0x%x) with the token (slot=%d) "
			      "Error: [0x%8.8X]", __PRETTY_FUNCTION__,
			      flags, slot_id, rv );
		return PKI_ERR;
	}

	// All Done
	return ( PKI_OK );
}

int HSM_PKCS11_session_close( CK_SESSION_HANDLE *hSession, PKCS11_HANDLER *lib){

	CK_RV rv;
	CK_SESSION_INFO session_info;

	if (!lib || !hSession ) return ( PKI_ERR );

	if(( rv = lib->callbacks->C_GetSessionInfo(*hSession, &session_info)) 
								== CKR_OK ) {
		if((rv = lib->callbacks->C_CloseSession( *hSession )) 
								!= CKR_OK ) {
			PKI_log_debug("HSM_PKCS11_session_close()::Error in "
				"closing session" );
			return ( PKI_ERR );
		}
	}

	return ( PKI_OK );
}


int HSM_PKCS11_check_mechanism ( PKCS11_HANDLER *lib, CK_MECHANISM_TYPE mech ) {

	int ret = PKI_ERR;
	int i = 0;

	if( !lib || !lib->mech_list ) {
		PKI_log_debug( "HSM_PKCS11_check_mechanism()::no lib "
					"or lib->mech_list!" );
		return (PKI_ERR);
	}

	for ( i = 0 ; i < lib->mech_num ; i++ ) {
		/* PKI_log_debug ("HSM_PKCS11_check_mech():: Checking 0x%8.8X "
			"(for 0x%8.8X) [%d/%d]", lib->mech_list[i], mech,
				i, lib->mech_num );
		*/

		if( lib->mech_list[i] == mech ) {
			/*
			PKI_log_debug("HSM_PKCS11_check_mech()::Found 0x%8.8X "
					"(%d)!", lib->mech_list[i], i );
			*/
			return (PKI_OK);
		}
	}
	
	return ( ret );
}

int HSM_PKCS11_get_attribute (CK_OBJECT_HANDLE *hPkey, 
		CK_SESSION_HANDLE *hSession, CK_ATTRIBUTE_TYPE attribute, 
			void **data, CK_ULONG *size, PKCS11_HANDLER *lib ) {

	CK_RV rv;
	CK_ATTRIBUTE pTemplate[1];
	CK_BYTE *p = NULL;

	if( !hPkey || !hSession || !lib || !lib->callbacks ||
				!lib->callbacks->C_GetAttributeValue ) {
		return ( PKI_ERR );
	}

	pTemplate[0].type = attribute;
	pTemplate[0].pValue = NULL;
	pTemplate[0].ulValueLen = 0;

	/* Let's get the size of the attribute */
	if(( rv = lib->callbacks->C_GetAttributeValue(*hSession, *hPkey, 
						pTemplate, 1 )) != CKR_OK ) {
		PKI_log_debug("%s()::Failed 0x%8.8X", __PRETTY_FUNCTION__, rv);
		return ( PKI_ERR );
	}

	if( pTemplate[0].ulValueLen <= 0 ) {
		PKI_log_debug("%s()::Attribute is Empty!", __PRETTY_FUNCTION__);
		return ( PKI_ERR );
	}

	if((p = (CK_BYTE *) PKI_Malloc ( pTemplate[0].ulValueLen )) == NULL ) {
		PKI_log_err ("%s()::Memory Error", __PRETTY_FUNCTION__);
		return ( PKI_ERR_MEMORY_ALLOC );
	}

	pTemplate[0].pValue = p;
	*size = pTemplate[0].ulValueLen;

	/* Now that we know the size, let's get the attribute */
	if(( rv = lib->callbacks->C_GetAttributeValue( *hSession, *hPkey, 
						pTemplate, 1 )) != CKR_OK ) {
		PKI_log_err("%s()::PKCS11/C_GetAttributeValue Failed (0x%8.8X)",
		 	    __PRETTY_FUNCTION__, rv );
		PKI_Free ( p );
		return ( PKI_ERR );
	}

	*data = p;

	return ( PKI_OK );
}

int HSM_PKCS11_get_attr_bool ( CK_OBJECT_HANDLE *hObj,
		CK_SESSION_HANDLE *hSession, CK_ATTRIBUTE_TYPE attribute, 
			CK_BBOOL *val, PKCS11_HANDLER *lib ) {

	CK_BBOOL *data = NULL;
	CK_ULONG size = 0;

	if( !hObj || !hSession || !val || !lib ) {
		return ( PKI_ERR );
	}

	if( HSM_PKCS11_get_attribute( hObj, hSession, attribute, 
				( void **) &data, &size, lib ) != PKI_OK ) {
		return ( PKI_ERR );
	}

	if ( data ) {
		*val = *data;
		PKI_Free ( data );
	}

	return ( PKI_OK );
}

int HSM_PKCS11_get_attr_ckulong ( CK_OBJECT_HANDLE *hObj,
		CK_SESSION_HANDLE *hSession, CK_ATTRIBUTE_TYPE attribute, 
			CK_ULONG *val, PKCS11_HANDLER *lib ) {

	CK_ULONG *data = NULL;
	CK_ULONG size = 0;
	CK_ULONG i = 0;

	if( !hObj || !hSession || !val || !lib ) {
		return ( PKI_ERR );
	}

	if( HSM_PKCS11_get_attribute( hObj, hSession, attribute, 
				(void **) &data, &size, lib ) != PKI_OK ) {
		return ( PKI_ERR );
	}

	if( data ) {
		for ( i = size; i < sizeof(CK_ULONG); i++ ) {
			*data = 0x0;
		}
		*val = *data;
		PKI_Free ( data );
	}

	return ( PKI_OK );
}

int HSM_PKCS11_get_attr_bn ( CK_OBJECT_HANDLE *hObj,
		CK_SESSION_HANDLE *hSession, CK_ATTRIBUTE_TYPE attribute, 
			BIGNUM **val, PKCS11_HANDLER *lib ) {

	unsigned char *data = NULL;
	CK_ULONG size = 0;

	if( !hObj || !hSession || !val || !lib ) {
		return ( PKI_ERR );
	}

	if( HSM_PKCS11_get_attribute( hObj, hSession, attribute, 
				(void **) &data, &size, lib ) != PKI_OK ) {
		return ( PKI_ERR );
	}

	if( *val ) {
		BN_bin2bn(data, (int) size, *val);
	} else {
		*val = BN_bin2bn(data, (int) size, NULL);
	}

	// Let's free the memory
	if (data) PKI_Free(data);

	// All Done
	return PKI_OK;
}

int HSM_PKCS11_get_attr_sn ( CK_OBJECT_HANDLE *hObj,
		CK_SESSION_HANDLE *hSession, CK_ATTRIBUTE_TYPE attribute, 
			char **val, PKCS11_HANDLER *lib ) {

	char *data = NULL;
	size_t real_size = 0;
	CK_ULONG size = 0;

	if( !hObj || !hSession || !val || !lib ) {
		return ( PKI_ERR );
	}

	if( HSM_PKCS11_get_attribute( hObj, hSession, attribute, 
			( void **) &data, &size, lib ) != PKI_OK ) {
		return ( PKI_ERR );
	}

	real_size = (size_t) size;

	if ( data != NULL ) {
		char *tmp = NULL;

		if( (tmp = PKI_Malloc ( real_size + 1 )) == NULL ) {
			PKI_Free ( data );
			return ( PKI_ERR );
		}
		memcpy(tmp, data, real_size);
		memset(&tmp[real_size], '\x0', 1);

		PKI_Free ( data );

		*val = tmp;
	}

	return ((int)real_size );
}

int HSM_PKCS11_set_attr_bool (CK_ATTRIBUTE_TYPE type,
				CK_BBOOL value, CK_ATTRIBUTE *attribute ) {

	if ( !attribute ) return ( PKI_ERR );

	attribute->type = type;
	attribute->pValue = (void *) PKI_Malloc ( sizeof(CK_BBOOL) );
	memcpy(attribute->pValue, &value, sizeof(value));
	attribute->ulValueLen = sizeof( value );

	return PKI_OK;

}

int HSM_PKCS11_set_attr_int ( CK_ATTRIBUTE_TYPE type,
				CK_ULONG value, CK_ATTRIBUTE *attribute ) {

	if ( !attribute ) return ( PKI_ERR );

	attribute->type = type;
	attribute->pValue = (void *) PKI_Malloc ( sizeof(CK_ULONG));
	memcpy(attribute->pValue, &value, sizeof(value));
	attribute->ulValueLen = sizeof( value );

	return PKI_OK;
}

int HSM_PKCS11_set_attr_sn ( CK_ATTRIBUTE_TYPE type, char *value, 
					size_t len, CK_ATTRIBUTE *attribute) {

	if ( !attribute ) return ( PKI_ERR );

	if ( len == 0 ) len = strlen( value );

	attribute->type = type;
	attribute->pValue = (void *) PKI_Malloc( len );
	memcpy( attribute->pValue, value, len);
	attribute->ulValueLen = len;

	return PKI_OK;
}

int HSM_PKCS11_set_attr_bn ( CK_ATTRIBUTE_TYPE type, const BIGNUM *bn, 
						CK_ATTRIBUTE *attribute) {

	int len = 0;

	if( !attribute || !bn ) return (PKI_ERR);

	if((len = BN_num_bytes(bn)) < 1 ) {
		return ( PKI_ERR );
	}

	if((attribute->pValue = PKI_Malloc ( (size_t) len )) == NULL ) {
		return (PKI_ERR);
	}

	if((len = BN_bn2bin(bn, attribute->pValue)) < 0 ) {
		/* Big trouble in little s! */
		if ( attribute->pValue ) PKI_Free ( attribute->pValue );
		attribute->pValue = NULL;

		return ( PKI_ERR );
	}

	attribute->type = type;
	attribute->ulValueLen = (size_t) len;

	return ( PKI_OK );
}

/* --------------------- Save Attributes to Objects ----------------------- */

int HSM_PKCS11_save_attribute (CK_OBJECT_HANDLE *obj, 
		CK_ATTRIBUTE *templ, int idx , CK_SESSION_HANDLE *hSession,
			PKCS11_HANDLER *lib ) {

	CK_RV rv = CKR_OK;

	if( !obj || !templ || !lib || !lib->callbacks || 
				!lib->callbacks->C_SetAttributeValue ) {
		return ( PKI_ERR );
	}

	rv = lib->callbacks->C_SetAttributeValue ( *hSession, *obj,
							templ, (CK_ULONG) idx );

	if( rv != CKR_OK ) {
		PKI_log_err ("C_SetAttributeValue()::Failed with 0x%8.8X");
		return ( PKI_ERR );
	}

	return ( PKI_OK );
}

int HSM_PKCS11_save_attr_bool (CK_OBJECT_HANDLE *obj, CK_ATTRIBUTE_TYPE type,
				CK_BBOOL value, CK_SESSION_HANDLE *hSession,
					PKCS11_HANDLER *lib ) {

	CK_ATTRIBUTE attribute[1];
	int ret = PKI_OK;

	if( !obj || !hSession || !lib ) return (PKI_ERR);

	attribute[0].type = type;
	attribute[0].pValue = (void *) PKI_Malloc ( sizeof(CK_BBOOL) );
	memcpy(attribute[0].pValue, &value, sizeof(value));
	attribute[0].ulValueLen = sizeof( value );

	ret = HSM_PKCS11_save_attribute ( obj, attribute, 1, hSession, lib );

	HSM_PKCS11_clean_template ( attribute, 1 );

	return ( ret );
}

int HSM_PKCS11_save_attr_int ( CK_OBJECT_HANDLE *obj, CK_ATTRIBUTE_TYPE type,
				int value, CK_SESSION_HANDLE *hSession,
					PKCS11_HANDLER *lib ) {

	CK_ATTRIBUTE attribute[1];
	int ret = PKI_OK;

	if( !obj || !hSession || !lib ) return (PKI_ERR);

	attribute[0].type = type;
	attribute[0].pValue = (void *) PKI_Malloc ( sizeof(int));
	memcpy(attribute[0].pValue, &value, sizeof(value));
	attribute[0].ulValueLen = sizeof( value );

	ret = HSM_PKCS11_save_attribute( obj, attribute, 1, hSession, lib );

	HSM_PKCS11_clean_template ( attribute, 1 );

	return ( ret );

}

int HSM_PKCS11_save_attr_sn ( CK_OBJECT_HANDLE *obj, CK_ATTRIBUTE_TYPE type,
			char *value, int len, CK_SESSION_HANDLE *hSession,
				PKCS11_HANDLER *lib ) {

	CK_ATTRIBUTE attribute[1];
	int ret = PKI_OK;

	if( !obj || !hSession || !lib ) return (PKI_ERR);

	if ( (len == 0) && (value != NULL) ) {
		len = (int ) strlen( value );
	}

	if ( value == NULL ) len = 0;

	attribute[0].type = type;
	attribute[0].pValue = (void *) PKI_Malloc( (size_t) len );
	memcpy( attribute[0].pValue, value, (size_t) len);
	attribute[0].ulValueLen = (size_t) len;

	ret = HSM_PKCS11_save_attribute ( obj, attribute, 1, hSession, lib );

	HSM_PKCS11_clean_template( attribute, 1 );

	return ( ret );
}

int HSM_PKCS11_save_attr_bn ( CK_OBJECT_HANDLE *obj, CK_ATTRIBUTE_TYPE type, 
				BIGNUM *bn, CK_SESSION_HANDLE *hSession,
					PKCS11_HANDLER *lib ) {

	CK_ATTRIBUTE attribute[1];
	int ret = PKI_OK;
	int len = 0;

	if( !obj || !hSession || !lib || !bn ) return (PKI_ERR);

	if((len = BN_num_bytes(bn)) < 1 ) {
		return ( PKI_ERR );
	}

	if((attribute[0].pValue = PKI_Malloc ( (size_t) len )) == NULL ) {
		return (PKI_ERR);
	}

	if((len = BN_bn2bin(bn, attribute[0].pValue)) < 0 ) {
		/* Big trouble in little s! */
		if ( attribute[0].pValue ) PKI_Free ( attribute[0].pValue );
		attribute[0].pValue = NULL;

		return ( PKI_ERR );
	}

	attribute[0].type = type;
	attribute[0].ulValueLen = (size_t) len;

	ret = HSM_PKCS11_save_attribute( obj, attribute, 1, hSession, lib );

	HSM_PKCS11_clean_template( attribute, 1 );

	return ( ret );
}

/* -------------------- Object Creation Function(s) ---------------------- */

CK_OBJECT_HANDLE *HSM_PKCS11_create_obj ( CK_SESSION_HANDLE *hSession,
		CK_ATTRIBUTE *templ, int size, PKCS11_HANDLER *lib ) {

	CK_OBJECT_HANDLE *ret = NULL;
	CK_RV rv = CKR_OK;
	CK_ULONG objSize = 0;

	if( !hSession ) return ( NULL );

	ret = (CK_OBJECT_HANDLE *) PKI_Malloc ( sizeof (CK_OBJECT_HANDLE));
	if( !ret ) return ( NULL );

	objSize = (CK_ULONG) size;

	if((rv = lib->callbacks->C_CreateObject( *hSession,
				templ, objSize, ret )) == CKR_OK ) {

		PKI_log_debug("HSM_PKCS11_create_obj()::Success!");
	} else {
		PKI_log_debug("HSM_PKCS11_create_obj()::Failed with 0x%8.8X",
									rv);
		if ( ret ) PKI_Free ( ret );
		return ( NULL );
	}

	return ( ret );
}

/* ---------------------- Clean up memory in a template ------------------- */
void HSM_PKCS11_clean_template ( CK_ATTRIBUTE *templ, int n ) {

	int i = 0;
	CK_ATTRIBUTE *attr = NULL;

	if( !templ ) return;

	for(i = 0; i < n; i++ ) {
		attr = &templ[i];

		if ( !attr ) return;

		if ( !attr->pValue ) continue;

		if (attr->pValue) PKI_Free (attr->pValue);
	}

	return;
}

