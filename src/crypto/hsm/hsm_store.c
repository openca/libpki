/* HSM Object Management Functions */

#include <libpki/crypto/hsm/hsm_store.h>

/* HSM_STORE_INFO Data Structure */
HSM_STORE_INFO default_slot_info = {

	/* Device Manufacturer ID */
	"Unknown",

	/* Device Description */
	"Unknown",

	/* Hardware Version */
	1,
	0,

	/* Firmware Version */
	1,
	0,

	/* Initialized */
	1,

	/* Present */
	1,

	/* Removable */
	0,

	/* Hardware */
	0,

	/* Token Info */
	{
		/* Token Label */
		"Unknown Label",
		/* ManufacturerID */
		"Unknown",
		/* Model */
		"Unknown Model",
		/* Serial Number */
		"0",
		/* Max Sessions */
		65535,
		/* Current Sessions */
		0,
		/* Max Pin Len */
		0,
		/* Min Pin Len */
		0,
		/* Memory Pub Total */
		0,
		/* Memory Pub Free */
		0,
		/* Memory Priv Total */
		0,
		/* Memory Priv Free */
		0,
		/* HW Version Major */
		1,
		/* HW Version Minor */
		0,
		/* FW Version Major */
		1,
		/* FW Version Minor */
		0,
		/* HAS Random Number Generator (RNG) */
		1,
		/* HAS clock */
		0,
		/* Login is Required */
		0,
		/* utcTime */
		""
	}

};

/* ------------- Slot Management functions --------------- */
	
unsigned long HSM_STORE_num ( HSM *hsm ) {

	if (!hsm || !hsm->store_callbacks) return ( 1 );

	if (hsm->store_callbacks && hsm->store_callbacks->store_num) {
		return hsm->store_callbacks->store_num( hsm );
	}

	return ( 1 );
};

int HSM_STORE_select ( unsigned long num, PKI_CRED *cred, HSM *hsm ) {

	int ret = PKI_OK;

	if( !hsm ) {
		return ( ret );
	}

	if( hsm && hsm->store_callbacks && hsm->store_callbacks->select_slot ) {
		ret = hsm->store_callbacks->select_slot ( num, cred, hsm );
	} else {
		PKI_log_debug("No slot select function for current HSM");
		ret = PKI_OK;
	}

	return ( ret );
}

int HSM_STORE_clear ( unsigned long num, PKI_CRED *cred, HSM *hsm ) {

	int ret = PKI_OK;

	if( !hsm ) {
		return ( ret );
	}

	if( hsm && hsm->store_callbacks && hsm->store_callbacks->clear_slot ) {
		ret = hsm->store_callbacks->clear_slot ( num, cred, hsm );
	} else {
		PKI_log_debug ("No Slot Clear function for current HSM");
		ret = PKI_OK;
	}

	return ( ret );
}

HSM_STORE_INFO * HSM_STORE_INFO_get ( unsigned long num, HSM *hsm ) {

	HSM_STORE_INFO *ret = NULL;

	if( !hsm ) {
		ret = (HSM_STORE_INFO *) PKI_Malloc ( sizeof (HSM_STORE_INFO));
		memcpy( ret, &default_slot_info, sizeof( HSM_STORE_INFO ));

		snprintf(ret->manufacturerID, HSM_MANUFACTURER_ID_SIZE, 
					"%s", "OpenCA Labs");
		snprintf(ret->description, HSM_DESCRIPTION_SIZE, 
					"%s", "LibPKI Software HSM");

		snprintf(ret->token_info.label, HSM_LABEL_SIZE, 
					"%s", "LibPKI Software Token");
		snprintf(ret->token_info.manufacturerID, HSM_MANUFACTURER_ID_SIZE, 
					"%s", "OpenCA Labs");
        	snprintf(ret->token_info.model, HSM_MODEL_SIZE, 
					"%s", "OpenSSL Library");
        	snprintf(ret->token_info.serialNumber, HSM_SERIAL_NUMBER_SIZE, 
					"%s", "0000:0000");

	} else if ( hsm->store_callbacks && hsm->store_callbacks->store_info_get) {
		ret = hsm->store_callbacks->store_info_get ( num, hsm );
	} else {
		ret = (HSM_STORE_INFO *) PKI_Malloc ( sizeof (HSM_STORE_INFO));
		memcpy( ret, &default_slot_info, sizeof( HSM_STORE_INFO ));
	};

	return ( ret );
};

int HSM_STORE_INFO_print( unsigned long num, PKI_CRED * cred, HSM *hsm ) {

	HSM_STORE_INFO *sl_info = NULL;
	HSM_TOKEN_INFO *tk_info = NULL;

    if((sl_info = HSM_STORE_INFO_get ( num, hsm )) == NULL ) {
		PKI_log_debug("Can not get the HSM info");
		return PKI_ERR;
	}

	printf("Slot [%lu] Info:\r\n", num );
	printf("  Description ........: %s\r\n", sl_info->description);
	printf("  Manufacturer ID ....: %s\r\n", sl_info->manufacturerID);
	printf("  Hardware Version ...: %d.%d\r\n",
		sl_info->hw_version_major, sl_info->hw_version_minor );
	printf("  Firmware Version ...: %d.%d\r\n",
		sl_info->fw_version_major, sl_info->fw_version_minor );

	tk_info = &(sl_info->token_info);
		
	printf("\n  Token Info:\n");
	printf("    Label .....................: %s\r\n", tk_info->label);
	printf("    Manufacturer ID ...........: %s\r\n", tk_info->manufacturerID);
	printf("    Model .....................: %s\r\n", tk_info->model);
	printf("    Serial Number .............: %s\r\n", tk_info->serialNumber);
	printf("    Free Pub Memory ...........: (%lu/%lu)\r\n",
		tk_info->memory_pub_free,
		tk_info->memory_pub_tot );
	printf("    Free Priv Memory ..........: (%lu/%lu)\r\n",
		tk_info->memory_priv_free,
		tk_info->memory_priv_tot );
	printf("    Hardware Version ..........: v%d.%d\r\n",
		tk_info->hw_version_major,
		tk_info->hw_version_minor );
	printf("    Firmware Version ..........: %d.%d\r\n",
		tk_info->fw_version_major,
		tk_info->fw_version_minor );
	printf("    Pin Len (Min/Max) .........: %lu/%lu\r\n",
		tk_info->min_pin_len,
		tk_info->max_pin_len );
	printf("    Sessions (Curr/Max) .......: %lu/%lu\r\n",
		tk_info->curr_sessions,
		tk_info->max_sessions );
	printf("    Token Status ..............: ");
	if( sl_info->present ) printf ("Present");
	if( sl_info->removable ) printf(", Removable");
	if( sl_info->hardware ) printf(", Hardware Token");
	printf("\n");

	if( tk_info->has_clock == 1 ) {
		printf("    Token Time ................: %s\r\n", 
			tk_info->utcTime );
	} else {
		printf("    Token Clock ...............: Yes\r\n");
	}

	if( tk_info->has_rng ) {
		printf("    Random Number Generator ...: Yes\r\n");
	} else {
		printf("    Random Number Generator ...: No\r\n");
	}

	printf("\r\n");

	if( hsm && hsm->type == HSM_TYPE_PKCS11 ) {
		HSM_PKCS11_get_contents_info ( num, cred, hsm );
	}

	printf("\r\n");

	return ( PKI_OK );
}

void HSM_STORE_INFO_free ( HSM_STORE_INFO *sl_info, HSM *hsm ) {

	if( !sl_info || !hsm ) {
		return;
	}

	if (hsm && hsm->store_callbacks && hsm->store_callbacks->store_info_free) {
		hsm->store_callbacks->store_info_free ( sl_info, hsm );
	} else {
		PKI_Free ( sl_info );
	};

	return;
}

// /* ----------------------- General Obj Management ------------------------ */

// /*! \brief Gets a stack of X509 objects from the URL in the HSM */

// PKI_X509_STACK *HSM_X509_STACK_get_url ( PKI_DATATYPE type, URL *url, 	
// 						PKI_DATA_FORMAT format, PKI_CRED *cred, HSM *hsm ) {

// 	PKI_STACK *ret = NULL;

// 	if( !url ) return ( NULL );

// 	if( url->proto != URI_PROTO_ID ) return NULL;

// 	if( !hsm ) hsm = (HSM * ) HSM_get_default();

// 	if( hsm  && hsm->store_callbacks && hsm->store_callbacks->x509_sk_get_url ) { 
// 		ret = hsm->store_callbacks->x509_sk_get_url( type, url, format, cred, hsm );
// 	};

//         return ( ret );
// }

// /*! \brief Stores a stack of PKI_X509 objects in the specified URL/HSM */

// int HSM_X509_STACK_put_url ( PKI_X509_STACK *sk, URL *url, 
// 						PKI_CRED *cred, HSM *hsm ) {

// 	int ret = PKI_OK;

// 	if( !url || !sk ) return PKI_ERR;

// 	if ( url->proto != URI_PROTO_ID ) return PKI_ERR;

// 	if( !hsm ) hsm = (HSM *) HSM_get_default();

// 	if( hsm  && hsm->store_callbacks && hsm->store_callbacks->x509_sk_add_url ) { 
// 		ret = hsm->store_callbacks->x509_sk_add_url( sk, url, cred, hsm );
// 	};

//         return ( ret );
// }

// /*! \brief Stores the contents of a stack of MEM to the specified URL/HSM */

// int HSM_MEM_STACK_put_url ( PKI_MEM_STACK *sk, URL *url, PKI_DATATYPE type,
// 						PKI_CRED *cred, HSM *hsm ) {
// 	int i = 0;
// 	int ret = PKI_OK;

// 	PKI_MEM *mem = NULL;
// 	PKI_X509 *x_obj = NULL;
// 	PKI_X509_STACK *obj_sk = NULL;

// 	if(( obj_sk = PKI_STACK_new_type( type )) == NULL ) {
// 		return PKI_ERR;
// 	}

// 	for ( i = 0; i < PKI_STACK_MEM_elements ( sk ); i++ ) {
// 		PKI_X509_STACK *mem_obj_sk = NULL;

// 		/* Gets the PKI_MEM container from the stack */
// 		if((mem = PKI_STACK_MEM_get_num ( sk, i )) == NULL ) {
// 			continue;
// 		}

// 		/* Gets the objects (multiple, possibly) from each PKI_MEM */
// 		if((mem_obj_sk = PKI_X509_STACK_get_mem ( mem, type, 
// 						PKI_DATA_FORMAT_UNKNOWN, cred, hsm )) == NULL ) {
// 			continue;
// 		}

// 		/* Builds the stack of PKI_X509 objects */
// 		while ((x_obj = PKI_STACK_X509_pop ( mem_obj_sk )) != NULL ) {
// 			/* Push the Object on the Stack */
// 			PKI_STACK_X509_push ( obj_sk, x_obj );
// 		}
// 	}

// 	/* Now Put the stack of objects in the HSM */
// 	ret = HSM_X509_STACK_put_url ( sk, url, cred, hsm );

// 	/* Clean the stack of Objects we created */
// 	while ( (x_obj = PKI_STACK_X509_pop ( sk )) != NULL ) {
// 		PKI_X509_free ( x_obj );
// 	}
// 	PKI_STACK_X509_free ( sk );

// 	/* Return value */
// 	return ret;
// }

// /*! \brief Deletes a Stack of Objects that are stored in a HSM */

// int HSM_X509_STACK_del ( PKI_X509_STACK *sk ) {

// 	int ret = PKI_ERR;
// 	int i = 0;

// 	// HSM *hsm = NULL;
// 	// HSM *def_hsm = NULL;

// 	PKI_X509 *obj = NULL;

// 	if ( !sk ) return ( PKI_ERR );

// 	for ( i = 0; i < PKI_STACK_X509_elements ( sk ); i++ ) {
// 		obj = PKI_STACK_X509_get_num ( sk, i );

// 		if (!obj || !obj->value ) continue;

// 		if ( obj->ref ) {
// 			ret = HSM_X509_del_url ( obj->type, obj->ref, 
// 							obj->cred, obj->hsm );

// 			if ( ret == PKI_ERR ) return PKI_ERR;
// 		}
// 	}

// 	return PKI_OK;
// }

// /*! \brief Deletes the contents of the specified URL in the HSM */

// int HSM_X509_del_url ( PKI_DATATYPE type, URL *url, PKI_CRED *cred, HSM *hsm ) {

// 	int ret = PKI_OK;

// 	if( !url ) return ( PKI_ERR );

// 	if( !hsm ) hsm = (HSM *) HSM_get_default();

// 	if( hsm  && hsm->store_callbacks && hsm->store_callbacks->x509_del_url ) { 
// 		ret = hsm->store_callbacks->x509_del_url( type, url, cred, hsm );
// 	};

//         return ( ret );
// }

// /*! \brief Returns the callbacks for the specific HSM */

// const PKI_X509_CALLBACKS * HSM_X509_get_cb ( PKI_DATATYPE type, HSM *hsm ) {

// 	if ( !hsm || !hsm->store_callbacks ) return HSM_OPENSSL_X509_get_cb (type);

// 	return hsm->store_callbacks->x509_get_cb ( type );
// }

