/* HSM Object Management Functions */

#include <libpki/pki.h>

/* HSM_SLOT_INFO Data Structure */
HSM_SLOT_INFO default_slot_info = {

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
	
unsigned long HSM_SLOT_num ( HSM *hsm ) {

	if( !hsm || !hsm->callbacks ) return ( 1 );

	if( hsm->callbacks && hsm->callbacks->slot_num ) {
		return hsm->callbacks->slot_num( hsm );
	}

	return ( 1 );
};

int HSM_SLOT_select ( unsigned long num, PKI_CRED *cred, HSM *hsm ) {

	int ret = PKI_OK;

	if( !hsm ) {
		return ( ret );
	}

	if( hsm && hsm->callbacks && hsm->callbacks->select_slot ) {
		ret = hsm->callbacks->select_slot ( num, cred, hsm );
	} else {
		PKI_log_debug("No slot select function for current HSM");
		ret = PKI_OK;
	}

	return ( ret );
}

int HSM_SLOT_clear ( unsigned long num, PKI_CRED *cred, HSM *hsm ) {

	int ret = PKI_OK;

	if( !hsm ) {
		return ( ret );
	}

	if( hsm && hsm->callbacks && hsm->callbacks->clear_slot ) {
		ret = hsm->callbacks->clear_slot ( num, cred, hsm );
	} else {
		PKI_log_debug ("No Slot Clear function for current HSM");
		ret = PKI_OK;
	}

	return ( ret );
}

HSM_SLOT_INFO * HSM_SLOT_INFO_get ( unsigned long num, HSM *hsm ) {

	HSM_SLOT_INFO *ret = NULL;

	if( !hsm ) {
		ret = (HSM_SLOT_INFO *) PKI_Malloc ( sizeof (HSM_SLOT_INFO));
		memcpy( ret, &default_slot_info, sizeof( HSM_SLOT_INFO ));

		snprintf(ret->manufacturerID, MANUFACTURER_ID_SIZE, 
					"%s", "OpenCA Labs");
		snprintf(ret->description, DESCRIPTION_SIZE, 
					"%s", "LibPKI Software HSM");

		snprintf(ret->token_info.label, LABEL_SIZE, 
					"%s", "LibPKI Software Token");
		snprintf(ret->token_info.manufacturerID, MANUFACTURER_ID_SIZE, 
					"%s", "OpenCA Labs");
        	snprintf(ret->token_info.model, MODEL_SIZE, 
					"%s", "OpenSSL Library");
        	snprintf(ret->token_info.serialNumber, SERIAL_NUMBER_SIZE, 
					"%s", "0000:0000");

	} else if ( hsm->callbacks && hsm->callbacks->slot_info_get ) {
		ret = hsm->callbacks->slot_info_get ( num, hsm );
	} else {
		ret = (HSM_SLOT_INFO *) PKI_Malloc ( sizeof (HSM_SLOT_INFO));
		memcpy( ret, &default_slot_info, sizeof( HSM_SLOT_INFO ));
	};

	return ( ret );
};

int HSM_SLOT_INFO_print( unsigned long num, PKI_CRED * cred, HSM *hsm ) {

	HSM_SLOT_INFO *sl_info = NULL;
	HSM_TOKEN_INFO *tk_info = NULL;

    if((sl_info = HSM_SLOT_INFO_get ( num, hsm )) == NULL ) {
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

void HSM_SLOT_INFO_free ( HSM_SLOT_INFO *sl_info, HSM *hsm ) {

	if( !sl_info || !hsm ) {
		return;
	}

	if ( hsm && hsm->callbacks && hsm->callbacks->slot_info_free ) {
		hsm->callbacks->slot_info_free ( sl_info, hsm );
	} else {
		PKI_Free ( sl_info );
	};

	return;
}

