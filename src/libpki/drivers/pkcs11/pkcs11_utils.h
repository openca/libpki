/* PKCS11 Utils */

#ifndef _LIBPKI_HSM_PKCS11_UTILS_H
#define _LIBPKI_HSM_PKCS11_UTILS_H

#define MAGIC			0xd00bed00

PKCS11_HANDLER * _hsm_get_pkcs11_handler ( void * hsm_void );
PKCS11_HANDLER * _pki_pkcs11_load_module(const char *filename,PKI_CONFIG *conf);
int _hsm_pkcs11_get_token_info( unsigned long slot_id, 
				HSM_TOKEN_INFO *tk_info, PKCS11_HANDLER *lib );

int HSM_PKCS11_get_contents_info( unsigned long slot_id, PKI_CRED *cred,
							void *driver );

int _strncpyClip( char *dst, char *orig, size_t size );

int HSM_PKCS11_check_mechanism ( PKCS11_HANDLER *lib, CK_MECHANISM_TYPE mech );

/* Session Handling */
int HSM_PKCS11_session_new( unsigned long slot_id, CK_SESSION_HANDLE *hSession,
					int flags, PKCS11_HANDLER *lib );
int HSM_PKCS11_session_close( CK_SESSION_HANDLE *hSession, PKCS11_HANDLER *lib);

/* Finds the first occurrence of an object */
CK_OBJECT_HANDLE * HSM_PKCS11_get_obj( CK_ATTRIBUTE *templ,
			int size, PKCS11_HANDLER *lib, CK_SESSION_HANDLE *s);

/* Create an Object in a PKCS11 device */
CK_OBJECT_HANDLE *HSM_PKCS11_create_obj ( CK_SESSION_HANDLE *hSession,
			CK_ATTRIBUTE *templ, int size, PKCS11_HANDLER *lib );

/* Get attributes from the PKCS11 device */
int HSM_PKCS11_get_attribute (CK_OBJECT_HANDLE *hPkey, 
		CK_SESSION_HANDLE *hSession, CK_ATTRIBUTE_TYPE attribute, 
			void **data, CK_ULONG *size, PKCS11_HANDLER *lib );
int HSM_PKCS11_get_attr_bool ( CK_OBJECT_HANDLE *hObj,
		CK_SESSION_HANDLE *hSession, CK_ATTRIBUTE_TYPE attribute, 
			CK_BBOOL *val, PKCS11_HANDLER *lib );
int HSM_PKCS11_get_attr_ckulong ( CK_OBJECT_HANDLE *hObj,
		CK_SESSION_HANDLE *hSession, CK_ATTRIBUTE_TYPE attribute, 
			CK_ULONG *val, PKCS11_HANDLER *lib );
int HSM_PKCS11_get_attr_bn ( CK_OBJECT_HANDLE *hObj,
		CK_SESSION_HANDLE *hSession, CK_ATTRIBUTE_TYPE attribute, 
			BIGNUM **val, PKCS11_HANDLER *lib );
int HSM_PKCS11_get_attr_sn ( CK_OBJECT_HANDLE *hObj,
		CK_SESSION_HANDLE *hSession, CK_ATTRIBUTE_TYPE attribute, 
			char **val, PKCS11_HANDLER *lib );

/* Set attributes for a PKCS11 object */
int HSM_PKCS11_set_attribute (CK_OBJECT_HANDLE *hObj,
		CK_SESSION_HANDLE *hSession, CK_ATTRIBUTE *attribute,
		int size, PKCS11_HANDLER *lib );

/* Set a single attribute in the CK_ATTRIBUTE[] that is to be uses to
   set/get the attribute in the PKCS#11 device */
int HSM_PKCS11_set_attr_bool (CK_ATTRIBUTE_TYPE type,
				CK_BBOOL value, CK_ATTRIBUTE *attribute );
int HSM_PKCS11_set_attr_int ( CK_ATTRIBUTE_TYPE type,
				CK_ULONG value, CK_ATTRIBUTE *attribute );
int HSM_PKCS11_set_attr_sn ( CK_ATTRIBUTE_TYPE type, char *value, 
					size_t len,CK_ATTRIBUTE *attribute);
int HSM_PKCS11_set_attr_bn ( CK_ATTRIBUTE_TYPE type, BIGNUM *bn, 
						CK_ATTRIBUTE *attribute);

/* Save a single attribute to an existing object */
int HSM_PKCS11_save_attribute (CK_OBJECT_HANDLE *obj, 
		CK_ATTRIBUTE *templ, int idx , CK_SESSION_HANDLE *hSession,
			PKCS11_HANDLER *lib );
int HSM_PKCS11_save_attr_bool (CK_OBJECT_HANDLE *obj, CK_ATTRIBUTE_TYPE type,
				CK_BBOOL value, CK_SESSION_HANDLE *hSession,
					PKCS11_HANDLER *lib );
int HSM_PKCS11_save_attr_int ( CK_OBJECT_HANDLE *obj, CK_ATTRIBUTE_TYPE type,
				int value, CK_SESSION_HANDLE *hSession,
					PKCS11_HANDLER *lib );
int HSM_PKCS11_save_attr_sn ( CK_OBJECT_HANDLE *obj, CK_ATTRIBUTE_TYPE type,
			char *value, int len, CK_SESSION_HANDLE *hSession,
				PKCS11_HANDLER *lib );
int HSM_PKCS11_save_attr_bn ( CK_OBJECT_HANDLE *obj, CK_ATTRIBUTE_TYPE type, 
				BIGNUM *bn, CK_SESSION_HANDLE *hSession,
					PKCS11_HANDLER *lib );

/* Clean a template (array of CK_ATTRIBUTE) */
void HSM_PKCS11_clean_template ( CK_ATTRIBUTE *templ, int n );

#endif /* _LIBPKI_HSM_PKCS11_UTILS_H */
