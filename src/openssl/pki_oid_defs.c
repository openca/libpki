/* OID management for libpki */

// Brings in default defs
#include <stdlib.h>
#include <string.h>

#ifndef HEADER_OBJECTS_H
# include <openssl/objects.h>
#endif

#ifndef HEADER_OBJECTS_MAC_H
# define HEADER_OBJECTS_MAC_H
# include <openssl/obj_mac.h>
#endif

#ifndef _LIBPKI_LOG_H
# include <libpki/pki_log.h>
#endif

#ifndef _LIBPKI_OID_DEFS_H
# include <libpki/openssl/pki_oid_defs.h>
#endif

#ifndef _LIBPKI_OID_H
# include <libpki/pki_oid.h>
#endif

// Default
#define PKI_OK		1
#define PKI_ERR		0

// ==========================
// Data Structure Definitions
// ==========================

typedef struct oid_init_table_st {
	int nid;
	const char * oid;
	const char * name;
	const char * desc;
} OID_INIT_OBJ;

typedef struct sigs_init_table_st {
	int nid;
	const char * oid;
	const char * name;
	const char * desc;
	int hash_nid;
	int pkey_nid;
	int sig_nid;
} OID_INIT_SIG;

typedef struct obj_alias_st {
	int nid;
	const char *name;
	const char *oid;
} LIBPKI_OBJ_ALIAS;

// =============================
// Objects and Signatures Tables
// =============================

#ifdef ENABLE_ECDSA
static struct obj_alias_st nist_curves_alias[] = {
	/* prime field curves */
	{ NID_P192, "P192", "1.2.840.10045.3.1.1" },
	{ NID_P224, "P224", "1.3.132.0.33" },
	{ NID_P256, "P256", "1.2.840.10045.3.1.7" },
	{ NID_P384, "P384", "1.3.132.0.34" },
	{ NID_P521, "P521", "1.3.132.0.35" },

	/* characteristic two field curves */
	{ NID_K163, "K163", "1.3.132.0.1" },
	{ NID_K233, "K233", "1.3.132.0.26" },
	{ NID_K283, "K283", "1.3.132.0.16" },
	{ NID_K409, "K409", "1.3.132.0.36" },
	{ NID_K571, "K571", "1.3.132.0.38" },

	{ NID_B163, "B163", "1.3.132.0.15" },
	{ NID_B233, "B233", "1.3.132.0.27" },
	{ NID_B283, "B283", "1.3.132.0.17" },
	{ NID_B409, "B409", "1.3.132.0.37" },
	{ NID_B571, "B571", "1.3.132.0.39" },

	{ -1, NULL, NULL },
};
#endif

OID_INIT_OBJ oids_table[] = {
	{ 0, OPENCA_OID, OPENCA_NAME, OPENCA_DESC},
	{ 0, CERTIFICATE_TEMPLATE_OID, CERTIFICATE_TEMPLATE_NAME, CERTIFICATE_TEMPLATE_DESC},
	{ 0, LEVEL_OF_ASSURANCE_OID, LEVEL_OF_ASSURANCE_NAME, LEVEL_OF_ASSURANCE_DESC},
	{ 0, CERTIFICATE_USAGE_OID, CERTIFICATE_USAGE_NAME, CERTIFICATE_USAGE_DESC},
#ifdef ENABLE_COMPOSITE
	{ 0, OPENCA_ALG_PKEY_COMP_OID, OPENCA_ALG_PKEY_COMP_NAME, OPENCA_ALG_PKEY_COMP_DESC},
#endif
#ifdef ENABLE_COMBINED
	{ 0, OPENCA_ALG_PKEY_ALT_OID, OPENCA_ALG_PKEY_ALT_NAME, OPENCA_ALG_PKEY_ALT_DESC},
#endif
	{ 0, NULL, NULL, NULL }
};

OID_INIT_SIG sigs_table[] = {

#ifdef ENABLE_COMPOSITE
	// Composite Signatures
	{ 0, OPENCA_ALG_SIGS_COMP_OID, OPENCA_ALG_SIGS_COMP_NAME, OPENCA_ALG_SIGS_COMP_DESC, 0, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_COMP_SHA1_OID, OPENCA_ALG_SIGS_COMP_SHA1_NAME, OPENCA_ALG_SIGS_COMP_SHA1_DESC, NID_sha1, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_COMP_SHA256_OID, OPENCA_ALG_SIGS_COMP_SHA256_NAME, OPENCA_ALG_SIGS_COMP_SHA256_DESC, NID_sha256, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_COMP_SHA384_OID, OPENCA_ALG_SIGS_COMP_SHA384_NAME, OPENCA_ALG_SIGS_COMP_SHA384_DESC, NID_sha384, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_COMP_SHA512_OID, OPENCA_ALG_SIGS_COMP_SHA512_NAME, OPENCA_ALG_SIGS_COMP_SHA512_DESC, NID_sha512, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_COMP_SHA3_256_OID, OPENCA_ALG_SIGS_COMP_SHA3_256_NAME, OPENCA_ALG_SIGS_COMP_SHA3_256_DESC, NID_sha3_256, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_COMP_SHA3_384_OID, OPENCA_ALG_SIGS_COMP_SHA3_384_NAME, OPENCA_ALG_SIGS_COMP_SHA3_384_DESC, NID_sha3_384, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_COMP_SHA3_512_OID, OPENCA_ALG_SIGS_COMP_SHA3_512_NAME, OPENCA_ALG_SIGS_COMP_SHA3_512_DESC, NID_sha3_512, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_COMP_SHAKE128_OID, OPENCA_ALG_SIGS_COMP_SHAKE128_NAME, OPENCA_ALG_SIGS_COMP_SHAKE128_DESC, NID_shake128, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_COMP_SHAKE256_OID, OPENCA_ALG_SIGS_COMP_SHAKE256_NAME, OPENCA_ALG_SIGS_COMP_SHAKE256_DESC, NID_shake128, 0, 0 },
#endif

#ifdef ENABLE_COMBINED
	// Alternative Signatures
	{ 0, OPENCA_ALG_SIGS_ALT_OID, OPENCA_ALG_SIGS_ALT_NAME, OPENCA_ALG_SIGS_ALT_DESC, 0, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_ALT_SHA1_OID, OPENCA_ALG_SIGS_ALT_SHA1_NAME, OPENCA_ALG_SIGS_ALT_SHA1_DESC, NID_sha1, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_ALT_SHA256_OID, OPENCA_ALG_SIGS_ALT_SHA256_NAME, OPENCA_ALG_SIGS_ALT_SHA256_DESC, NID_sha256, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_ALT_SHA384_OID, OPENCA_ALG_SIGS_ALT_SHA384_NAME, OPENCA_ALG_SIGS_ALT_SHA384_DESC, NID_sha384, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_ALT_SHA512_OID, OPENCA_ALG_SIGS_ALT_SHA512_NAME, OPENCA_ALG_SIGS_ALT_SHA512_DESC, NID_sha512, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_ALT_SHA3_256_OID, OPENCA_ALG_SIGS_ALT_SHA3_256_NAME, OPENCA_ALG_SIGS_ALT_SHA3_256_DESC, NID_sha3_256, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_ALT_SHA3_384_OID, OPENCA_ALG_SIGS_ALT_SHA3_384_NAME, OPENCA_ALG_SIGS_ALT_SHA3_384_DESC, NID_sha3_384, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_ALT_SHA3_512_OID, OPENCA_ALG_SIGS_ALT_SHA3_512_NAME, OPENCA_ALG_SIGS_ALT_SHA3_512_DESC, NID_sha3_512, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_ALT_SHAKE128_OID, OPENCA_ALG_SIGS_ALT_SHAKE128_NAME, OPENCA_ALG_SIGS_ALT_SHAKE128_DESC, NID_shake128, 0, 0 },
	{ 0, OPENCA_ALG_SIGS_ALT_SHAKE256_OID, OPENCA_ALG_SIGS_ALT_SHAKE256_NAME, OPENCA_ALG_SIGS_ALT_SHAKE256_DESC, NID_shake128, 0, 0 },
#endif

#ifdef ENABLE_OQS
	// Dilithium3 and Dilithium5 Signatures
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA256_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA256_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA256_DESC, NID_sha256, NID_dilithium3, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA384_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA384_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA384_DESC, NID_sha384, NID_dilithium3, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA512_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA512_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHA512_DESC, NID_sha512, NID_dilithium3, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHAKE128_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHAKE128_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHAKE128_DESC, NID_shake128, NID_dilithium3, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHAKE256_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHAKE256_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM3_SHAKE256_DESC, NID_shake256, NID_dilithium3, 0 },

	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA256_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA256_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA256_DESC, NID_sha256, NID_dilithium5, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA384_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA384_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA384_DESC, NID_sha384, NID_dilithium5, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA256_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA256_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHA256_DESC, NID_sha512, NID_dilithium5, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHAKE128_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHAKE128_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHAKE128_DESC, NID_shake128, NID_dilithium5, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHAKE256_OID, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHAKE256_NAME, OPENCA_ALG_SIGS_PQC_DILITHIUM5_SHAKE256_DESC, NID_shake256, NID_dilithium5, 0 },

	// Falcon512 and Falcon1024
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON512_SHA256_OID, OPENCA_ALG_SIGS_PQC_FALCON512_SHA256_NAME, OPENCA_ALG_SIGS_PQC_FALCON512_SHA256_DESC, NID_sha256, NID_falcon512, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON512_SHA384_OID, OPENCA_ALG_SIGS_PQC_FALCON512_SHA384_NAME, OPENCA_ALG_SIGS_PQC_FALCON512_SHA384_DESC, NID_sha384, NID_falcon512, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON512_SHA256_OID, OPENCA_ALG_SIGS_PQC_FALCON512_SHA256_NAME, OPENCA_ALG_SIGS_PQC_FALCON512_SHA256_DESC, NID_sha512, NID_falcon512, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON512_SHAKE128_OID, OPENCA_ALG_SIGS_PQC_FALCON512_SHAKE128_NAME, OPENCA_ALG_SIGS_PQC_FALCON512_SHAKE128_DESC, NID_shake128, NID_falcon512, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON512_SHAKE256_OID, OPENCA_ALG_SIGS_PQC_FALCON512_SHAKE256_NAME, OPENCA_ALG_SIGS_PQC_FALCON512_SHAKE256_DESC, NID_shake256, NID_falcon512, 0 },

	{ 0, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA256_OID, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA256_NAME, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA256_DESC, NID_sha256, NID_dilithium5, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA384_OID, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA384_NAME, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA384_DESC, NID_sha384, NID_dilithium5, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA256_OID, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA256_NAME, OPENCA_ALG_SIGS_PQC_FALCON1024_SHA256_DESC, NID_sha512, NID_dilithium5, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON1024_SHAKE128_OID, OPENCA_ALG_SIGS_PQC_FALCON1024_SHAKE128_NAME, OPENCA_ALG_SIGS_PQC_FALCON1024_SHAKE128_DESC, NID_shake128, NID_falcon1024, 0 },
	{ 0, OPENCA_ALG_SIGS_PQC_FALCON1024_SHAKE256_OID, OPENCA_ALG_SIGS_PQC_FALCON1024_SHAKE256_NAME, OPENCA_ALG_SIGS_PQC_FALCON1024_SHAKE256_DESC, NID_shake256, NID_falcon1024, 0 },
#endif
	{ 0, NULL, NULL, NULL, 0, 0, 0 }
};

// ================
// Static Functions
// ================

static int __create_object_with_id ( const char *oid, const char *sn, 
		const char *ln, int id) {
	int ret = PKI_OK;
	unsigned char *buf;
	int i;

	ASN1_OBJECT *obj=NULL;

	if ( id < 0 ) {
		id = OBJ_new_nid(1);
	};

    if((i = a2d_ASN1_OBJECT(NULL,0,oid,-1)) <= 0 ) {
		return PKI_ERR;
	};

    if((buf=(unsigned char *)OPENSSL_malloc((size_t)i)) == NULL) {
        return PKI_ERR;
	}

    if((i=a2d_ASN1_OBJECT(buf,i,oid,-1)) == 0 ) {
        goto err;
	}

    if((obj=(ASN1_OBJECT *)ASN1_OBJECT_create(id,buf,i,sn,ln)) == 0 ) {
        goto err;
	}

    ret = OBJ_add_object(obj);

err:
    ASN1_OBJECT_free(obj);
    OPENSSL_free(buf);

	if( ret == 0 ) return PKI_ERR;

	return PKI_OK;
}

// ==============
// Main Functions
// ==============

int PKI_X509_OID_init() {

	OID_INIT_OBJ * obj = oids_table;
	OID_INIT_SIG * sig = sigs_table;
	int index = 0;

#ifdef ENABLE_ECDSA

	for (int i = 0; nist_curves_alias[i].name; i++ ) {
		PKI_OID *oid = NULL;
		char buf[2048];

		if( nist_curves_alias[i].oid ) {
			oid = PKI_OID_get( (char *) nist_curves_alias[i].oid );
		} else {
			oid = PKI_OID_new_id( nist_curves_alias[i].nid );
		}
		
		if (!oid) continue;

		OBJ_obj2txt(buf, sizeof(buf), oid, 1);
		PKI_OID_free ( oid );

		if( __create_object_with_id (buf,
									 nist_curves_alias[i].name, 
									 nist_curves_alias[i].name, 
									nist_curves_alias[i].nid ) == 0 ) {
				// Error while adding "easy" names for NIST curves
				PKI_DEBUG("Cannot add NIST curve alias %s", nist_curves_alias[i].name);
		}
	}

#endif

	// Process all the objects/items
	while (obj != NULL && obj->oid != NULL) {
		fprintf(stderr, "ITEM OID => %s\n", obj->oid);
		// Retrieves the object
		// obj = &oids_table[index];
		// Generate the object
		obj->nid = OBJ_create(obj->oid, obj->name, obj->desc);
		// Verify the results
		if (obj->nid == 0) {
			// Debugging
			PKI_DEBUG("Cannot create a new object for (name: %s, oid: %s)",
				obj->name, obj->oid);
			index++;
			// Continue
			continue;
		}
		fprintf(stderr, "[OID] New PKEY OID: %s (%d) => %s\n", obj->oid, obj->nid, obj->name);
		obj = &oids_table[++index];
	}

	// Resets the index
	index = 0;

	fprintf(stderr, "SIG OID => %s\n", sig->oid);


	// Process all the signatures
	while (sig != NULL && sig->oid != NULL) {
		// Retrieves the Sig item
		// sig = &sigs_table[index++];

	fprintf(stderr, "[IN] SIG OID => %s (%s)\n", sig->oid, sig->name);

		// Generates the New Signature Object
		sig->nid = OBJ_create(sig->oid, sig->name, sig->desc);

	fprintf(stderr, "[IN] SIG NID => %d (%s)\n", sig->nid, sig->name);

		// Checks if we need to get the OID of the PKEY
		if (sig->pkey_nid == 0) {
			if (!strncmp(sig->oid, OPENCA_ALG_SIGS_COMP_OID, strlen(sig->oid))
				|| !strncmp(sig->oid, OPENCA_ALG_SIGS_COMP_SHA1_OID, strlen(sig->oid))
				|| !strncmp(sig->oid, OPENCA_ALG_SIGS_COMP_SHA256_OID, strlen(sig->oid))
				|| !strncmp(sig->oid, OPENCA_ALG_SIGS_COMP_SHA384_OID, strlen(sig->oid))
				|| !strncmp(sig->oid, OPENCA_ALG_SIGS_COMP_SHA512_OID, strlen(sig->oid))
				|| !strncmp(sig->oid, OPENCA_ALG_SIGS_COMP_SHA3_256_OID, strlen(sig->oid))
				|| !strncmp(sig->oid, OPENCA_ALG_SIGS_COMP_SHA3_384_OID, strlen(sig->oid))
				|| !strncmp(sig->oid, OPENCA_ALG_SIGS_COMP_SHA3_512_OID, strlen(sig->oid))
				|| !strncmp(sig->oid, OPENCA_ALG_SIGS_COMP_SHAKE128_OID, strlen(sig->oid))
				|| !strncmp(sig->oid, OPENCA_ALG_SIGS_COMP_SHAKE256_OID, strlen(sig->oid))
			   )
			{
				sig->pkey_nid = OBJ_txt2nid(OPENCA_ALG_PKEY_COMP_OID);
				fprintf(stderr, "[IN] COMPOSITE PKEY NID => %d (%s)\n", sig->pkey_nid, OPENCA_ALG_PKEY_COMP_OID);

			}
			else if (
				!strncmp(sig->oid, OPENCA_ALG_SIGS_ALT_OID, strlen(sig->oid))
				|| !strncmp(sig->oid, OPENCA_ALG_SIGS_ALT_SHA1_OID, strlen(sig->oid))
				|| !strncmp(sig->oid, OPENCA_ALG_SIGS_ALT_SHA256_OID, strlen(sig->oid))
				|| !strncmp(sig->oid, OPENCA_ALG_SIGS_ALT_SHA384_OID, strlen(sig->oid))
				|| !strncmp(sig->oid, OPENCA_ALG_SIGS_ALT_SHA512_OID, strlen(sig->oid))
				|| !strncmp(sig->oid, OPENCA_ALG_SIGS_ALT_SHA3_256_OID, strlen(sig->oid))
				|| !strncmp(sig->oid, OPENCA_ALG_SIGS_ALT_SHA3_384_OID, strlen(sig->oid))
				|| !strncmp(sig->oid, OPENCA_ALG_SIGS_ALT_SHA3_512_OID, strlen(sig->oid))
				|| !strncmp(sig->oid, OPENCA_ALG_SIGS_ALT_SHAKE128_OID, strlen(sig->oid))
				|| !strncmp(sig->oid, OPENCA_ALG_SIGS_ALT_SHAKE256_OID, strlen(sig->oid))
			)
			{
				sig->pkey_nid = OBJ_txt2nid(OPENCA_ALG_PKEY_ALT_OID);
				fprintf(stderr, "[IN] COMBINED PKEY NID => %d (%s)\n", sig->pkey_nid, OPENCA_ALG_PKEY_ALT_OID);
			}
			else
			{
				PKI_DEBUG("Cannot find the PKEY nid for %s", sig->name);
				index++;
				continue;
			}
		}
		sig->sig_nid = OBJ_add_sigid(sig->nid, sig->hash_nid, sig->pkey_nid);
		fprintf(stderr, "[OID] New Signature OID: %d => %s (oid: %s, hash: %d, pkey: %d)\n", 
			sig->sig_nid, sig->name, sig->oid, sig->hash_nid, sig->pkey_nid);
	
		sig = &sigs_table[++index];
	}

	fprintf(stderr, "TEST STDERR\n");
	fflush(stderr);

	return 1;
}

