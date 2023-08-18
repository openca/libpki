/* ID management for libpki */

#include <libpki/pki.h>

typedef struct oids_and_scheme {
	int oid;
	PKI_SCHEME_ID scheme;
} OIDS_AND_SCHEME;

// int pqc_sig_nids_list[] = {

// #ifdef ENABLE_PQC
//         NID_dilithium2,
//         NID_dilithium3,
//         NID_dilithium5,
//         NID_falcon512,
//         NID_falcon1024,
// 		NID_sphincssha2128fsimple,
// 		NID_sphincssha2128ssimple,
// 		NID_sphincssha2192fsimple,
// 		NID_sphincssha2192ssimple
// #endif
// 		NID_undef

// };

// int pqc_kem_nids_list[] = {

// #ifdef ENABLE_PQC
//         NID_frodo640aes,
//         NID_frodo640shake,
//         NID_frodo976aes,
//         NID_frodo976shake,
//         NID_frodo1344aes,
//         NID_frodo1344shake,
//         NID_kyber512,
//         NID_kyber768,
//         NID_kyber1024,
//         NID_bikel1,
//         NID_bikel3,
// 		NID_bikel5,
//         NID_hqc128,
//         NID_hqc192,
//         NID_hqc256,
// #endif
// 		NID_undef
// };

#define _qs_nids_size 10
static OIDS_AND_SCHEME _qs_nids[_qs_nids_size] = {

#if defined(ENABLE_OQS) || defined(ENABLE_OQSPROV)

	// ----- SIGs -----
	{ 0, PKI_SCHEME_DILITHIUM }, // Dilithium2
	{ 0, PKI_SCHEME_DILITHIUM }, // Dilithium3
	{ 0, PKI_SCHEME_DILITHIUM }, // Dilithium5
	{ 0, PKI_SCHEME_FALCON }, // Falcon512
	{ 0, PKI_SCHEME_FALCON }, // Falcon1024
	{ 0, PKI_SCHEME_SPHINCS }, // SphincsSha2128fSimple
	{ 0, PKI_SCHEME_SPHINCS }, // SphincsSha2192fSimple

	// ----- KEMs -----
	{ 0, PKI_SCHEME_KYBER }, // Kyber512
	{ 0, PKI_SCHEME_KYBER }, // Kyber768
	{ 0, PKI_SCHEME_KYBER }, // Kyber1024

#endif // End of ENABLE_OQS || ENABLE_OQSPROV

};

#define _composite_nids_size 1
static OIDS_AND_SCHEME _composite_nids[_composite_nids_size] = {

#ifdef ENABLE_COMPOSITE

	{ 0, PKI_SCHEME_COMPOSITE }, // Composite

#endif // End of ENABLE_COMPOSITE

};

#define _explicit_composite_nids_size 14
static OIDS_AND_SCHEME _fixed_composite_nids[_explicit_composite_nids_size] = {

#ifdef ENABLE_COMPOSITE
#if defined(ENABLE_OQS) || defined(ENABLE_OQSPROV)

	{ 0, PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSA }, // Dilithium3-RSA-SHA256
	{ 0, PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_P256 }, // Dilithium3-P256-SHA256
	{ 0, PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_BRAINPOOL256 }, // Dilithium3-Brainpool256-SHA256
	{ 0, PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_ED25519 }, // Dilithium3-Ed25519
	{ 0, PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_P384 }, // Dilithium5-P384-SHA384
	{ 0, PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_BRAINPOOL384 }, // Dilithium5-Brainpool384-SHA384
	{ 0, PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_ED448 }, // Dilithium5-Ed448
	{ 0, PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_P256 }, // Falcon512-P256-SHA256
	{ 0, PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_BRAINPOOL256 }, // Falcon512-Brainpool256-SHA256
	{ 0, PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_ED25519 }, // Falcon512-Ed25519
	{ 0, PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM3_RSAPSS }, // Dilithium3-RSAPSS-SHA256
	{ 0, PKI_SCHEME_COMPOSITE_EXPLICIT_FALCON512_RSA }, // Falcon512-RSA-SHA256
	{ 0, PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_P521 }, // Dilithium5-Falcon1024-P521-SHA512
	{ 0, PKI_SCHEME_COMPOSITE_EXPLICIT_DILITHIUM5_FALCON1024_RSA }, // Dilithium5-Falcon1024-RSA-SHA256

#endif // End of ENABLE_OQS || ENABLE_OQSPROV
#endif // End of ENABLE_COMPOSITE

};

static uint8_t __local_id_initialized__ = 0;

static void _init_local_ids() {
	
	// Check if we are already initialized
	if (__local_id_initialized__) return;

#if defined(ENABLE_OQS) || defined(ENABLE_OQSPROV)

	int idx;
		// Index variable

	// Initialize the PQC IDs
	// ----------------------

	idx = -1;

	// Dilithium
	_qs_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM2_NAME);
	if (_qs_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Dilithium2 not found during initialization!");
	_qs_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM3_NAME);
	if (_qs_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Dilithium3 not found during initialization!");
	_qs_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_DILITHIUM5_NAME);
	if (_qs_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Dilithium5 not found during initialization!");

	// Falcon
	_qs_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_FALCON512_NAME);
	if (_qs_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Falcon512 not found during initialization!");
	_qs_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_FALCON1024_NAME);
	if (_qs_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Falcon1024 not found during initialization!");

	// Sphincs+
	_qs_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_SPHINCS128_F_SIMPLE_NAME);
	if (_qs_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Sphincs128 not found during initialization!");
	_qs_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_SPHINCS192_F_SIMPLE_NAME);
	if (_qs_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Sphincs192 not found during initialization!");

	// Kyber
	_qs_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_KYBER512_NAME);
	if (_qs_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Kyber512 not found during initialization!");
	_qs_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_KYBER768_NAME);
	if (_qs_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Kyber768 not found during initialization!");
	_qs_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_PQC_KYBER1024_NAME);
	if (_qs_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Kyber1024 not found during initialization!");

#endif

#ifdef ENABLE_COMPOSITE

	// Initialize the Composite IDs
	// ----------------------------

	idx = -1;

	// Composite
	_composite_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_EXP_COMP_NAME);
	if (_composite_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Composite not found during initialization!");

#if defined(ENABLE_OQS) || defined(ENABLE_OQSPROV)

	// Initializes the Explicit Composite IDs
	// --------------------------------------

	idx = -1;

	// Dilithium3-RSA-SHA256
	_fixed_composite_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSA_SHA256_NAME);
	if (_fixed_composite_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Dilithium3-RSA-SHA256 not found during initialization!");
	_fixed_composite_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_P256_SHA256_NAME);
	if (_fixed_composite_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Dilithium3-P256-SHA256 not found during initialization!");
	_fixed_composite_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_BRAINPOOL256_SHA256_NAME);
	if (_fixed_composite_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Dilithium3-Brainpool256-SHA256 not found during initialization!");
	_fixed_composite_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_ED25519_NAME);
	if (_fixed_composite_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Dilithium3-Ed25519 not found during initialization!");
	_fixed_composite_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_P384_SHA384_NAME);
	if (_fixed_composite_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Dilithium5-P384-SHA384 not found during initialization!");
	_fixed_composite_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_BRAINPOOL384_SHA384_NAME);
	if (_fixed_composite_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Dilithium5-Brainpool384-SHA384 not found during initialization!");
	_fixed_composite_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_ED448_NAME);
	if (_fixed_composite_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Dilithium5-Ed448 not found during initialization!");
	_fixed_composite_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_P256_SHA256_NAME);
	if (_fixed_composite_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Falcon512-P256-SHA256 not found during initialization!");
	_fixed_composite_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_BRAINPOOL256_SHA256_NAME);
	if (_fixed_composite_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Falcon512-Brainpool256-SHA256 not found during initialization!");
	_fixed_composite_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_ED25519_NAME);
	if (_fixed_composite_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Falcon512-Ed25519 not found during initialization!");
	_fixed_composite_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM3_RSAPSS_SHA256_NAME);
	if (_fixed_composite_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Dilithium3-RSAPSS-SHA256 not found during initialization!");
	_fixed_composite_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_FALCON512_RSA_SHA256_NAME);
	if (_fixed_composite_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Falcon512-RSA-SHA256 not found during initialization!");
	_fixed_composite_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_P521_SHA512_NAME);
	if (_fixed_composite_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Dilithium5-Falcon1024-P521-SHA512 not found during initialization!");
	_fixed_composite_nids[++idx].oid = PKI_ID_get_by_name(OPENCA_ALG_PKEY_EXP_COMP_EXPLICIT_DILITHIUM5_FALCON1024_RSA_SHA256_NAME);
	if (_fixed_composite_nids[idx].oid == PKI_ID_UNKNOWN) PKI_DEBUG("Dilithium5-Falcon1024-RSA-SHA256 not found during initialization!");

#endif // End of ENABLE_OQS || ENABLE_OQSPROV
#endif // End of ENABLE_COMPOSITE

	// Make sure we do not repeat the operation
	__local_id_initialized__ = 1;

	// All Done
	return;
}

PKI_ID PKI_ID_get_by_name ( const char *name ) {

	int ret = PKI_ID_UNKNOWN;

	if( !name ) return ( PKI_ID_UNKNOWN );

	/* Check if the object already exists */
	if( (ret = OBJ_sn2nid(name)) == PKI_ID_UNKNOWN) {
		ret = OBJ_ln2nid(name);
	}

	return ( ret );
}

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

int PKI_ID_is_composite(PKI_ID id, PKI_SCHEME_ID * scheme_id) {

#ifdef ENABLE_COMPOSITE

	// Input checks
	if (id <= 0) return PKI_ERR;

	// Make sure we have the full memoization of IDs
	if (!__local_id_initialized__) _init_local_ids();

	// Checks if the ID is a composite one
	for (int i = 0; i < _composite_nids_size; i++) {
		if (_composite_nids[i].oid == id) {
			if (scheme_id) *scheme_id = _composite_nids[i].scheme;
			return PKI_OK;
		}
	}

#endif // End of ENABLE_COMPOSITE

	// If reaches here, not composite
	return PKI_ERR;
}

int PKI_ID_is_explicit_composite(PKI_ID id, PKI_SCHEME_ID * scheme_id) {

#ifdef ENABLE_COMPOSITE

	// Input checks
	if (id <= 0) {
		PKI_ERROR(PKI_ERR_PARAM_RANGE, NULL);
		return PKI_ERR;
	}

	// Make sure we have the full memoization of IDs
	if (!__local_id_initialized__) _init_local_ids();

	// Checks if the ID is a composite one
	for (int i = 0; i < _explicit_composite_nids_size; i++) {
		if (_fixed_composite_nids[i].oid == id) {
			if (scheme_id) *scheme_id = _fixed_composite_nids[i].scheme;
			return PKI_OK;
		}
	}

#endif // End of ENABLED_COMPOSITE

	// If reaches here, not explicit/fixed composite
	return PKI_ERR;
}

int PKI_ID_is_traditional(PKI_ID key_id, PKI_SCHEME_ID * scheme_id) {

	// Make sure we have the full memoization of IDs
	if (!__local_id_initialized__) _init_local_ids();

	// Maps the type of the keypair to the scheme
	switch(key_id) {

		// case PKI_ALGOR_DH: {
		// 	if (scheme_id) *scheme_id = PKI_SCHEME_DH;
		// } break;

		case PKI_ALGOR_DSA: {
			if (scheme_id) *scheme_id = PKI_SCHEME_DSA;
		} break;

		case PKI_ALGOR_RSA: {
			if (scheme_id) *scheme_id =  PKI_SCHEME_RSA;
		} break;

		case PKI_ALGOR_RSAPSS: {
			if (scheme_id) *scheme_id =  PKI_SCHEME_RSAPSS;
		} break;

#ifdef ENABLE_ECDSA

		case PKI_ALGOR_ECDSA: {
			if (scheme_id) *scheme_id =  PKI_SCHEME_ECDSA;
		} break;

		case PKI_ALGOR_X448: {
			if (scheme_id) *scheme_id =  PKI_SCHEME_X448;
		} break;

		case PKI_ALGOR_ED448: {
			if (scheme_id) *scheme_id =  PKI_SCHEME_ED448;
		} break;

		case PKI_ALGOR_X25519:  {
			if (scheme_id) *scheme_id =  PKI_SCHEME_X25519;
		} break;

		case PKI_ALGOR_ED25519: {
			if (scheme_id) *scheme_id =  PKI_SCHEME_ED25519;
		} break;

#endif // End of ENABLE_ECDSA

		default:
			PKI_DEBUG("Provided PKI_ID (%d) is not a traditional scheme!", key_id);
			return PKI_ERR;
	}

	return PKI_OK;
}

int PKI_ID_is_pqc(PKI_ID id, PKI_SCHEME_ID * scheme_id) {

#if defined(ENABLE_OQS) || defined(ENABLE_OQSPROV)

	// Make sure we have the full memoization of IDs
	if (!__local_id_initialized__) _init_local_ids();

	// Input checks
	if (id <= 0) return PKI_ERR;

	// Checks if the ID is a PQC one
	for (int i = 0; i < _qs_nids_size; i++) {
		if (_qs_nids[i].oid == id) {
			if (scheme_id) *scheme_id = _qs_nids[i].scheme;
			return PKI_OK;
		}
	}

#endif // End of ENABLE_OQS || ENABLE_OQSPROV


// #ifdef ENABLE_PQC

// 	// Checks the PKEY / Signatures
// 	switch (id) {

// 		// Signature Algorithms
// 		case NID_dilithium2:
//         case NID_dilithium3:
//         case NID_dilithium5:{
// 			// Verified PQC algorithm
// 			if (scheme_id) *scheme_id = PKI_SCHEME_DILITHIUM;
// 			return PKI_OK;
// 		} break;

//         case NID_falcon512:
//         case NID_falcon1024:{
// 			// Verified PQC algorithm
// 			if (scheme_id) *scheme_id = PKI_SCHEME_FALCON;
// 			return PKI_OK;
// 		} break;

// #ifdef NID_sphincssha2128fsimple
//         case NID_sphincssha2128fsimple:
// #endif
// #ifdef NID_sphincssha2128ssimple
//         case NID_sphincssha2128ssimple:
// #endif
// #ifdef NID_sphincssha2192fsimple
//         case NID_sphincssha2192fsimple:
// #endif
// 		{
// 			// Verified PQC algorithm
// 			if (scheme_id) *scheme_id = PKI_SCHEME_SPHINCS;
// 			return PKI_OK;
// 		} break;

// 		// KEM/Encryption Algorithms
// 		case NID_frodo640aes:
//         case NID_frodo640shake:
//         case NID_frodo976aes:
//         case NID_frodo976shake:
//         case NID_frodo1344aes:
//         case NID_frodo1344shake:{
// 			// Verified PQC algorithm
// 			if (scheme_id) *scheme_id = PKI_SCHEME_FRODOKEM;
// 			return PKI_OK;
// 		} break;

//         case NID_kyber512:
//         case NID_kyber768:
//         case NID_kyber1024: {
// 			// Verified PQC algorithm
// 			if (scheme_id) *scheme_id = PKI_SCHEME_KYBER;
// 			return PKI_OK;
// 		} break;

//         case NID_bikel1:
//         case NID_bikel3:
// 		case NID_bikel5: {
// 			// Verified PQC algorithm
// 			if (scheme_id) *scheme_id = PKI_SCHEME_BIKE;
// 			return PKI_OK;
// 		} break;

// 		case PKI_ALGOR_ID_CLASSIC_MCELIECE1: {
// 			// Verified PQC algorithm
// 			if (scheme_id) *scheme_id = PKI_SCHEME_CLASSIC_MCELIECE;
// 			return PKI_OK;
// 		} break;

// 		default:
// 			break;
// 	}
// #endif // End of ENABLE_PQC

	// If here, not a PQC algorithm
	return PKI_ERR;
}

int PKI_ID_requires_digest(PKI_ID id) {

	int sig_id = 0;

	// Input checks
	if (id <= 0) return PKI_ERR;

	// PQC do not require digests
	if (PKI_ID_is_pqc(id, NULL) == PKI_OK) return PKI_ERR;

	// Generic Composite does not require digests
	if (PKI_ID_is_composite(id, NULL) == PKI_OK) return PKI_ERR;

	// Explicit does not require digests
	if (PKI_ID_is_explicit_composite(id, NULL) == PKI_OK) return PKI_ERR;

	// Classical Territory
	switch (id) {

		case PKI_ALGOR_ID_RSAPSS:
		case PKI_ALGOR_ID_ED25519:
		case PKI_ALGOR_ID_X25519:
		case PKI_ALGOR_ID_ED448:
		case PKI_ALGOR_ID_X448: {
			// No digest required
			return PKI_ERR;
		} break;

		default:
			// Digest is required for all remaining
			// classical algorithm
			return PKI_OK;
	}

	// Checks if the ID supports a NULL digest
	OBJ_find_sigid_by_algs(&sig_id, NID_undef, id);

	// If not found, digest is actually required
	if (sig_id == NID_undef) return PKI_OK;

	// Digest not required here
	return PKI_OK;
}