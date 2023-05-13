/* openssl/pki_asn1.c */

#ifndef _LIBPKI_PKI_ASN1_H
#include <libpki/pki_asn1.h>
#endif

#ifndef OPENSSL_OSSL_INTERNALS_H
#include "internal/ossl_lcl.h"
#endif

int PKI_ASN1_item_verify(const ASN1_ITEM * it, 
						 X509_ALGOR 	 * a,
                     	 ASN1_BIT_STRING  * signature,
						 void             * asn, 
						 EVP_PKEY         * pkey) {

	EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *ctx = NULL;
    unsigned char *buf_in = NULL;
    // int ret = -1, inl = 0;
    int ret = PKI_ERR, inl = 0;
    int mdnid, pknid;
    size_t inll = 0;

    if (!pkey) {
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		return PKI_ERR;
    }

	if (signature->type == V_ASN1_BIT_STRING && signature->flags & 0x7) {
        PKI_DEBUG("Invalid bit string termination (& 0x7)");
        goto end;
    }

	/* Convert signature OID into digest and public key OIDs */
	if (!OBJ_find_sigid_algs(OBJ_obj2nid(a->algorithm), &mdnid, &pknid)) {
		PKI_DEBUG("Unknown signature algorithm (%d)", OBJ_obj2nid(a->algorithm));
		goto end;
	}

	/* Check public key OID matches public key type */
	if (EVP_PKEY_type(pknid) != pkey->ameth->pkey_id) {
		PKI_DEBUG("Public key type mismatch (%d != %d)", EVP_PKEY_type(pknid), pkey->ameth->pkey_id);
		goto end;
	}

    ctx = EVP_MD_CTX_new();
	pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL || pctx == NULL) {
        PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		goto end;
    }

	// Resets the MD_CTX
	EVP_MD_CTX_init(ctx);

	// Sets the PKEY for the CTX
	EVP_MD_CTX_set_pkey_ctx(ctx, pctx);

	// Initializes the verify (and contexts)
    if (pkey->ameth && pkey->ameth->item_verify) {

		// if (!EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey)) {
		// 	PKI_DEBUG("EVP_DigestVerifyInit failed");
		// 	goto end;
		// }

		// Calls the AMETH verify function
        ret = pkey->ameth->item_verify(ctx, it, asn, a, signature, pkey);

        /*
         * Return value of 2 means carry on, anything else means we exit
         * straight away: either a fatal error of the underlying verification
         * routine handles all verification.
         */

		// Error condition
		if (ret <= 0) {
			PKI_DEBUG("AMETH verify failed (ret=%d)", ret);
			goto end;
		}

		// The ASN1 method did everything, just return
		if (ret == 1) goto end;

		// The ASN1 method only processed the algorithm
		// (and parameters), we need to continue as usual
        if (ret != 2) {
			ret = PKI_ERR;
			PKI_DEBUG("AMETH verify returned an unknown value (%d)", ret);
			goto end;
		}

		// Resets the return code
		ret = PKI_ERR;

    } else if (mdnid != NID_undef) {

		const EVP_MD *type = EVP_get_digestbynid(mdnid);

		if (type == NULL) {
			PKI_DEBUG("Unknown digest algorithm (%d)", mdnid);
			goto end;
		}

		if (!EVP_DigestVerifyInit(ctx, NULL, type, NULL, pkey)) {
			PKI_DEBUG("EVP_DigestVerifyInit failed");
			goto end;
		}
    }

    inl = ASN1_item_i2d(asn, &buf_in, it);
    if (inl <= 0) {
        PKI_DEBUG("Error converting ASN1 structure to DER");
		goto end;
    }
    if (buf_in == NULL) {
        PKI_DEBUG("Error converting ASN1 structure to DER (buf_in == NULL)");
        goto end;
    }
    inll = (size_t)inl;

    ret = EVP_DigestVerify(ctx, signature->data, (size_t)signature->length,
                           buf_in, (size_t)inl);
    if (ret <= 0) {
        PKI_DEBUG("EVP_DigestVerify failed");
        goto end;
    }
    ret = 1;
 
 end:
    OPENSSL_clear_free(buf_in, inll);
    EVP_MD_CTX_free(ctx);
    return ret;
}