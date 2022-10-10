/* openssl/pki_pkey.c */

/* Internal usage only - we want to keep the lib abstract */
#ifndef _LIBPKI_HSM_OPENSSL_PKEY_H
#define _LIBPKI_HSM_OPENSSL_PKEY_H

#include <libpki/pki.h>

PKI_RSA_KEY * _pki_rsakey_new( PKI_KEYPARAMS *kp );
PKI_DSA_KEY * _pki_dsakey_new( PKI_KEYPARAMS *kp );
#ifdef ENABLE_ECDSA
PKI_EC_KEY * _pki_ecdsakey_new( PKI_KEYPARAMS *kp);
#else
void * _pki_ecdsakey_new( PKI_KEYPARAMS *kp );
#endif

int _pki_rand_init( void );

/* End of _LIBPKI_INTERNAL_PKEY_H */
#endif

int _pki_rand_seed( void ) {
    unsigned char seed[20];

    if (!RAND_bytes(seed, 20)) return 0;

    RAND_seed(seed, sizeof seed);

    return(1);
}

PKI_RSA_KEY * _pki_rsakey_new( PKI_KEYPARAMS *kp ) {

    BIGNUM *bne = NULL;
    PKI_RSA_KEY *rsa = NULL;
    int ossl_rc = 0;

    int bits = PKI_RSA_KEY_DEFAULT_SIZE;

    unsigned long e = RSA_F4;
        // Default exponent (65537)

    if ( kp && kp->bits > 0 ) bits = kp->bits;

    if ( bits < PKI_RSA_KEY_MIN_SIZE ) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_SIZE_SHORT, NULL);
        return NULL;
    }

    if ((bne = BN_new()) != NULL) {
        if (1 != BN_set_word(bne, e)) {
            PKI_ERROR(PKI_ERR_GENERAL, NULL);
            return NULL;
        }
    } else {
        PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
        return NULL;
    }
        
    if ((rsa = RSA_new()) == NULL) {
        BN_free(bne);
        PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
        return NULL;
    }

    if ((ossl_rc = RSA_generate_key_ex(rsa, bits, bne, NULL)) != 1 ) {
        /* Error */
        BN_free(bne);
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, NULL);
        return NULL;
    }

    BN_free(bne);

    /* Let's return the RSA_KEY infrastructure */
    return (rsa);
};

PKI_DSA_KEY * _pki_dsakey_new( PKI_KEYPARAMS *kp ) {

    PKI_DSA_KEY *k = NULL;
    unsigned char seed[20];

    int bits = PKI_DSA_KEY_DEFAULT_SIZE;

    if ( kp && kp->bits > 0 ) bits = kp->bits;

    if ( bits < PKI_DSA_KEY_MIN_SIZE ) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_SIZE_SHORT, NULL);
        return NULL;
    };

    if (!RAND_bytes(seed, 20)) {
        /* Not enought rand ? */
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Too low Entropy");
        return NULL;
    }

    if ((k = DSA_new()) == NULL) {
        // Memory Allocation Error
        PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Too low Entropy");
        return NULL;
    }

    if (1 != DSA_generate_parameters_ex(k, bits, seed, 20, NULL, NULL, NULL)) {
        if( k ) DSA_free( k );
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not generated DSA params");
        return NULL;
    }

    return( k );
}

#ifdef ENABLE_ECDSA
PKI_EC_KEY * _pki_ecdsakey_new( PKI_KEYPARAMS *kp ) {
    /* ECDSA is a little more complicated than the other
       schemes as it involves a group of functions. As the
       purpose of this library is to provide a very hi-level
       easy to use library, we will provide some hardwired
       parameters.
    */
    PKI_EC_KEY *k = NULL;
    EC_builtin_curve *curves = NULL;
    EC_GROUP *group = NULL;
    size_t num_curves = 0;
    int degree = 0;

    int bits    = PKI_EC_KEY_DEFAULT_SIZE;
    int curve   = PKI_EC_KEY_CURVE_DEFAULT;
    int flags   = PKI_EC_KEY_ASN1_DEFAULT;

    PKI_EC_KEY_FORM form     = PKI_EC_KEY_FORM_DEFAULT;

    /* Get the number of available ECDSA curves in OpenSSL */
    if ((num_curves = EC_get_builtin_curves(NULL, 0)) < 1 ) {
        /* No curves available! */
        PKI_ERROR(PKI_ERR_OBJECT_CREATE, "Builtin EC curves");
        return NULL;
    }

    /* Alloc the needed memory */
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
    curves = OPENSSL_malloc((int)(sizeof(EC_builtin_curve) * num_curves));
#else
    curves = OPENSSL_malloc(sizeof(EC_builtin_curve) * num_curves);
#endif

    /* Check for memory allocation */
    if (curves == NULL) return NULL;

    /* Get the builtin curves */
    if (!EC_get_builtin_curves(curves, (size_t) num_curves))
    {
        PKI_ERROR(PKI_ERR_OBJECT_CREATE, "Can not get builtin EC curves (%d)", num_curves);
        goto err;
        return NULL;
    }

    /* We completely change behavior - we adopt one of the two
         * curves suggested by NIST. In particular:
         * - NID_secp384r1
         * - NID_secp521r1
         * For today (2008) usage, the first curve + SHA256 seems to be
         * the best approach
         */

    if( kp && kp->bits > 0 ) {
        bits = kp->bits;
    };

    if(bits < PKI_EC_KEY_MIN_SIZE ){
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_SIZE_SHORT, "%d", bits);
        return NULL;
    };

    if( kp && kp->ec.curve > 0 ) {
        curve = kp->ec.curve;
    } else {
        if( bits <= 112 ) {
            bits = 112;
            curve = NID_secp112r1;
        } else if( bits <= 128 ) {
            bits = 128;
            curve = NID_secp128r1;
        } else if( bits <= 160 ) {
            bits = 160;
            curve = NID_secp160r1;
        } else if( bits <= 192 ) {
            bits = 192;
            curve = NID_X9_62_prime192v1;
        } else if( bits <= 224 ) {
            bits = 224;
            curve = NID_secp224r1;
        } else if( bits <= 256 ) {
            bits = 256;
            curve = NID_X9_62_prime256v1;
        } else if( bits <= 384 ) {
            bits = 384;
            curve = NID_secp384r1;
        } else {
            bits = 512;
            curve = NID_secp521r1;
        };
    };

    /* Initialize the key */
    if ((k = EC_KEY_new()) == NULL) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, NULL);
        goto err;
        return NULL;
    }

    if((group = EC_GROUP_new_by_curve_name(curve)) == NULL ) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Invalid Curve - %d", curve);
        goto err;
        return NULL;
    };

    EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
    EC_GROUP_set_point_conversion_form(group, form);

    /* Assign the group to the key */
    if (EC_KEY_set_group(k, group) == 0) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Invalid Group");
        goto err;
        return NULL;
    }

    /* Sets the point compression */
    if ( kp && kp->ec.form != PKI_EC_KEY_FORM_UNKNOWN ) {
        form = kp->ec.form;
    };
    EC_KEY_set_conv_form(k, (point_conversion_form_t)form);

    /* Sets the type of parameters, flags > 0 ==> by OID, 
      * flags == 0 ==> specifiedCurve
      */
    if ( kp->ec.asn1flags > -1 ) {
        flags = kp->ec.asn1flags;
    };
    EC_KEY_set_asn1_flag(k, flags);

    /* We do not need it now, let's free the group */
    if ( group ) EC_GROUP_free( group );
    group = NULL;

    if((group = (EC_GROUP *) EC_KEY_get0_group(k)) != NULL ) {
        EC_GROUP_set_asn1_flag( group, OPENSSL_EC_NAMED_CURVE );
    };

    degree = EC_GROUP_get_degree(EC_KEY_get0_group(k));

    if( degree < bits ) {
        /* Fix the problem, let's get the right bits */
        bits = degree;
    }

    //    // Let's cycle through all the available curves
    //    // until we find one that matches (if any)
    //    i = (i + 1 ) % num_curves;
    //
    // } while ( (degree < bits ) && (i != n_start) );

    /* Now generate the key */
    if (!EC_KEY_generate_key(k)) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, NULL );
        goto err;
        return NULL;
    }

    /* Verify the Key to be ok */
    if (!EC_KEY_check_key(k)) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Verify failed for ECDSA key" );
        goto err;
        return NULL;
    }

    // EC_KEY_set_enc_flags(k, EC_PKEY_NO_PARAMETERS);
    // ecKeyPnt = (struct __ec_key_st2 *) k;
    // ecKeyPnt->version = 1;

    goto end;

err:
    if( curves ) free ( curves );
    if ( group ) EC_GROUP_free( group );

    if( k ) {
        EC_KEY_free ( k );
        k = NULL;
    };

end:
    return ( k );
}

#else /* EVP_PKEY_EC */

void * _pki_ecdsakey_new( PKI_KEYPARAMS *kp ) {
    PKI_ERROR(PKI_ERR_NOT_IMPLEMENTED, NULL);
    return ( NULL );
}

#endif

#ifdef ENABLE_OQS

EVP_PKEY_CTX * _pki_get_evp_pkey_ctx(PKI_KEYPARAMS *kp) {

    const EVP_PKEY_ASN1_METHOD *ameth;

    ENGINE *tmpeng = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    int pkey_id = -1;

    ameth = EVP_PKEY_asn1_find(&tmpeng, kp->oqs.algId);
    if (!ameth) {
       PKI_log_debug("Missing ASN1 Method for algorithm '%s' (%d)", 
           PKI_ALGOR_ID_txt(kp->oqs.algId), kp->oqs.algId);
       return NULL;
    }

    ERR_clear_error();

    EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL, ameth);

    if ((ctx = EVP_PKEY_CTX_new_id(pkey_id, NULL)) == NULL)
        goto err;

    // Let's set the operation (check EVP_PKEY_CTX_ctrl function -pmeth_lib.c:432)
    // Use the EVP interface to initialize the operation (crypto/evp/pmeth_gn.c:69)
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Cannot Initialize Key Generation");
        goto err;
    }

#ifdef ENABLE_COMPOSITE

    // CTX operations for Composite Crypto
    //
    // EVP_PKEY_CTRL_COMPOSITE_PUSH       
    // EVP_PKEY_CTRL_COMPOSITE_POP        
    // EVP_PKEY_CTRL_COMPOSITE_ADD        
    // EVP_PKEY_CTRL_COMPOSITE_DEL        
    // EVP_PKEY_CTRL_COMPOSITE_CLEAR      


    if ((kp->scheme == PKI_SCHEME_COMPOSITE ||
         kp->scheme == PKI_SCHEME_COMBINED)
         && kp->comp.k_stack != NULL) {

        for (int i = 0; i < PKI_STACK_X509_KEYPAIR_elements(kp->comp.k_stack); i++) {

            PKI_X509_KEYPAIR * tmp_key = NULL;

            // Let's get the i-th PKI_X509_KEYPAIR
            tmp_key = PKI_STACK_X509_KEYPAIR_get_num(kp->comp.k_stack, i);
            // Now we can use the CRTL interface to pass the new keys
            if (EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_KEYGEN,
                                  EVP_PKEY_CTRL_COMPOSITE_PUSH, 0, tmp_key->value) <= 0) {
                PKI_log_debug("Cannot add key via the CTRL interface");
                goto err;
            }
        }
    }
#endif

    return ctx;

 err:

    PKI_log_debug("Error initializing context for [scheme: %d, algId: %d]\n", 
        kp->scheme, kp->oqs.algId);

    if (ctx) EVP_PKEY_CTX_free(ctx);
    return NULL;
}

#endif

#ifdef ENABLE_COMPOSITE
PKI_COMPOSITE_KEY * _pki_composite_new( PKI_KEYPARAMS *kp ) {

    PKI_COMPOSITE_KEY *k = NULL;

    if ((k = COMPOSITE_KEY_new()) == NULL) {
        // Memory Allocation Error
        PKI_ERROR(PKI_ERR_MEMORY_ALLOC, "Too low Entropy");
        return NULL;
    }

    if (kp->comp.k_stack != NULL) {

        for (int i = 0; i < PKI_STACK_X509_KEYPAIR_elements(kp->comp.k_stack); i++) {

            PKI_X509_KEYPAIR * tmp_key = NULL;

            // Let's get the i-th PKI_X509_KEYPAIR
            tmp_key = PKI_STACK_X509_KEYPAIR_get_num(kp->comp.k_stack, i);

            // Pushes the Key onto the stack
            COMPOSITE_KEY_push(k, tmp_key->value);

            // // Now we can use the CRTL interface to pass the new keys
            // if (EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_KEYGEN,
            //                       EVP_PKEY_CTRL_COMPOSITE_PUSH, 0, tmp_key->value) <= 0) {
            //     PKI_log_debug("Cannot add key via the CTRL interface");
            //     goto err;
            // }
        }
    }

    // All Done.
    return k;
}
#endif

PKI_X509_KEYPAIR *HSM_OPENSSL_X509_KEYPAIR_new( PKI_KEYPARAMS *kp, 
        URL *url, PKI_CRED *cred, HSM *driver ) {

    PKI_X509_KEYPAIR *ret = NULL;
    PKI_RSA_KEY *rsa = NULL;
    PKI_DSA_KEY *dsa = NULL;

#ifdef ENABLE_ECDSA
    PKI_EC_KEY *ec = NULL;
#endif

#ifdef ENABLE_OQS
    EVP_PKEY_CTX * ctx = NULL;
#endif

#ifdef ENABLE_COMPOSITE
    COMPOSITE_KEY * composite = NULL;
#endif

#ifdef ENABLE_COMBINED
    EVP_PKEY_COMBINED * combined = NULL;
#endif

    PKI_SCHEME_ID type = PKI_SCHEME_DEFAULT;

    if ( kp && kp->scheme != PKI_SCHEME_UNKNOWN ) type = kp->scheme;

    if((ret = PKI_X509_new ( PKI_DATATYPE_X509_KEYPAIR, NULL )) == NULL ) {
        PKI_ERROR(PKI_ERR_OBJECT_CREATE, "KeyPair");
        return NULL;
    }

    if((ret->value = (PKI_X509_KEYPAIR_VALUE *) EVP_PKEY_new()) == NULL ) {
        PKI_ERROR(PKI_ERR_OBJECT_CREATE, "KeyPair Value");
        return NULL;
    }

    if( _pki_rand_seed() == 0 ) {
        /* Probably low level of randomization available */
        PKI_log_debug("WARNING, low rand available!");
    }

    switch (type) {
        case PKI_SCHEME_RSA:
            if((rsa = _pki_rsakey_new( kp )) == NULL ) {
                if( ret ) HSM_OPENSSL_X509_KEYPAIR_free( ret );
                return NULL;
            };
            if(!EVP_PKEY_assign_RSA((EVP_PKEY *) ret->value, rsa)) {
                PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not assign RSA key");
                if( rsa ) RSA_free( rsa );
                if( ret ) HSM_OPENSSL_X509_KEYPAIR_free( ret );
                return NULL;
            };
            break;

        case PKI_SCHEME_DSA:
            if((dsa = _pki_dsakey_new( kp )) == NULL ) {
                if( ret ) HSM_OPENSSL_X509_KEYPAIR_free( ret );
                return(NULL);
            };
            if (!DSA_generate_key( dsa )) {
                PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, NULL);
                if( ret ) HSM_OPENSSL_X509_KEYPAIR_free( ret );
                return NULL;
            }
            if (!EVP_PKEY_assign_DSA((EVP_PKEY *)ret->value, dsa)) {
                PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not assign DSA key");
                if( dsa ) DSA_free ( dsa );
                if( ret ) HSM_OPENSSL_X509_KEYPAIR_free( ret );
                return NULL;
            }
            dsa=NULL;
            break;

#ifdef ENABLE_ECDSA

        case PKI_SCHEME_ECDSA:
            if((ec = _pki_ecdsakey_new( kp )) == NULL ) {
                if( ret ) HSM_OPENSSL_X509_KEYPAIR_free( ret );
                return(NULL);
            };
            if (!EVP_PKEY_assign_EC_KEY((EVP_PKEY *)ret->value,ec)){
                PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not assign ECDSA key");
                if( ec ) EC_KEY_free ( ec );
                if( ret ) HSM_OPENSSL_X509_KEYPAIR_free( ret );
                return NULL;
            }
            ec=NULL;
            break;

#ifdef ENABLE_COMPOSITE
        case PKI_SCHEME_COMPOSITE:
            if ((composite = _pki_composite_new(kp)) == NULL) {
                if (ret) HSM_OPENSSL_X509_KEYPAIR_free(ret);
                PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not initiate keypair generation");
                return NULL;
            };
            if (!EVP_PKEY_assign_COMPOSITE(ret->value, composite)) {
                if (ret) HSM_OPENSSL_X509_KEYPAIR_free(ret);
                PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not assign COMPOSITE key");
                if (composite) COMPOSITE_KEY_free(composite);
                return NULL;
            }
            composite=NULL;
            break;
#endif

#ifdef ENABLE_COMBINED
        case PKI_SCHEME_COMBINED:
        if ((combined = _pki_combined_new(kp)) == NULL) {
                if (ret) HSM_OPENSSL_X509_KEYPAIR_free(ret);
                PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not initiate keypair generation");
                return NULL;
            };
            if (!EVP_PKEY_assign_COMBINED(ret->value, combined)) {
                if (ret) HSM_OPENSSL_X509_KEYPAIR_free(ret);
                PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, "Can not assign COMBINED key");
                if (combined) COMBINED_KEY_free(combined);
                return NULL;
            }
            combined=NULL;
            break;
#endif

#endif // ENABLE_ECDSA

        default:

#ifdef ENABLE_OQS
            if ((ctx = _pki_get_evp_pkey_ctx(kp)) == NULL) {
                if (ret) HSM_OPENSSL_X509_KEYPAIR_free( ret );
                return NULL;
            }

            if (EVP_PKEY_keygen(ctx, (EVP_PKEY **)&(ret->value)) <= 0) {
                if (ret) HSM_OPENSSL_X509_KEYPAIR_free( ret );
                if (ctx) EVP_PKEY_CTX_free(ctx);
                return NULL;
            }
#else
            /* No recognized scheme */
            PKI_ERROR(PKI_ERR_HSM_SCHEME_UNSUPPORTED, "%d", type );
            if( ret ) HSM_OPENSSL_X509_KEYPAIR_free( ret );
            return NULL;

#endif // ENABLE_OQS

    }

    /* Let's return the PKEY infrastructure */
    return ( ret );
}

/* Key Free function */
void HSM_OPENSSL_X509_KEYPAIR_free ( PKI_X509_KEYPAIR *pkey ) {

    if( !pkey) return;

    PKI_X509_free ( pkey );

    return;
}

// OpenSSL Fix
// When writing PEM formatted Keys the wrong version "0" is
// used by the default EVP_PKEY_ write functions for EC keys,
// we have to provide our own function until OpenSSL solve
// this issue

int OPENSSL_HSM_write_bio_PrivateKey (BIO *bp, EVP_PKEY *x, 
        const EVP_CIPHER *enc, unsigned char *out_buffer, int klen, 
        pem_password_cb *cb, void *u) {

    int ret = PKI_ERR;

    // Input Check
    if (!x || !bp) return PKI_ERR;

    // Different functions depending on the Key type
    switch(EVP_PKEY_type(EVP_PKEY_id(x)))
    {

#ifdef ENABLE_ECDSA
        case EVP_PKEY_EC: {
# if OPENSSL_VERSION_NUMBER < 0x1010000fL
            ret = PEM_write_bio_ECPrivateKey(bp, 
                x->pkey.ec, enc, (unsigned char *) out_buffer, klen, cb, u);
# else
            ret = PEM_write_bio_ECPrivateKey(bp, 
                EVP_PKEY_get0_EC_KEY(x), enc, (unsigned char *) out_buffer, klen, cb, u);
# endif
            if (!ret) {
                PKI_DEBUG("Internal Error while encoding EC Key (PEM).");
                return PKI_ERR;
            }
        } break;
#endif

        default: {
            if ((ret = PEM_write_bio_PKCS8PrivateKey(bp, x, enc, 
                (char *) out_buffer, klen, cb, u)) != 1) {
                // Debug Info
                PKI_DEBUG("Key Type NOT supported (%d)", 
                    EVP_PKEY_type(EVP_PKEY_id(x)));
                // Error Condition
                return PKI_ERR;
            }
        }
    }

    // All Done
    return ret;
}

// OpenSSL Fix
//
// Strangely enough OpenSSL does not provide an EVP_PKEY_dup()
// function, we supply it

EVP_PKEY *OPENSSL_HSM_KEYPAIR_dup(EVP_PKEY *kVal)
{
    EVP_PKEY *ret = NULL;

    if(!kVal) return NULL;

    if ((ret = EVP_PKEY_new()) == NULL) return NULL;

    if (!EVP_PKEY_copy_parameters(ret, kVal)) return NULL;

    switch (EVP_PKEY_type(EVP_PKEY_id(kVal)))
    {

        case EVP_PKEY_RSA: {
            RSA *rsa = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
            if (((rsa = EVP_PKEY_get0_RSA(kVal)) == NULL) ||
#else
            if (((rsa = (RSA *)EVP_PKEY_get0(kVal)) == NULL) ||
#endif
                                   (!EVP_PKEY_set1_RSA(ret, rsa))) {
                return NULL;
            }
        } break;

        case EVP_PKEY_DH: {
            DH *dh = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
            if ( ((dh = EVP_PKEY_get0_DH(kVal)) == NULL) ||
#else
            if ( ((dh = (DH *)EVP_PKEY_get0(kVal)) == NULL) ||
#endif
                                   (!EVP_PKEY_set1_DH(ret, dh))) {
                return NULL;
            }
        } break;

#ifdef ENABLE_ECDSA
        case EVP_PKEY_EC: {
            EC_KEY * ec = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
            if (((ec = EVP_PKEY_get0_EC_KEY(kVal)) == NULL) ||
#else
            if (((ec = (EC_KEY *)EVP_PKEY_get0(kVal)) == NULL) ||
#endif
                                 (!EVP_PKEY_set1_EC_KEY(ret, ec))) {
                return NULL;
            }
        } break;
#endif

#ifdef ENABLE_DSA
        case EVP_PKEY_DSA: {
            DSA *dsa = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
            if ( ((dsa = EVP_PKEY_get0_DSA(kVal)) == NULL) ||
#else
            if ( ((dsa = (DSA *)EVP_PKEY_get0(kVal)) == NULL) ||
#endif
                                 (!EVP_PKEY_set1_DSA(ret, dsa))) {
                return NULL;
            }
        } break;
#endif

        default: {
            PKI_ERROR(PKI_ERR_ALGOR_UNKNOWN, NULL);
            return NULL;
        } break;
    }

    return ret;


};

