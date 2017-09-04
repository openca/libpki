/* PKI_TOKEN write/load object management */

#include <libpki/pki.h>

/* ----------------------- Internal PKCS12 functions ----------------------- */

enum bag_datatype_st {
  BAG_DATATYPE_ALL = 0,
  BAG_DATATYPE_KEYPAIR,
  BAG_DATATYPE_CERT,
  BAG_DATATYPE_CACERT,
  BAG_DATATYPE_OTHERCERTS,
  BAG_DATATYPE_UNKNOWN
};

/* Prototypes */

static STACK_OF(PKCS12_SAFEBAG) * _get_bags(
		const PKI_X509_PKCS12 * const p12,
		const char * const pwd);

static void * _get_bags_data(
		const STACK_OF(PKCS12_SAFEBAG) * bags, 
          	int                              dataType,
		const char                     * const pwd );

static void * _get_bag_value(PKCS12_SAFEBAG * bag,
		int                           dataType,
		const char                  * const pwd );

static PKI_X509_CERT * _get_cacert(
		const PKI_X509_PKCS12 * const p12, 
            	const PKI_X509_CERT * const x,
		const char *pwd);

static PKI_X509_CERT_STACK * _get_othercerts_stack(
		const PKI_X509_PKCS12 * const p12, 
            	const PKI_X509_CERT * const x,
		const char * const pwd);

static PKI_X509_KEYPAIR_STACK * _get_keypair_stack(
		const PKI_X509_PKCS12 * const p12, 
                const char * const pwd);

/* Internal Functions */

static STACK_OF(PKCS12_SAFEBAG) * _get_bags(
		const PKI_X509_PKCS12 * const p12,
		const char * const pwd) {

  STACK_OF(PKCS7) *asafes = NULL;
  STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
  STACK_OF(PKCS12_SAFEBAG) *ret = NULL;

  int i, bagnid;
  PKCS7 *p7 = NULL;

  if ( !p12 || !p12->value ) return NULL;

  if (!( asafes = PKCS12_unpack_authsafes(p12->value)))
    return (NULL);

  if((ret = sk_PKCS12_SAFEBAG_new_null()) == NULL ) {
    PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
    return NULL;
  }

  for (i = 0; i < sk_PKCS7_num (asafes); i++) {
    PKCS12_SAFEBAG *oneBag = NULL;

    p7 = sk_PKCS7_value (asafes, i);
    bagnid = OBJ_obj2nid (p7->type);
    if (bagnid == NID_pkcs7_data) {
      bags = PKCS12_unpack_p7data(p7);
    } else if (bagnid == NID_pkcs7_encrypted) {
      if( pwd) {
        bags=PKCS12_unpack_p7encdata(p7,pwd,(int)strlen(pwd));
      } else {
        bags = PKCS12_unpack_p7encdata(p7, NULL, 0);
      }
    } else {
      continue;
    }

    if (!bags) {
      PKI_DEBUG("No Bags got from PKCS7 # %d", i);
      continue;
    }

    while ((oneBag = sk_PKCS12_SAFEBAG_pop ( bags )) != NULL ){
      sk_PKCS12_SAFEBAG_push( ret, oneBag );
    }

    sk_PKCS12_SAFEBAG_free ( bags );
    bags = NULL;
  }

  if( sk_PKCS12_SAFEBAG_num( ret ) < 1 ) {
    PKI_log_debug("%s:%d::No SAFEBAGS found in P12!",
          __FILE__, __LINE__ );
    sk_PKCS12_SAFEBAG_free ( ret );
    return ( NULL );
  }

  return ( ret );
}

static void * _get_bags_data (
		const STACK_OF(PKCS12_SAFEBAG) * bags, 
          	int                              dataType,
		const char                     * const pwd ) {

  int i;

  void *ret = NULL;
  PKCS12_SAFEBAG *bag = NULL;

  if( !bags ) {
    PKI_log_debug("_get_bags_data()::ERROR, no bags passed!");
    return ( NULL );
  }

  switch ( dataType ) {
    case BAG_DATATYPE_KEYPAIR:
      ret = PKI_STACK_X509_KEYPAIR_new();
      break;
    case BAG_DATATYPE_CERT:
    case BAG_DATATYPE_CACERT:
    case BAG_DATATYPE_OTHERCERTS:
      ret = PKI_STACK_X509_CERT_new();
      break;
    default:
      return ( NULL );
  }

  if( !ret ) {
    PKI_log_debug("%s:%d::Memory Error", __FILE__, __LINE__ );
    return ( NULL );
  }

  for ( i=0 ; i < sk_PKCS12_SAFEBAG_num ( bags ); i++ ) {
    PKI_STACK *bag_sk = NULL;
    void *el = NULL;

    if((bag = sk_PKCS12_SAFEBAG_value ( bags, i )) == NULL ) {
      PKI_log_debug("_get_bags_data()::No BaG got from "
        "bags # %d", i );
      continue;
    };

    if((bag_sk = _get_bag_value ( bag, dataType, pwd )) == NULL ) {
      // PKI_log_debug("_get_bags_data()::No BaG_SK got from "
      //   "bags # %d", i );
      continue;
    }

    // PKI_log_debug("_get_bags_data()::Got %d data items (i=%d)",
    //   PKI_STACK_elements( bag_sk ), i);

    while ((el = PKI_STACK_pop ( bag_sk )) != NULL) {
      PKI_STACK_push( ret, el );
    }

    if (bag_sk) PKI_STACK_free(bag_sk);
    bag_sk = NULL;
  }

  return ( ret );
}


static void * _get_bag_value(
		PKCS12_SAFEBAG *bag, 
		int dataType,
		const char * const pwd ) {

  int type;

  PKI_X509_KEYPAIR_VALUE *pkey = NULL;
  PKI_X509_KEYPAIR *k = NULL;
  PKI_X509_CERT *cert = NULL;
  PKI_X509_CERT_VALUE *cert_val = NULL;

  const PKCS8_PRIV_KEY_INFO *p8 = NULL;

  void *ret = NULL;
  PKI_STACK *sk = NULL;

  type = M_PKCS12_bag_type ( bag );

  switch ( type ) {

    case NID_keyBag: {
        if( dataType != BAG_DATATYPE_KEYPAIR ) {
          return ( NULL );
        };
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
	p8 = PKCS12_SAFEBAG_get0_p8inf(bag);
#else
        p8 = bag->value.keybag;
#endif
        if (!(pkey = EVP_PKCS82PKEY((PKCS8_PRIV_KEY_INFO *)p8))) {
          return (NULL);
        }
        // print_attribs (out, p8->attributes, "Key Attributes");
        // PEM_write_bio_PrivateKey (out, pkey, enc, NULL, 0, NULL, pempass);
        // ret = EVP_PKEY_new();
        // EVP_PKEY_copy_parameters(ret, pkey);
        if (( k = PKI_X509_KEYPAIR_new_null()) == NULL ) {
          return NULL;
        }
        k->value = pkey;
        ret = k;
      } break;

    case NID_pkcs8ShroudedKeyBag: {
      if( dataType != BAG_DATATYPE_KEYPAIR ) {
        return ( NULL );
      };
      if (!(p8 = PKCS12_decrypt_skey(bag, pwd, (int) strlen(pwd)))) {
        return ( NULL );
      }
      if (!(pkey = EVP_PKCS82PKEY((PKCS8_PRIV_KEY_INFO *)p8))) {
        // PKCS8_PRIV_KEY_INFO_free(p8);
        return (NULL);
      }
      if (( k = PKI_X509_KEYPAIR_new_null()) == NULL ) {
        return NULL;
      }
      k->value = pkey;
      ret = k;
    } break;

    case NID_certBag: {
      if( (dataType != BAG_DATATYPE_CERT ) && 
          ( dataType != BAG_DATATYPE_CACERT ) &&
          (dataType != BAG_DATATYPE_OTHERCERTS)) {
        return ( NULL );
      }

      // Checks it is not a key bag
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
      if (PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID)) {
        if (dataType != BAG_DATATYPE_CERT) return NULL;
      }
#else
      if (PKCS12_get_attr(bag, NID_localKeyID)) {
        if (dataType != BAG_DATATYPE_CERT) return NULL;
      }
#endif

      // print_attribs (out, bag->attrib, "Bag Attributes");
      if (M_PKCS12_cert_bag_type(bag) != NID_x509Certificate ) {
        return ( NULL );
      }
      if (!(cert_val = PKCS12_certbag2x509(bag))) {
        return ( NULL );
      }
      if(( cert = PKI_X509_CERT_new_null ()) == NULL ) {
        X509_free ( cert_val );
        return NULL;
      }

      cert->value = cert_val;
      ret = cert;
    } break;

    case NID_safeContentsBag: {
      // PKI_log_debug("Found Bag => TYPE is NID_safeContentsBag");
      const STACK_OF(PKCS12_SAFEBAG) * safes = NULL;

      // Get the SafeBags
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
      safes = PKCS12_SAFEBAG_get0_safes(bag);
#else
      safes = bag->value.safes;
#endif

      // If no safe bags, let's return NULL
      if (!safes) return NULL;

      // Returns the SafeBags Data
      return _get_bags_data(safes, dataType, pwd);

    } break;

    default: {
      PKI_log_debug("ERROR::P12 BAG type not supported (%d)",
        type );
      return (NULL);
    }
  }

  switch ( dataType ) {
    case BAG_DATATYPE_KEYPAIR:
      sk = PKI_STACK_X509_KEYPAIR_new();
      PKI_STACK_X509_KEYPAIR_push (
          (PKI_X509_KEYPAIR_STACK *) sk, 
          (PKI_X509_KEYPAIR *) ret );
      break;
    case BAG_DATATYPE_CERT:
    case BAG_DATATYPE_CACERT:
    case BAG_DATATYPE_OTHERCERTS:
      sk = PKI_STACK_X509_CERT_new();
      PKI_STACK_X509_CERT_push ( (PKI_X509_CERT_STACK *) sk, 
          (PKI_X509_CERT *) ret );
      break;
  }

  return ( sk );
}

static PKI_X509_CERT_STACK * _get_cert_stack(
		const PKI_X509_PKCS12 * const p12, 
		const char * const pwd) {

  STACK_OF(PKCS12_SAFEBAG) *sk_bags = NULL;
  PKI_X509_CERT_STACK *ret = NULL;

  // PKI_log_debug("_get_cert_stack()::Start()!");

  if((sk_bags = _get_bags ( p12, pwd )) == NULL ) {
    PKI_log_debug("_get_cert_stack()::No Bags found!");
    return ( NULL );
  }

  // PKI_log_debug("_get_cert_stack()::Got %d Bags found!", 
  //         sk_PKCS12_SAFEBAG_num( sk_bags) );
  ret = _get_bags_data ( sk_bags, BAG_DATATYPE_CERT, pwd );
  // PKI_log_debug("_get_cert_stack()::Got %d Certs back", 
  //     PKI_STACK_X509_CERT_elements( ret ));

  // PKI_log_debug("_get_cert_stack()::END()!");
  return ( ret );
}


static PKI_X509_CERT * _get_cacert (
		const PKI_X509_PKCS12 * const p12, 
          	const PKI_X509_CERT * const client,
		const char * const pwd) {

  STACK_OF(PKCS12_SAFEBAG) *sk_bags = NULL;
  PKI_X509_CERT_STACK *ca_sk = NULL;

  PKI_X509_CERT *cacert = NULL;
  PKI_X509_CERT *ret = NULL;

  const PKI_X509_CERT *x = NULL;

  PKI_CRED cred;
  PKI_CRED *cred_pnt = NULL;

  int i = 0;

  if (!p12 || !p12->value) return NULL;

  if ((sk_bags = _get_bags(p12, pwd)) == NULL) return NULL;

  x = client;

  if( pwd ) {
    cred.password = pwd;
    cred_pnt = &cred;
  }

  if (x == NULL) {
    if ((x = PKI_X509_PKCS12_get_cert( p12, cred_pnt )) == NULL ) {
      PKI_DEBUG("Can not find user cert in P12");
      return NULL;
    }
  }

  if ((ca_sk = _get_bags_data(sk_bags, BAG_DATATYPE_CACERT, pwd)) == NULL) {
    // No Bags DATA found
    return NULL;
  }

  for (i = 0; i < PKI_STACK_X509_CERT_elements(ca_sk); i++ ) {

    if ((cacert = PKI_STACK_X509_CERT_get_num(ca_sk, i)) == NULL) continue;

    if ((X509_check_issued(cacert->value, x->value)) == X509_V_OK) {
      // Found CA Cert - Exit Cycle
      break;
    }

    // Resets the pointer
    cacert = NULL;
  }

  // Duplicate the CA certificate
  if (cacert) ret = PKI_X509_CERT_dup(cacert);

  // Free allocated memory
  if (!client && x) PKI_X509_CERT_free((PKI_X509_CERT *)x);
  if (ca_sk) PKI_STACK_X509_CERT_free(ca_sk);

  return ret;
}

static PKI_X509_CERT_STACK * _get_othercerts_stack(
			const PKI_X509_PKCS12 * const p12, 
          		const PKI_X509_CERT * const cacert,
			const char * const pwd){

  STACK_OF(PKCS12_SAFEBAG) *sk_bags = NULL;
  PKI_X509_CERT_STACK *x_sk = NULL;
  const PKI_X509_CERT *ca_cert = NULL;
  PKI_X509_CERT *user_cert = NULL;
  PKI_X509_CERT_VALUE *ca_cert_val = NULL;
  PKI_X509_CERT_VALUE *user_cert_val = NULL;
  PKI_CRED cred;

  int i=0;

  memset ( &cred, 0L, sizeof( cred ));

  if (!p12 || !p12->value) return NULL;

  if ((sk_bags = _get_bags(p12, pwd)) == NULL) return NULL;

  if ((x_sk = _get_bags_data(sk_bags, BAG_DATATYPE_OTHERCERTS, pwd)) == NULL) {
    return ( x_sk );
  }

  if (pwd) cred.password = pwd;

  if (!cacert) ca_cert = _get_cacert( p12, NULL, pwd);
  else ca_cert = cacert;

  if (ca_cert) ca_cert_val = ca_cert->value;

  user_cert = PKI_X509_PKCS12_get_cert(p12, &cred);
  if (user_cert) user_cert_val = user_cert->value;

  if (!ca_cert_val && !user_cert_val) return x_sk;

  for (i = 0; i < PKI_STACK_X509_CERT_elements(x_sk); i++) {

    PKI_X509_CERT *x = NULL;

    x = PKI_STACK_X509_CERT_get_num ( x_sk, i );
    if( (ca_cert) && (X509_cmp( x->value, ca_cert_val) == 0) ) {
      x = PKI_STACK_X509_CERT_del_num ( x_sk, i );
      PKI_X509_CERT_free ( x );
      continue;
    }

    if (user_cert_val && X509_cmp (x->value, user_cert_val ) == 0) {
      x = PKI_STACK_X509_CERT_del_num ( x_sk, i );
      PKI_X509_CERT_free ( x );
      continue;
    }
  }

  if (!cacert && ca_cert) PKI_X509_CERT_free((PKI_X509_CERT *)ca_cert);
  if (user_cert) PKI_X509_CERT_free (user_cert);

  return ( x_sk );
}

static PKI_X509_KEYPAIR_STACK * _get_keypair_stack(
		const PKI_X509_PKCS12 * const p12, 
                const char * const pwd) {

  STACK_OF(PKCS12_SAFEBAG) *sk_bags = NULL;
  PKI_X509_KEYPAIR_STACK *ret = NULL;

  if ((sk_bags = _get_bags ( p12, pwd )) == NULL) {
    PKI_DEBUG("No Keypair found");
    return NULL;
  }

  ret = _get_bags_data(sk_bags, BAG_DATATYPE_KEYPAIR, pwd);
  return ( ret );
}

static int _pki_p12_copy_bag_attr(PKCS12_SAFEBAG         * bag, 
  				  const PKI_X509_KEYPAIR * const k,
				  int                      nid) {

  int idx;
  X509_ATTRIBUTE *attr;
  STACK_OF(X509_ATTRIBUTE) * attr_sk = NULL;

  if( !k || !k->value || !bag ) return PKI_ERR;

  idx = EVP_PKEY_get_attr_by_NID(k->value, nid, -1);

  if (idx < 0) return (PKI_OK);

  attr = EVP_PKEY_get_attr(k->value, idx);
#if OPENSSL_VERSION_NUMBER > 0x1010000fL
  attr_sk = (STACK_OF(X509_ATTRIBUTE) *)PKCS12_SAFEBAG_get0_attrs(bag);
#else
  attr_sk = bag->attrib;
#endif

  if (!X509at_add1_attr(&attr_sk, attr)) return PKI_ERR;

  return (PKI_OK);
}
/* ----------------------- Exported PKCS12 functions ----------------------- */

/*! \brief Allocates memory for a new PKI_X509_PKCS12 object */

PKI_X509_PKCS12 *PKI_X509_PKCS12_new_null ( void ) {

  PKI_X509_PKCS12 *p12 = NULL;

  if((p12 = PKI_X509_new( PKI_DATATYPE_X509_PKCS12, NULL )) == NULL ) {
    return NULL;
  }

  /* Returns the result */
  return ( p12 );
}

/*! \brief Releases the memory associated with a PKI_X509_PKCS12 object */

void PKI_X509_PKCS12_free ( PKI_X509_PKCS12 *p12 ) {

  if ( p12 ) PKI_X509_free ( p12 );

  return;
}

void PKI_X509_PKCS12_free_void ( void *p12 ) {
  
  if( p12 ) PKI_X509_free ( (PKI_X509_PKCS12 *) p12 );

  return;
}

/*! \brief Verifies the MAC against the passed credentials */

int PKI_X509_PKCS12_verify_cred(const PKI_X509_PKCS12 * const p12,
				const PKI_CRED * const cred ) {

  int macVerified = PKI_ERR;

  if( !cred || !cred->password ) {
    if( PKCS12_verify_mac( p12->value, NULL, 0) ) {
      macVerified = PKI_OK;
    }
  } else if (PKCS12_verify_mac ( p12->value, cred->password, -1)) {
    macVerified = PKI_OK;
         }

  return macVerified;
}

/*! \brief Returns the keypair present in a PKI_X509_PKCS12 object */

PKI_X509_KEYPAIR *PKI_X509_PKCS12_get_keypair(
				const PKI_X509_PKCS12 * const p12, 
              			const PKI_CRED * const cred ) {

  PKI_X509_KEYPAIR_STACK *sk = NULL;
  PKI_X509_KEYPAIR *ret = NULL;
  char *pwd = NULL;

  if( cred ) pwd = (char *) cred->password;

  if((sk = _get_keypair_stack( p12, pwd)) == NULL ) {
    PKI_log_debug("PKI_X509_PKCS12_get_keypair()::Returned stack is "
      "empty!");
    return ( NULL );
  }

  ret = PKI_STACK_X509_KEYPAIR_pop( sk );

  PKI_STACK_X509_KEYPAIR_free ( sk );

  return ( ret );
}

/*! \brief Returns a copy of the client (user) cert present 
 *         in a PKI_X509_PKCS12 object */

PKI_X509_CERT *PKI_X509_PKCS12_get_cert(
			const PKI_X509_PKCS12 * const p12,
			const PKI_CRED * const cred ) {

  PKI_X509_CERT_STACK *sk = NULL;
  PKI_X509_CERT *ret = NULL;
  PKI_X509_CERT *x = NULL;
  PKI_X509_KEYPAIR *key = NULL;

  int i = 0;

  char *pwd = NULL;

  if( !p12 || !p12->value ) return NULL;

  if( cred ) pwd = (char *) cred->password;

  if((key = PKI_X509_PKCS12_get_keypair ( p12, cred )) == NULL ) {
    PKI_log_debug("ERROR::PKCS#12 without private key!");
  }

  if((sk = _get_cert_stack( p12, pwd)) == NULL ) {
    return ( NULL );
  }

  for( i=0; i < PKI_STACK_X509_CERT_elements( sk ); i++ ) {
    if((x = PKI_STACK_X509_CERT_get_num( sk, i )) == NULL ) {
      continue;
    }
    if(key && X509_check_private_key(x->value, key->value)) {
      // char *subj;

      // subj = PKI_X509_CERT_get_parsed(x,
      //     PKI_X509_DATA_SUBJECT );
      /* Cert and Key match, we found our cert! */
      ret = PKI_X509_dup( x );
      // PKI_log_debug("Cert Matching private Key: %s", subj );
    } else {
      // char *subj;

      // subj = PKI_X509_CERT_get_parsed(x,
      //     PKI_X509_DATA_SUBJECT );
      // PKI_log_debug("Cert not matching key: %s", subj );
      // PKI_Free ( subj );
    }
  }

  PKI_STACK_X509_CERT_free_all ( sk );

  return ( ret );
}

/*! \brief Returns the CA cert present (if) in a PKI_X509_PKCS12 object */

PKI_X509_CERT *PKI_X509_PKCS12_get_cacert(
			const PKI_X509_PKCS12 * const p12, 
              		const PKI_CRED * const cred ) {

  PKI_X509_CERT *ret = NULL;
  char *pwd = NULL;

  if (!p12 || !p12->value) return NULL;

  if (cred) pwd = (char *) cred->password;

  if ((ret = _get_cacert( p12, NULL, pwd)) == NULL) return NULL;

  return ( ret );
}

/*! \brief Returns all the certs besides the CA and the user cert present (if)
 *         in a PKI_X509_PKCS12 object */

PKI_X509_CERT_STACK *PKI_X509_PKCS12_get_otherCerts(
			const PKI_X509_PKCS12 * const p12, 
              		const PKI_CRED * const cred) {

  PKI_X509_CERT_STACK *sk = NULL;
  PKI_X509_CERT *cacert = NULL;
  char *pwd = NULL;

  if (!p12 || !p12->value) return NULL;

  if (cred) pwd = (char *) cred->password;

  if ((cacert = _get_cacert(p12, NULL, pwd)) != NULL)
  	sk = _get_othercerts_stack( p12, cacert, pwd);

  return sk;
}

int PKI_X509_PKCS12_TOKEN_export(
			const PKI_TOKEN * const tk,
			const URL * const url,
			int format, 
                	HSM *hsm ) {

  if (!tk || !url) return PKI_ERR;

  /*
  p12 = PKCS12_create(cpass, name, key, ucert, certs,
                                key_pbe, cert_pbe, iter, -1, keytype);

        if (!p12)
                {
                ERR_print_errors (bio_err);
                goto export_end;
                }

        if (maciter != -1)
                PKCS12_set_mac(p12, mpass, -1, NULL, 0, maciter, NULL);
  
  i2d_PKCS12_bio(out, p12);
  */

  return (PKI_ERR);
}

/*! \brief Generates a new PKI_X509_PKCS12 object from a PKI_X509_PKCS12_DATA obj */

PKI_X509_PKCS12 * PKI_X509_PKCS12_new(
			const PKI_X509_PKCS12_DATA * const p12_data, 
              		const PKI_CRED * const cred) {

  PKI_X509_PKCS12 *ret = NULL;
  char *pass = NULL;
  int mac_iter = -1;

  if( !p12_data ) return ( NULL );

  if(( ret = PKI_X509_PKCS12_new_null()) == NULL ) {
    return NULL;
  }

  /* let's add the safes */
  if((ret->value = PKCS12_add_safes((PKI_X509_PKCS12_DATA *)p12_data, 
				  			0)) == NULL ) {
    PKI_X509_PKCS12_free ( ret );
    return NULL;
  }

  ret->cred = PKI_CRED_dup ( cred );

  if( cred && cred->password ) {
    pass = (char *) cred->password;
    mac_iter = 1;
  }

        if ((mac_iter != -1) &&
          !PKCS12_set_mac(ret->value, pass, -1, NULL, 0, mac_iter, NULL)){
    PKI_log_debug("ERROR, can not set mac iter!");
    PKI_X509_PKCS12_free (ret);
    return ( NULL );
  }

  return ( ret );
}

/*! \brief Generates an empty PKI_X509_PKCS12_DATA object to be populated before
 *         using it to create a PKCS12 */

PKI_X509_PKCS12_DATA *PKI_X509_PKCS12_DATA_new ( void ) {
  PKI_X509_PKCS12_DATA *ret = NULL;

  if((ret = sk_PKCS7_new_null()) == NULL ) {
    PKI_log_debug("Memory Error!");
    return ( NULL );
  }

  return ( ret );
}

void PKI_X509_PKCS12_DATA_free ( PKI_X509_PKCS12_DATA *p12_data ) {

  if( !p12_data ) return;

        sk_PKCS7_pop_free(p12_data, PKCS7_free);

  return;
}

/*! \brief Adds a Keypair (LocalKey) to the PKCS12 */

int PKI_X509_PKCS12_DATA_add_keypair(
			PKI_X509_PKCS12_DATA *data, 
        		const PKI_X509_KEYPAIR * const keypair,
			const PKI_CRED * const cred ) {

  STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
  PKCS12_SAFEBAG *bag = NULL;
  char *pass = NULL;

  PKI_DIGEST *keyid;
  int keytype = 0;

  /* Check Parameters */
  if( !data || !keypair ) return (PKI_ERR);

  if( cred && cred->password ) {
    pass = (char *) cred->password;
  }

  /* Get the Digest of the Public key */
  keyid = PKI_X509_KEYPAIR_pub_digest ( keypair, PKI_DIGEST_ALG_SHA1 );

  /* Builds the bag for the PKCS12 */
  bag = PKCS12_add_key(&bags, keypair->value, keytype, 
    PKCS12_DEFAULT_ITER, NID_pbe_WithSHA1And3_Key_TripleDES_CBC, 
      pass);

  if (!bag) {
    PKI_log_debug("ERROR::Can not add bag to P12 (%s)",
      ERR_error_string(ERR_get_error(), NULL ));
    goto err;
  }

  if ((_pki_p12_copy_bag_attr(bag, keypair, NID_ms_csp_name)) == PKI_ERR ) {
    PKI_log_debug("ERROR::Can not copy bag attributes(%s)!",
      ERR_error_string(ERR_get_error(),NULL));
    goto err;
  }
  if ((_pki_p12_copy_bag_attr(bag, keypair, 
      NID_localKeyID)) == PKI_ERR ) {
    PKI_log_debug("ERROR::Can not copy bag attributes (%s)!",
      ERR_error_string(ERR_get_error(), NULL));
    goto err;
  }

  if( keyid ) {
    if(!PKCS12_add_localkeyid( bag, keyid->digest, 
            (int) keyid->size )) {
      PKI_log_debug("ERROR::Can not add p12 localkeyid (%s)!",
        ERR_error_string(ERR_get_error(), NULL));
      goto err;
    }
  }

  if (bags && !PKCS12_add_safe(&data, bags, -1, 0, NULL)) {
    PKI_log_debug("ERROR::Can not add bags to p12 (%s)!",
      ERR_error_string(ERR_get_error(), NULL));
                goto err;
  }

  sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
  PKI_DIGEST_free ( keyid );

  return (PKI_OK);

err:

  if (keyid) PKI_DIGEST_free ( keyid );
  if (bags) sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);

  return ( PKI_ERR );
}

/*! \brief Adds user certificate, cacertificate and trusted certs to P12 */

int PKI_X509_PKCS12_DATA_add_certs (
			PKI_X509_PKCS12_DATA *data, 
   			const PKI_X509_CERT * const cert,
			const PKI_X509_CERT * const cacert, 
      			const PKI_X509_CERT_STACK * const trusted,
			const PKI_CRED * const cred ) {

  STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
  PKCS12_SAFEBAG *bag = NULL;
  PKI_X509_KEYPAIR *keypair = NULL;
  PKI_DIGEST *keyid = NULL;

  const PKI_X509_KEYPAIR_VALUE *pubKey = NULL;

  char *name = NULL;
  char *pass = NULL;

  int nid_cert = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
  int iter = PKCS12_DEFAULT_ITER;

  if (!cert || !cert->value) return PKI_ERR;

  if (cred && cred->password) pass = (char *) cred->password;

  /* Get the Digest of the Public key */
  if ((pubKey = PKI_X509_CERT_get_data(cert, 
				       PKI_X509_DATA_KEYPAIR_VALUE)) == NULL) {
    PKI_ERROR(PKI_ERR_GENERAL, "Can not retrieve pubKey from the certificate");
    return ( PKI_ERR );
  }

  if ((keypair = PKI_X509_new(PKI_DATATYPE_X509_KEYPAIR, NULL)) == NULL) {
    PKI_ERROR(PKI_ERR_X509_KEYPAIR_GENERATION, NULL);
    return PKI_ERR;
  }

  keypair->value = (PKI_X509_KEYPAIR *)pubKey;

  if ((keyid = PKI_X509_KEYPAIR_pub_digest(keypair, 
				  	   PKI_DIGEST_ALG_SHA1)) == NULL) {
    PKI_ERROR(PKI_ERR_GENERAL, "Can not get keypair digest");
    return ( PKI_ERR );
  }

  keypair->value = NULL;
  PKI_X509_KEYPAIR_free ( keypair );

  if ((bag = PKCS12_add_cert(&bags, cert->value )) == NULL)
  {
    PKI_ERROR(PKI_ERR_GENERAL, "Can not add cert bag to the list of bags");
    return ( PKI_ERR );
  }

  name = PKI_X509_CERT_get_parsed( cert, PKI_X509_DATA_SUBJECT);
  if (name && !PKCS12_add_friendlyname(bag, name, -1))
  {
    PKI_ERROR(PKI_ERR_GENERAL, "can not add friendly name");
    PKI_DIGEST_free ( keyid );
    return ( PKI_ERR );
  }
  PKI_Free(name);
  name = NULL; // Safety

  if (keyid->size && !PKCS12_add_localkeyid(bag, keyid->digest, (int) keyid->size))
  {
    PKI_ERROR(PKI_ERR_GENERAL, "can not add localkeyid");
    PKI_DIGEST_free ( keyid );
    return ( PKI_ERR );
  };

  /* Let's free some memory */
  PKI_DIGEST_free ( keyid );

  /* Adds the CA certificate */
  if (cacert && cacert->value)
  {
    if (!PKCS12_add_cert(&bags, cacert->value ))
    {
      PKI_ERROR(PKI_ERR_GENERAL, "can not add CA cert to P12");
      return PKI_ERR;
    }
  }

  /* Adds all the other certs */
  if (trusted)
  {
    int i = 0;

    for (i = 0; i < PKI_STACK_X509_CERT_elements (trusted); i++)
    {
      PKI_X509_CERT *x = NULL;

      x = PKI_STACK_X509_CERT_get_num(trusted, i);
      if (x->value)
      {
        if (!PKCS12_add_cert(&bags, x->value))
          PKI_ERROR(PKI_ERR_GENERAL, "can not add certificate in bag");
      }
    }
  }

  if (bags && !PKCS12_add_safe(&data, bags, nid_cert, iter, pass))
  {
    PKI_ERROR(PKI_ERR_GENERAL, "can not add data to PKCS12_DATA object");
    return PKI_ERR;
  }

  /* Free more memory */
  sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);

  return PKI_OK;
}

/*! \brief Adds a 'generic' list of certs to P12 */

int PKI_X509_PKCS12_DATA_add_other_certs(
			PKI_X509_PKCS12_DATA *data, 
        		const PKI_X509_CERT_STACK * const sk,
			const PKI_CRED * const cred ) {

  STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
  char *pass = NULL;

  int nid_cert = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
  int iter = PKCS12_DEFAULT_ITER;
  int i = 0;

  if( !data || !sk ) return ( PKI_ERR );

  if( cred && cred->password ) {
    pass = (char *) cred->password;
  }

  for(i = 0; i < PKI_STACK_X509_CERT_elements (sk); i++) {
    PKI_X509_CERT *x = NULL;

    x = PKI_STACK_X509_CERT_get_num ( sk, i);
    if( x->value ) {
      if (!PKCS12_add_cert(&bags, x->value)) {
        PKI_log_debug("ERROR, can not add cert in bag");
      }
    }
  }

  if (bags && !PKCS12_add_safe(&data, bags, nid_cert, iter, pass)) {
    PKI_log_err("ERROR, can not add data to PKCS12_DATA obj!");
    sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
    return ( PKI_ERR );
  }

  sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);

  return ( PKI_OK );

}

/* ------------------------ PEM <-> INTERNAL Macros ------------------- */

PKI_X509_PKCS12_VALUE *PEM_read_bio_PKCS12( PKI_IO *bp ) {
#if OPENSSL_VERSION_NUMBER < 0x0090800fL
  return (PKI_X509_PKCS12_VALUE *) 
    PEM_ASN1_read_bio( (char *(*)()) d2i_PKCS12, 
        PKI_X509_PKCS12_PEM_ARMOUR, bp, NULL, NULL, NULL);
#else
  return (PKI_X509_PKCS12_VALUE *) 
    PEM_ASN1_read_bio( (void *(*)()) d2i_PKCS12, 
        PKI_X509_PKCS12_PEM_ARMOUR, bp, NULL, NULL, NULL);
#endif
}

int PEM_write_bio_PKCS12( PKI_IO *bp, 
			  const PKI_X509_PKCS12_VALUE * o ) {

  return PEM_ASN1_write_bio ( (int (*)())i2d_PKCS12, 
      PKI_X509_PKCS12_PEM_ARMOUR, bp, (char *) o, NULL, 
        NULL, 0, NULL, NULL );
}

