#include "ocsprov.h"

// static struct keytype_desc_st PrivateKeyInfo_dilithium2_desc = {
//     "dilithium2", oqs_dilithium2_keymgmt_functions, "PrivateKeyInfo", 0, (0x01), ((void *)0), ((void *)0), ((void *)0), oqsx_d2i_PKCS8, ((void *)0), ((void *)0), oqsx_key_adjust, (free_key_fn *)oqsx_key_free
//     };

// static OSSL_FUNC_decoder_newctx_fn PrivateKeyInfo_der2dilithium2_newctx;

// static void *PrivateKeyInfo_der2dilithium2_newctx(void *provctx) {
//     if (getenv("OQSDEC"))
//         printf("OQS DEC provider: _newctx called.\n");
//     return der2key_newctx(provctx, &PrivateKeyInfo_dilithium2_desc, "dilithium2");
// }

// static int PrivateKeyInfo_der2dilithium2_does_selection(void *provctx, int selection) {
//     if (getenv("OQSDEC")) printf("OQS DEC provider: _does_selection called.\n");
//     return der2key_check_selection(selection, &PrivateKeyInfo_dilithium2_desc);
// }

// const OSSL_DISPATCH oqs_PrivateKeyInfo_der_to_dilithium2_decoder_functions[] = {
//     {1, (void (*)(void))PrivateKeyInfo_der2dilithium2_newctx}, 
//     {2, (void (*)(void))der2key_freectx}, 
//     {10, (void (*)(void))PrivateKeyInfo_der2dilithium2_does_selection},
//     {11, (void (*)(void))oqs_der2key_decode}, {20, (void (*)(void))der2key_export_object}, {0, ((void *)0)}
// };


