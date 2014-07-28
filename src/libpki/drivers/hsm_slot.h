/* HSM Object Management Functions */

#ifndef _LIBPKI_HSM_MAIN_SLOT_H
#define _LIBPKI_HSM_MAIN_SLOT_H

/* ---------------------- Slot Management Functions ----------------------- */

unsigned long HSM_SLOT_num ( HSM *hsm );
int HSM_SLOT_select ( unsigned long num, PKI_CRED *cred, HSM *hsm );
int HSM_SLOT_clear ( unsigned long num, PKI_CRED *cred, HSM *hsm );

HSM_SLOT_INFO * HSM_SLOT_INFO_get ( unsigned long num, HSM *hsm );
int HSM_SLOT_INFO_print( unsigned long num, PKI_CRED *cred, HSM *hsm );
void HSM_SLOT_INFO_free ( HSM_SLOT_INFO *sl_info, HSM *hsm );

#endif
