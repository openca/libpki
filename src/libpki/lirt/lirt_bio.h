/* Lightweight Internet Revocation Token implementation
 * (c) 2004-2012 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 *
 * This software is released under the GPL2 License included
 * in the archive. You can not remove this copyright notice.
 */
                                                                                
#ifndef _LIBPKI_LIRT_BIO_H
#define _LIBPKI_LIRT_BIO_H

#define PEM_STRING_PKI_LIRT "LIRT"

PKI_LIRT *d2i_PKI_LIRT_bio ( BIO *bp, PKI_LIRT *p );
int i2d_PKI_LIRT_bio(BIO *bp, PKI_LIRT *o );

/* PEM <-> INTERNAL Macros */
PKI_LIRT *PEM_read_bio_PKI_LIRT( BIO *bp );
int PEM_write_bio_PKI_LIRT( BIO *bp, PKI_LIRT *o );

#endif
