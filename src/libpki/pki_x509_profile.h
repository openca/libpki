/*
 * LibPKI - X509 Profile Management functionality
 * (c) 2006-2007 by Massimiliano Pala and OpenCA Project
 * OpenCA LICENSED software
 *
*/

#ifndef _LIBPKI_X509_PROFILE_H
#define _LIBPKI_X509_PROFILE_H
# pragma once

#ifndef __XML_TREE_H__
#include <libxml/tree.h>
#endif

// ===========================
// PKI_X509_PROFILE definition
// ===========================

#define PKI_X509_PROFILE  xmlDoc

// ==========
// Prototypes
// ==========

PKI_X509_PROFILE * PKI_X509_PROFILE_get ( char *url );
PKI_X509_PROFILE * PKI_X509_PROFILE_write( PKI_X509_PROFILE *prof, char *url );

#endif


