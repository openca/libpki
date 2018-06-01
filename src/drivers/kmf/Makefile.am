## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2007 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ../..
include $(TOP)/global-vars

BASE_DEFS = 

DEFS = $(OPENCA_DEFS)

AM_CPPFLAGS = -I$(TOP) \
	$(openssl_cflags) \
	$(libxml2_cflags) \
	$(COND_INCLUDES)

SRCS = \
	kmf_hsm.c \
	kmf_hsm_pkey.c \
	kmf_hsm_sign.c \
	kmf_hsm_engine.c

# noinst_LTLIBRARIES = libpki-token.la
noinst_LTLIBRARIES = libpki-token-kmf.la

libpki_token_kmf_la_SOURCES = $(SRCS)

libpki_token_kmf_la_CFLAGS = $(BUILD_LIBPKI_CFLAGS)

# libpki_token_kmf_la_LIBADD = $(BUILD_LIBPKI_LDFLAGS)

# libpki_token_a_LDFLAGS = -version-info 1:0:0

# $(OPENCA_INCLUDE_LIBS) \
#			$(openssl_cflags) $(openssl_libs)

#pki_token_a_LIBADD   = \
#			$(openssl_cflags) $(openssl_libs) \
#			$(libxml2_cflags) $(libxml2_libs) \
#			$(OPENCA_INCLUDE_LIBS)

