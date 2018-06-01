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
	engine_hsm.c \
	engine_hsm_pkey.c \
	engine_hsm_obj.c

##	openssl_hsm_engine.c

##	openssl_hsm_sign.c \

# noinst_LTLIBRARIES = libpki-token.la
noinst_LTLIBRARIES = libpki-token-engine.la

libpki_token_engine_la_SOURCES = $(SRCS)

libpki_token_engine_la_CFLAGS = $(BUILD_LIBPKI_CFLAGS)

# libpki_token_engine_la_LIBADD = $(BUILD_LIBPKI_LDFLAGS)

# libpki_token_a_LDFLAGS = -version-info 1:0:0

# $(OPENCA_INCLUDE_LIBS) \
#			$(openssl_cflags) $(openssl_libs)

#pki_token_a_LIBADD   = \
#			$(openssl_cflags) $(openssl_libs) \
#			$(libxml2_cflags) $(libxml2_libs) \
#			$(OPENCA_INCLUDE_LIBS)

