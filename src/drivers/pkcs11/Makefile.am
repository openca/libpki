## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2007 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ../..
-include $(TOP)/global-vars

BASE_DEFS = 

DEFS = $(OPENCA_DEFS)

AM_CPPFLAGS = -I$(TOP) \
	$(pkcs11_cflags) \
	$(libxml2_cflags) \
	$(COND_INCLUDES)

SRCS = \
	pkcs11_hsm.c \
	pkcs11_hsm_pkey.c \
	pkcs11_hsm_obj.c \
	utils/pkcs11_init.c

noinst_LTLIBRARIES = libpki-token-pkcs11.la

libpki_token_pkcs11_la_SOURCES = $(SRCS)

libpki_token_pkcs11_la_CFLAGS = $(BUILD_LIBPKI_CFLAGS)

