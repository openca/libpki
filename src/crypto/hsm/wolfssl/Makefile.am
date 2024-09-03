## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2009 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ../..
include $(TOP)/global-vars

BASE_DEFS = 

DEFS = $(OPENCA_DEFS)

AM_CPPFLAGS = -I$(TOP) \
	$(wolfssl_cflags) \
	$(libxml2_cflags) \
	$(COND_INCLUDES)

SRCS = \
	wolfssl_hsm.c \
	wolfssl_hsm_pkey.c \
	wolfssl_hsm_obj.c \
	wolfssl_hsm_cb.c

noinst_LTLIBRARIES = libpki-token-openssl.la

libpki_token_wolfssl_la_SOURCES = $(SRCS)
libpki_token_wolfssl_la_CFLAGS = $(BUILD_LIBPKI_CFLAGS)

