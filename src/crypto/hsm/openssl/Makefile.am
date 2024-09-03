## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2009 by Massimiliano Pala and OpenCA Project
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
	openssl_hsm.c \
	openssl_hsm_pkey.c \
	openssl_hsm_obj.c \
	openssl_hsm_cb.c

noinst_LTLIBRARIES = libpki-hsm-openssl.la

libpki_hsm_openssl_la_SOURCES = $(SRCS)
libpki_hsm_openssl_la_CFLAGS = $(BUILD_LIBPKI_CFLAGS)

