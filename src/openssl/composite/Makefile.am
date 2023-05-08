## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2022 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ../..
include $(TOP)/global-vars

BASE_DEFS = 

DEFS = $(OPENCA_DEFS)

AM_CPPFLAGS = -I$(TOP) \
	$(openssl_cflags) \
	$(libxml2_cflags) \
	$(COND_INCLUDES)

OPENSSL_INTERNAL_SRCS = \
	composite_ossl_lcl.h \
	composite_ameth_lcl.h

nobase_include_HEADERS = 

COMPOSITE_SRCS = \
	composite_key.c \
	composite_ctx.c \
	composite_ameth.c \
	composite_pmeth.c \
	composite_err.c \
	composite_utils.c \
	composite_init.c \
	$(OPENSSL_INTERNAL_SRCS)

noinst_LTLIBRARIES = libpki-composite.la

libpki_composite_la_SOURCES = $(COMPOSITE_SRCS)
libpki_composite_la_CFLAGS = $(BUILD_LIBPKI_CFLAGS)

