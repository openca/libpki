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

OPENSSL_INTERNAL_SRCS = 

nobase_include_HEADERS = 

COMPOSITE_SRCS = \
	composite_ameth.c \
	composite_pmeth.c \
	composite_err.c \
	$(OPENSSL_INTERNAL_SRCS)

noinst_LTLIBRARIES = libpki-composite.la

libpki_composite_la_SOURCES = $(COMPOSITE_SRCS)
libpki_composite_la_CFLAGS = $(BUILD_LIBPKI_CFLAGS)
# libpki_composite_la_LDFLAGS = $(BUILD_LIBPKI_LDFLAGS)
# libpki_composite_la_LIBADD = $(BUILD_LIBPKI_LDADD)

