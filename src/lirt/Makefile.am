## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2007 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ..
include $(TOP)/global-vars

BASE_DEFS = 

DEFS = $(OPENCA_DEFS)
LIRT_VERSION = 0.1.0

INCLUDES = -I$(TOP) \
	$(openssl_cflags) \
	$(libxml2_cflags) \
	$(COND_INCLUDES)

LIRT_SRCS = \
	lirt_asn1.c \
	lirt_bio.c \
	lirt_lib.c

noinst_LTLIBRARIES = libpki-lirt.la
libpki_lirt_la_SOURCES = $(LIRT_SRCS)
libpki_lirt_la_CFLAGS = $(BUILD_LIBPKI_CFLAGS)
# libpki_lirt_la_LIBADD = $(OPENSSL_LIBS) 

