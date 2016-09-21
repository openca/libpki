## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2007 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ..
-include $(TOP)/global-vars

BASE_DEFS = 

if ENABLE_KMF
HSM_KMF = kmf
HSM_KMF_OBJ = $(top_builddir)/src/drivers/kmf/libpki-token-kmf.a
else
HSM_KMF =
endif

if ENABLE_OPENSSL
HSM_SOFTWARE = openssl
HSM_SOFTWARE_OBJ = $(top_builddir)/src/drivers/openssl/libpki-token-openssl.la
else
HSM_SOFTWARE =
endif

if ENABLE_OPENSSL_ENGINE
HSM_ENGINE = engine
HSM_ENGINE_OBJ = $(top_builddir)/src/drivers/engine/libpki-token-engine.la
else
HSM_ENGINE =
endif

HSM_PKCS11 = pkcs11
HSM_PKCS11_OBJ = $(top_builddir)/src/drivers/pkcs11/libpki-token-pkcs11.la

HSMS = $(HSM_SOFTWARE) $(HSM_KMF) $(HSM_ENGINE) $(HSM_PKCS11)
OBJECTS = $(HSM_KMF_OBJ) $(HSM_SOFTWARE_OBJ) $(HSM_ENGINE_OBJ) $(HSM_PKCS11_OBJ)

SUBDIRS = $(HSMS) .

AM_CPPFLAGS = -I$(TOP)

SRCS = \
	hsm_main.c \
	hsm_slot.c \
	hsm_keypair.c


noinst_LTLIBRARIES = libpki-token.la
# noinst_LIBRARIES = libpki-token.a

libpki_token_la_SOURCES = $(SRCS)
libpki_token_la_CFLAGS  = $(BUILD_LIBPKI_CFLAGS)
# libpki_token_la_LIBADD  = $(BUILD_LIBPKI_LDFLAGS) $(OBJECTS)
libpki_token_la_LIBADD  = $(OBJECTS)

