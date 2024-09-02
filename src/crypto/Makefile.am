## OpenCA Makefile - by Massimiliano Pala
## (c) 1999-2007 by Massimiliano Pala and OpenCA Project
## All Rights Reserved

TOP     = ..
include $(TOP)/global-vars

BASE_DEFS = 

SUBDIRS = artifacts composite hsm .

AM_CPPFLAGS = -I$(TOP)

SRCS = \
	c_algorithm.c \
	c_digest.c \
	c_hmac.c \
	c_rand.c \
	c_kdf.c \
	c_id.c \
	c_keypair.c \
	c_keyparams.c \
	c_oid.c \
	c_oid_defs.c


noinst_LTLIBRARIES = libpki-crypto.la

libpki_crypto_la_SOURCES = $(SRCS)
libpki_crypto_la_CFLAGS  = $(BUILD_LIBPKI_CFLAGS)
libpki_crypto_la_LIBADD  = $(OBJECTS)

