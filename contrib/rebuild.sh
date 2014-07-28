#!/bin/bash

aclocal -I build && automake && autoconf -I build/

./configure \
	--prefix=/usr/local/libPKI/ \
	--with-openssl-prefix=/usr/local/openssl-0.9.8a

make && sudo make install
