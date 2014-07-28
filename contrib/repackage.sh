#!/bin/bash

aclocal -I build && automake && autoconf -I build/

./configure && make distclean

./configure && make dist

