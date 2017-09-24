#!/bin/bash

# Simple script to create the Makefile and build

# export PATH="$PATH:/usr/local/cuda/bin/"

make distclean || echo clean

rm -f Makefile.in
rm -f config.status
./autogen.sh || echo done

CFLAGS="-g -O3 -fgcse-sm -march=native" ./configure
#./configure.sh

make -j 4
