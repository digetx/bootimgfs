#! /bin/sh

libtoolize

autoreconf -v --force --install

./configure
