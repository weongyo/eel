#!/bin/sh

TOPDIR=/home/weongyo/Sources/eel
NSPR_ROOT=$TOPDIR/vendor/nsprpub/dist

cd vendor/c-ares-1.10.0 && ./configure --prefix=/opt/eel-1.0.0 && \
    make && make install

cd vendor/curl-7.33.0 && ./configure --prefix=/opt/eel-1.0.0 \
    --enable-debug --disable-optimize --enable-ares=/opt/eel-1.0.0 && \
    make && make install

cd vendor/gumbo-parser && ./configure --prefix=/opt/eel-1.0.0 \
    --enable-debug --disable-optimize && make && make install

./configure --prefix=/opt/eel-1.0.0 \
    --enable-64bit --enable-debug --disable-optimize \
    --enable-threadsafe \
    --with-nspr-cflags="-I$NSPR_ROOT/include/nspr" \
    --with-nspr-libs="$NSPR_ROOT/lib/libnspr4.a $NSPR_ROOT/lib/libplds4.a $NSPR_ROOT/lib/libplc4.a"
