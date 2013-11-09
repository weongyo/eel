#!/bin/sh

NSPR_ROOT=/home/weongyo/Sources/eel/vendor/nsprpub/dist

./configure --prefix=/opt/eel-1.0.0 \
    --enable-64bit --enable-debug --disable-optimize \
    --enable-threadsafe \
    --with-nspr-cflags="-I$NSPR_ROOT/include/nspr" \
    --with-nspr-libs="$NSPR_ROOT/lib/libnspr4.a $NSPR_ROOT/lib/libplds4.a $NSPR_ROOT/lib/libplc4.a"
