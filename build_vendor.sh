#!/bin/sh

export PREFIX=/opt/eel/1.0.0

cd vendor/c-ares-1.10.0 && ./configure --prefix=$PREFIX && \
    make && make install
cd ../../

cd vendor/curl-7.33.0 && ./configure --prefix=$PREFIX \
    --enable-debug --disable-optimize --enable-ares=$PREFIX && \
    make && make install
cd ../../

cd vendor/gumbo-parser && ./configure --prefix=$PREFIX \
    --enable-debug --disable-optimize && make && make install
cd ../../

cd vendor/uriparser-0.7.9 && ./configure --prefix=$PREFIX \
    --disable-test --disable-doc && make && make install
cd ../../

cd vendor/nspr && ./configure --prefix=$PREFIX \
    --enable-debug --disable-optimize --enable-64bit && make && make install
cd ../../

cd vendor/mozjs17.0.0/js/src && ./configure --prefix=$PREFIX \
    --enable-64bit --enable-debug --disable-optimize \
    --enable-threadsafe \
    --with-nspr-cflags="-I$PREFIX/include/nspr" \
    --with-nspr-libs="$PREFIX/lib/libnspr4.a $PREFIX/lib/libplds4.a $PREFIX/lib/libplc4.a" && \
    make && make install
cd ../../../../
