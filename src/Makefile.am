
bin_PROGRAMS = eel

eel_SOURCES = \
	callout.c \
	eel.c \
	eel_js.cc \
	vct.c \
	vsb.c

eel_CFLAGS = -I$(prefix)/include -I$(prefix)/include/nspr \
	-I$(prefix)/include/js-17.0 \
	-Wall -Wmissing-prototypes -Wpointer-arith \
	-Wreturn-type -Wcast-qual -Wwrite-strings -Wswitch -Wshadow \
	-Wcast-align -Wunused-parameter -Wchar-subscripts -Winline \
	-Wnested-externs -Wformat -Werror

eel_CXXFLAGS = -I$(prefix)/include -I$(prefix)/include/nspr \
	-I$(prefix)/include/js-17.0 \
	-Werror \
	-DDEBUG -D__STDC_LIMIT_MACROS

eel_LDFLAGS = -L$(prefix)/lib

eel_LDADD = -lcurl -lgumbo -lmozjs-17.0 -lnspr4 -luriparser -lcrypto -lpthread