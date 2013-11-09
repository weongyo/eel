
bin_PROGRAMS = eel

eel_SOURCES = \
	eel.c

eel_CFLAGS = -I$(prefix)/include \
	-Wall -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith \
	-Wreturn-type -Wcast-qual -Wwrite-strings -Wswitch -Wshadow \
	-Wcast-align -Wunused-parameter -Wchar-subscripts -Winline \
	-Wnested-externs -Wredundant-decls -Wformat -Werror

eel_LDFLAGS = -L$(prefix)/lib

eel_LDADD = -lcurl