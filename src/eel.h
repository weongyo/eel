#ifndef _EEL_H
#define	_EEL_H

#define	AZ(foo)		do { assert((foo) == 0); } while (0)
#define	AN(foo)		do { assert((foo) != 0); } while (0)

#ifdef __cplusplus
extern "C" {
#endif

/* eel_js.cc */
int	EJS_init(void);

#ifdef __cplusplus
}
#endif

#endif

