#ifndef _EEL_H
#define	_EEL_H

#define	AZ(foo)		do { assert((foo) == 0); } while (0)
#define	AN(foo)		do { assert((foo) != 0); } while (0)

#ifdef __cplusplus
extern "C" {
#endif

/* eel_js.cc */
int	EJS_init(void);
void *	EJS_new(const char *url);
void	EJS_free(void *arg);
void	EJS_eval(void *arg, const char *filename, unsigned int line,
	    const char *src, ssize_t len);

#ifdef __cplusplus
}
#endif

#endif

