#ifndef _EEL_H
#define	_EEL_H

#define	AZ(foo)		do { assert((foo) == 0); } while (0)
#define	AN(foo)		do { assert((foo) != 0); } while (0)
#define CHECK_OBJ(ptr, type_magic)					\
	do {								\
		assert((ptr)->magic == type_magic);			\
	} while (0)
#define CHECK_OBJ_NOTNULL(ptr, type_magic)				\
	do {								\
		assert((ptr) != NULL);					\
		assert((ptr)->magic == type_magic);			\
	} while (0)
#define CAST_OBJ_NOTNULL(to, from, type_magic)				\
	do {								\
		(to) = (from);						\
		assert((to) != NULL);					\
		CHECK_OBJ((to), (type_magic));				\
	} while (0)
#define	TRUST_ME(ptr)	((void*)(uintptr_t)(ptr))

#ifdef __cplusplus
extern "C" {
#endif

/* eel.c */
struct req;
void	LNK_newhref(struct req *req, const char *url);
const char *
	REQ_geturl(void *reqarg);

/* eel_js.cc */
int	EJS_init(void);
void *	EJS_newreq(const char *url, void *arg);
void *	EJS_newwrk(void *arg);
int	EJS_fetch(void *arg, void *reqarg);
void	EJS_free(void *arg);
void	EJS_eval(void *arg, const char *filename, unsigned int line,
	    const char *src, ssize_t len);

#ifdef __cplusplus
}
#endif

#endif

