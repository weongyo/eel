#include "config.h"

#include <assert.h>

#include "jsapi.h"
#include "jslock.h"
#include "jsprf.h"

#include "eel.h"

static JSClass global_class = {
	"global",
	JSCLASS_NEW_RESOLVE | JSCLASS_GLOBAL_FLAGS,
	JS_PropertyStub,
	JS_PropertyStub,
	JS_PropertyStub,
	JS_StrictPropertyStub,
	JS_EnumerateStub,
	JS_ResolveStub,
	JS_ConvertStub,
	NULL,
	JSCLASS_NO_OPTIONAL_MEMBERS
};

#define DEFAULT_MAX_STACK_SIZE 500000
static size_t gMaxStackSize = DEFAULT_MAX_STACK_SIZE;
static unsigned gStackBaseThreadIndex;
static size_t gStackChunkSize = 8192;

struct ejs_private {
	unsigned		magic;
#define	EJS_PRIVATE_MAGIC	0x51a3b032
	JSRuntime		*rt;
	JSContext		*cx;
	JSObject		*global;
};

static void
my_ErrorReporter(JSContext *cx, const char *message, JSErrorReport *report)
{
	int i, j, k, n;
	char *prefix, *tmp;
	const char *ctmp;

	if (!report) {
		fprintf(stderr, "%s\n", message);
		fflush(stderr);
		return;
	}

	prefix = NULL;
	if (report->filename)
		prefix = JS_smprintf("%s:", report->filename);
	if (report->lineno) {
		tmp = prefix;
		prefix = JS_smprintf("%s%u:%u ", tmp ? tmp : "", report->lineno,
		    report->column);
		JS_free(cx, tmp);
	}
	if (JSREPORT_IS_WARNING(report->flags)) {
		tmp = prefix;
		prefix = JS_smprintf("%s%swarning: ",
		    tmp ? tmp : "",
		    JSREPORT_IS_STRICT(report->flags) ? "strict " : "");
		JS_free(cx, tmp);
	}

	/* embedded newlines -- argh! */
	while ((ctmp = strchr(message, '\n')) != 0) {
		ctmp++;
		if (prefix)
			fputs(prefix, stderr);
		fwrite(message, 1, ctmp - message, stderr);
		message = ctmp;
	}

	/* If there were no filename or lineno, the prefix might be empty */
	if (prefix)
		fputs(prefix, stderr);
	fputs(message, stderr);

	if (!report->linebuf) {
		fputc('\n', stderr);
		goto out;
	}

	/* report->linebuf usually ends with a newline. */
	n = strlen(report->linebuf);
	fprintf(stderr, ":\n%s%s%s%s",
            prefix,
            report->linebuf,
            (n > 0 && report->linebuf[n-1] == '\n') ? "" : "\n",
            prefix);
	n = report->tokenptr - report->linebuf;
	for (i = j = 0; i < n; i++) {
		if (report->linebuf[i] == '\t') {
			for (k = (j + 8) & ~7; j < k; j++) {
				fputc('.', stderr);
			}
			continue;
		}
		fputc('.', stderr);
		j++;
	}
	fputs("^\n", stderr);
out:
	fflush(stderr);
	JS_free(cx, prefix);
}

static JSBool
ShellOperationCallback(JSContext *cx)
{

	printf("%s\n", __func__);

	return (false);
}

static JSContext *
NewContext(JSRuntime *rt)
{
	JSContext *cx;

	cx = JS_NewContext(rt, gStackChunkSize);
	if (!cx)
		return (NULL);

	JS_SetContextPrivate(cx, NULL);
	JS_SetErrorReporter(cx, my_ErrorReporter);
	JS_SetVersion(cx, JSVERSION_LATEST);
	JS_SetOperationCallback(cx, ShellOperationCallback);
	return (cx);
}

void *
EJS_new(void)
{
	struct ejs_private *ep;
	JSBool ret;

	ep = (struct ejs_private *)calloc(sizeof(*ep), 1);
	AN(ep);
	ep->magic = EJS_PRIVATE_MAGIC;
	ep->rt = JS_NewRuntime(32L * 1024L * 1024L);
	AN(ep->rt);
	JS_SetGCParameter(ep->rt, JSGC_MAX_BYTES, 0xffffffff);
	JS_SetNativeStackQuota(ep->rt, gMaxStackSize);
	ep->cx = NewContext(ep->rt);
	AN(ep->cx);
	JS_SetOptions(ep->cx, JS_GetOptions(ep->cx) | JSOPTION_VAROBJFIX);

	JSAutoRequest ar(ep->cx);
	/* Create the global object in a new compartment. */
	ep->global = JS_NewGlobalObject(ep->cx, &global_class, NULL);
	AN(ep->global);
	/* Set the context's global */
	JSAutoCompartment ac(ep->cx, ep->global);
	JS_SetGlobalObject(ep->cx, ep->global);
	/*
	 * Populate the global object with the standard globals, like
	 * Object and Array.
	 */
	ret = JS_InitStandardClasses(ep->cx, ep->global);
	assert(ret == JS_TRUE);

	return ((void *)ep);
}

void
EJS_free(void *arg)
{
	struct ejs_private *ep = (struct ejs_private *)arg;

	JS_DestroyContext(ep->cx);
	JS_DestroyRuntime(ep->rt);
	free(ep);
}

int
EJS_init(void)
{
	JSRuntime *rt;
	PRStatus ret;
	int stackDummy;

	ret = PR_NewThreadPrivateIndex(&gStackBaseThreadIndex, NULL);
	if (ret == PR_FAILURE)
		return (-1);
	ret = PR_SetThreadPrivate(gStackBaseThreadIndex, &stackDummy);
	if (ret == PR_FAILURE)
		return (-1);
	return (0);
}
