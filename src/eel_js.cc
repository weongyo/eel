/*-
 * Copyright (c) 2013 Weongyo Jeong <weongyo@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "config.h"

#include <assert.h>
#include <time.h>

#include "jsapi.h"
#include "jsdbgapi.h"
#include "jslock.h"
#include "jsprf.h"

#include "eel.h"

#define DEFAULT_MAX_STACK_SIZE 500000
static size_t gMaxStackSize = DEFAULT_MAX_STACK_SIZE;
static unsigned gStackBaseThreadIndex;
static size_t gStackChunkSize = 8192;

struct ejs_private {
	unsigned		magic;
#define	EJS_PRIVATE_MAGIC	0x51a3b032
	const char		*url;
	void			*arg;
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
	    prefix, report->linebuf,
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

	JS_SetErrorReporter(cx, my_ErrorReporter);
	JS_SetVersion(cx, JSVERSION_LATEST);
	JS_SetOperationCallback(cx, ShellOperationCallback);
	return (cx);
}

/*----------------------------------------------------------------------*/

static void
dumpobj(JSContext *cx, JSObject *obj)
{
	JSBool ok;
	JSString *str;
	jsval x;

	x = OBJECT_TO_JSVAL(obj);
	if (JSVAL_IS_VOID(x)) {
		printf("(void)");
		return;
	}
	str = JS_ValueToSource(cx, x);
	ok = !!str;
	if (ok) {
		JSAutoByteString bytes(cx, str);
		ok = !!bytes;
		if (ok)
			fprintf(stderr, "%s\n", bytes.ptr());
	}
}

#define	DUMPID(cx, id, flags)	dumpid(cx, id, flags, __func__, __LINE__)

static void
dumpid(JSContext *cx, JSHandleId id, unsigned int flags, const char *func,
    int line)
{

	if (JSID_IS_STRING(id)) {
		JSAutoByteString tname(cx, JSID_TO_STRING(id));
		if (!tname)
			assert(0 == 1);
		printf("%s: id == STRING(%s) flags == %#x\n", __func__,
		    tname.ptr(), flags);
	}
	if (JSID_IS_OBJECT(id))
		printf("%s: id == OBJECT\n", __func__);
	if (JSID_IS_INT(id))
		printf("%s: id == INT\n", __func__);
	if (JSID_IS_ZERO(id))
		printf("%s: id == ZERO\n", __func__);
	if (JSID_IS_VOID(id))
		printf("%s: id == VOID\n", __func__);
	if (JSID_IS_EMPTY(id))
		printf("%s: id == EMPTY\n", __func__);
}

static JSBool
dump(JSContext *cx, unsigned argc, jsval *vp)
{
	jsval *argv = JS_ARGV(cx, vp);

	js_DumpBacktrace(cx);
	js_DumpValue(argv[0]);

	if (!JSVAL_IS_PRIMITIVE(argv[0]))
		dumpobj(cx, JSVAL_TO_OBJECT(argv[0]));
	else if (JSVAL_IS_STRING(argv[0])) {
		JSAutoByteString tname(cx, JSVAL_TO_STRING(argv[0]));
		if (!tname)
			assert(0 == 1);
		printf("%s: STRING(%s)\n", __func__, tname.ptr());
	} else
		printf("DUMP: UNKNOWN TYPE\n");
	return JS_TRUE;
}

/*----------------------------------------------------------------------*/

static JSBool
global_enumerate(JSContext *cx, JSHandleObject obj)
{
	JSBool ret;

	ret = JS_EnumerateStandardClasses(cx, obj);
	if (ret == JS_FALSE)
		printf("%s:%d ENUM fail\n", __func__, __LINE__);
	return (ret);
}

static JSBool
global_resolve(JSContext *cx, JSHandleObject obj, JSHandleId id,
    unsigned int flags, JSMutableHandleObject objp)
{
	JSBool resolved;

	if (!JS_ResolveStandardClass(cx, obj, id, &resolved))
		return (false);
	if (resolved) {
		objp.set(obj);
		return (true);
	}
	return (true);
}

static JSClass global_class = {
	"global",
	JSCLASS_NEW_RESOLVE | JSCLASS_GLOBAL_FLAGS,
	JS_PropertyStub,
	JS_PropertyStub,
	JS_PropertyStub,
	JS_StrictPropertyStub,
	global_enumerate,
	(JSResolveOp)global_resolve,
	JS_ConvertStub,
	NULL,
	JSCLASS_NO_OPTIONAL_MEMBERS
};

/*----------------------------------------------------------------------*/

static double
TIM_real(void)
{
	struct timespec ts;

	assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
	return (ts.tv_sec + 1e-9 * ts.tv_nsec);
}

static JSBool
envjs_getURL(JSContext *cx, unsigned int argc, jsval *vp)
{
	struct ejs_private *ep;
	JSString *val;

	ep = (struct ejs_private *)JS_GetContextPrivate(cx);
	AN(ep);
	val = JS_NewStringCopyZ(cx, ep->url);
	AN(val);
	JS_SET_RVAL(cx, vp, STRING_TO_JSVAL(val));
	return JS_TRUE;
}

static JSBool
envjs_collectURL(JSContext *cx, unsigned int argc, jsval *vp)
{
	struct ejs_private *ep;
	JSString *str;
	jsval *argv = JS_ARGV(cx, vp);

	if (argc < 1 ||
	    !JSVAL_IS_STRING(argv[0])) {
		JS_ReportError(cx, "Invalid arguments to ENVJS.collectURL.");
		return (JS_FALSE);
	}
	CAST_OBJ_NOTNULL(ep, (struct ejs_private *)JS_GetContextPrivate(cx),
	    EJS_PRIVATE_MAGIC);

	str = JSVAL_TO_STRING(argv[0]);
	AN(str);
	JSAutoByteString url(cx, str);
	LNK_newhref((struct req *)ep->arg, url.ptr());

	JS_SET_RVAL(cx, vp, JSVAL_VOID);
	return JS_TRUE;
}

static void *
ejs_newraw(void *arg)
{
	struct ejs_private *ep;
	uint32_t oldopts;

	ep = (struct ejs_private *)calloc(sizeof(*ep), 1);
	AN(ep);
	ep->magic = EJS_PRIVATE_MAGIC;
	ep->arg = arg;
	ep->rt = JS_NewRuntime(32L * 1024L * 1024L);
	AN(ep->rt);
	JS_SetGCParameter(ep->rt, JSGC_MAX_BYTES, 0xffffffff);
	JS_SetNativeStackQuota(ep->rt, gMaxStackSize);
	ep->cx = NewContext(ep->rt);
	AN(ep->cx);
	JS_SetContextPrivate(ep->cx, ep);
	JS_SetOptions(ep->cx, JS_GetOptions(ep->cx) | JSOPTION_VAROBJFIX);

	JSAutoRequest ar(ep->cx);
	/* Create the global object in a new compartment. */
	ep->global = JS_NewGlobalObject(ep->cx, &global_class, NULL);
	AN(ep->global);
	/* Set the context's global */
	JSAutoCompartment ac(ep->cx, ep->global);
	JS_SetGlobalObject(ep->cx, ep->global);
	return ((void *)ep);
}

void *
EJS_newwrk(void *arg)
{
	struct ejs_private *ep;
	JSScript *script;
	uint32_t oldopts;
	const char *filename = "/opt/eel/" PACKAGE_VERSION "/etc/conf.js";

	ep = (struct ejs_private *)ejs_newraw(arg);
	AN(ep);
	JSAutoRequest ar(ep->cx);
	JSAutoCompartment ac(ep->cx, ep->global);
	do {
		FILE *fp;

		fp = fopen(filename, "r");
		if (fp == NULL)
			break;
		AN(fp);
		oldopts = JS_GetOptions(ep->cx);
		JS_SetOptions(ep->cx, oldopts | JSOPTION_COMPILE_N_GO |
		    JSOPTION_NO_SCRIPT_RVAL);
		script = JS_CompileUTF8FileHandle(ep->cx, ep->global, filename,
		    fp);
		AN(script);
		JS_SetOptions(ep->cx, oldopts);
		if (!JS_ExecuteScript(ep->cx, ep->global, script, NULL))
			printf("[ERROR] JS_ExecuteScript() failed.\n");
		fclose(fp);
	} while (0);
	return ((void *)ep);
}

void *
EJS_newreq(const char *url, void *arg)
{
	struct ejs_private *ep;
	JSBool ret;
	JSFunction *func;
	JSObject *envjs;
	JSScript *script;
	jsval val;
	uint32_t oldopts;
	const char *filename = "/opt/eel/" PACKAGE_VERSION "/share/dom.js";

	ep = (struct ejs_private *)ejs_newraw(arg);
	AN(ep);
	ep->url = url;

	JSAutoRequest ar(ep->cx);
	JSAutoCompartment ac(ep->cx, ep->global);
	if (!JS_DefineFunction(ep->cx, ep->global, "DUMP", &dump, 1, 0))
		printf("[ERROR] JS_DefineFunction() failed.\n");
	envjs = JS_NewObject(ep->cx, NULL, NULL, NULL);
	AN(envjs);
	func = JS_DefineFunction(ep->cx, envjs, "collectURL", &envjs_collectURL,
	    0, 0);
	assert(func != NULL);
	func = JS_DefineFunction(ep->cx, envjs, "getURL", &envjs_getURL, 0, 0);
	assert(func != NULL);
	val = OBJECT_TO_JSVAL(envjs);
	ret = JS_SetProperty(ep->cx, ep->global, "ENVJS", &val);
	assert(ret == JS_TRUE);
	{
		static int first = 1;
		FILE *fp;
		double now = TIM_real();

		fp = fopen(filename, "r");
		AN(fp);
		oldopts = JS_GetOptions(ep->cx);
		JS_SetOptions(ep->cx, oldopts | JSOPTION_COMPILE_N_GO |
		    JSOPTION_NO_SCRIPT_RVAL);
		script = JS_CompileUTF8FileHandle(ep->cx, ep->global, filename,
		    fp);
		JS_SetOptions(ep->cx, oldopts);
		if (!JS_ExecuteScript(ep->cx, ep->global, script, NULL))
			printf("[ERROR] JS_ExecuteScript() failed.\n");
		fclose(fp);
		if (first == 1) {
			printf("[INFO] Built-in JS compile time: %.3f\n",
			    TIM_real() - now);
			first = 0;
		}
	}
	return ((void *)ep);
}

void
EJS_free(void *arg)
{
	struct ejs_private *ep = (struct ejs_private *)arg;

	assert(ep->magic == EJS_PRIVATE_MAGIC);

	JS_DestroyContext(ep->cx);
	JS_DestroyRuntime(ep->rt);
	free(ep);
}

/*----------------------------------------------------------------------*/

static JSBool
JCL_enumerate(JSContext *cx, JSHandleObject obj)
{

	return (JS_TRUE);
}

static JSBool
JCL_resolve(JSContext *cx, JSHandleObject obj, JSHandleId id,
    unsigned int flags, JSMutableHandleObject objp)
{
	JSBool ret;
	void *reqarg;

	if (!JSID_IS_STRING(id))
		return true;
	JSAutoByteString name(cx, JSID_TO_STRING(id));
	if (!name) {
		JS_ReportOutOfMemory(cx);
		return false;
	}
	if (!strcmp(name.ptr(), "url")) {
		JSString *valstr;

		reqarg = JS_GetPrivate(obj);
		AN(reqarg);

		valstr = JS_NewStringCopyZ(cx, RTJ_geturl(reqarg));
		AN(valstr);
		ret = JS_DefineProperty(cx, obj, name.ptr(),
		    STRING_TO_JSVAL(valstr), NULL, NULL, 0);
		if (ret == JS_FALSE)
			printf("JS_DefineProperty Failed.\n");
		objp.set(obj);
	} else if (!strcmp(name.ptr(), "javascript")) {
		JSBool valbool;
		int val;

		val = RTJ_isjavascript(reqarg);
		if (val == 0)
			valbool = JS_FALSE;
		else
			valbool = JS_TRUE;
		ret = JS_DefineProperty(cx, obj, name.ptr(),
		    BOOLEAN_TO_JSVAL(valbool), NULL, NULL, 0);
		if (ret == JS_FALSE)
			printf("JS_DefineProperty Failed.\n");
		objp.set(obj);
	}
	return (true);
}

static JSClass jcl_class = {
	"JCL",
	JSCLASS_NEW_RESOLVE | JSCLASS_HAS_PRIVATE,
	JS_PropertyStub,
	JS_PropertyStub,
	JS_PropertyStub,
	JS_StrictPropertyStub,
	JCL_enumerate,
	(JSResolveOp)JCL_resolve,
	JS_ConvertStub,
	NULL,
	JSCLASS_NO_OPTIONAL_MEMBERS
};

/*----------------------------------------------------------------------*/

void
EJS_eval(void *arg, const char *filename, unsigned int line, const char *src,
    ssize_t len)
{
	struct ejs_private *ep = (struct ejs_private *)arg;
	JSBool ret;
	jsval rval;

	JSAutoRequest ar(ep->cx);
	JSAutoCompartment ac(ep->cx, ep->global);
	ret = JS_EvaluateScript(ep->cx, ep->global, src, len, filename, line,
	    &rval);
	if (ret != JS_TRUE)
		fprintf(stderr, "JS_EvaluateScript() error.\n");
}

int
EJS_fetch(void *arg, void *reqarg)
{
	struct ejs_private *ep = (struct ejs_private *)arg;
	JSBool ret;
	JSObject *obj;
	jsval args[1], val;

	JSAutoRequest ar(ep->cx);
	JSAutoCompartment ac(ep->cx, ep->global);
	obj = JS_NewObject(ep->cx, &jcl_class, NULL, NULL);
	AN(obj);
	JS_SetPrivate(obj, reqarg);
	args[0] = OBJECT_TO_JSVAL(obj);
	ret = JS_CallFunctionName(ep->cx, ep->global, "fetch", 1, args, &val);
	JS_SetPrivate(obj, NULL);
	if (ret == JS_FALSE) {
		printf("JS_CallFunctionName failed\n");
		return (-1);
	}
	if (!JSVAL_IS_BOOLEAN(val)) {
		printf("Wrong return type from `fetch' function.\n");
		return (-1);
	}
	ret = JSVAL_TO_BOOLEAN(val);
	if (ret == JS_FALSE)
		return (0);
	return (1);
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
	JS_SetCStringsAreUTF8();
	return (0);
}
