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
#include "gumbo.h"

#define DEFAULT_MAX_STACK_SIZE 500000
static size_t gMaxStackSize = DEFAULT_MAX_STACK_SIZE;
static unsigned gStackBaseThreadIndex;
static size_t gStackChunkSize = 8192;

struct ejsconf {
	unsigned		magic;
#define	EJSCONF_MAGIC		0x51a3b032
	unsigned		flags;
#define	EJSCONF_F_RTINHERITED	(1 << 0)
#define	EJSCONF_F_CONFLOADED	(1 << 1)
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
	struct ejsconf *ep;
	JSString *val;

	ep = (struct ejsconf *)JS_GetContextPrivate(cx);
	AN(ep);
	val = JS_NewStringCopyZ(cx, ep->url);
	AN(val);
	JS_SET_RVAL(cx, vp, STRING_TO_JSVAL(val));
	return JS_TRUE;
}

static JSBool
envjs_collectURL(JSContext *cx, unsigned int argc, jsval *vp)
{
	struct ejsconf *ep;
	JSString *str;
	jsval *argv = JS_ARGV(cx, vp);

	if (argc < 1 ||
	    !JSVAL_IS_STRING(argv[0])) {
		JS_ReportError(cx, "Invalid arguments to ENVJS.collectURL.");
		return (JS_FALSE);
	}
	CAST_OBJ_NOTNULL(ep, (struct ejsconf *)JS_GetContextPrivate(cx),
	    EJSCONF_MAGIC);

	str = JSVAL_TO_STRING(argv[0]);
	AN(str);
	JSAutoByteString url(cx, str);
	LNK_newhref((struct req *)ep->arg, NULL, -1, url.ptr());

	JS_SET_RVAL(cx, vp, JSVAL_VOID);
	return JS_TRUE;
}

static void *
ejs_newraw(struct ejsconf *epconf, void *arg)
{
	struct ejsconf *ep;
	uint32_t oldopts;

	ep = (struct ejsconf *)calloc(sizeof(*ep), 1);
	AN(ep);
	ep->magic = EJSCONF_MAGIC;
	ep->arg = arg;
	if (epconf == NULL)
		ep->rt = JS_NewRuntime(32L * 1024L * 1024L);
	else {
		ep->rt = epconf->rt;
		ep->flags = EJSCONF_F_RTINHERITED;
	}
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

extern const char *f_arg;

void *
EJS_newwrk(void *arg)
{
	struct ejsconf *ep;
	JSScript *script;
	uint32_t oldopts;

	ep = (struct ejsconf *)ejs_newraw(NULL, arg);
	AN(ep);
	JSAutoRequest ar(ep->cx);
	JSAutoCompartment ac(ep->cx, ep->global);
	do {
		FILE *fp;

		fp = fopen(f_arg, "r");
		if (fp == NULL)
			break;
		AN(fp);
		oldopts = JS_GetOptions(ep->cx);
		JS_SetOptions(ep->cx, oldopts | JSOPTION_COMPILE_N_GO |
		    JSOPTION_NO_SCRIPT_RVAL);
		script = JS_CompileUTF8FileHandle(ep->cx, ep->global, f_arg,
		    fp);
		AN(script);
		JS_SetOptions(ep->cx, oldopts);
		if (!JS_ExecuteScript(ep->cx, ep->global, script, NULL))
			printf("[ERROR] JS_ExecuteScript() failed.\n");
		fclose(fp);
		ep->flags |= EJSCONF_F_CONFLOADED;
	} while (0);
	return ((void *)ep);
}

void *
EJS_newreq(void *confpriv, const char *url, void *arg)
{
	struct ejsconf *ep;
	struct ejsconf *epconf = (struct ejsconf *)confpriv;
	JSBool ret;
	JSFunction *func;
	JSObject *envjs;
	JSScript *script;
	jsval val;
	uint32_t oldopts;
	const char *filename = "/opt/eel/" PACKAGE_VERSION "/share/dom.js";

	ep = (struct ejsconf *)ejs_newraw(epconf, arg);
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
	struct ejsconf *ep = (struct ejsconf *)arg;

	assert(ep->magic == EJSCONF_MAGIC);

	JS_DestroyContext(ep->cx);
	if ((ep->flags & EJSCONF_F_RTINHERITED) == 0)
		JS_DestroyRuntime(ep->rt);
	free(ep);
}

/*----------------------------------------------------------------------*/

void
EJS_eval(void *arg, const char *filename, unsigned int line, const char *src,
    ssize_t len)
{
	struct ejsconf *ep = (struct ejsconf *)arg;
	JSBool ret;
	jsval rval;

	JSAutoRequest ar(ep->cx);
	JSAutoCompartment ac(ep->cx, ep->global);
	ret = JS_EvaluateScript(ep->cx, ep->global, src, len, filename, line,
	    &rval);
	if (ret != JS_TRUE)
		fprintf(stderr, "JS_EvaluateScript() error.\n");
}

static JSObject *
EJS_getWindowDocument(void *arg)
{
	struct ejsconf *ep = (struct ejsconf *)arg;
	JSBool ret;
	jsval val;

	JSAutoRequest ar(ep->cx);
	JSAutoCompartment ac(ep->cx, ep->global);

	ret = JS_GetProperty(ep->cx, ep->global, "window", &val);
	assert(ret == JS_TRUE);
	assert(!JSVAL_IS_PRIMITIVE(val));
	ret = JS_GetProperty(ep->cx, JSVAL_TO_OBJECT(val), "document", &val);
	assert(ret == JS_TRUE);
	assert(!JSVAL_IS_PRIMITIVE(val));
	return (JSVAL_TO_OBJECT(val));
}

void *
EJS_documentCreateElement(void *arg, void *nodearg)
{
	struct ejsconf *ep = (struct ejsconf *)arg;
	GumboNode *node = (GumboNode *)nodearg;
	JSBool ret;
	JSObject *document;
	JSString *str;
	jsval args[1], val;
	const char *name;

	JSAutoRequest ar(ep->cx);
	JSAutoCompartment ac(ep->cx, ep->global);

	document = EJS_getWindowDocument(ep);
	AN(document);
	name = gumbo_normalized_tagname(node->v.element.tag);
	AN(name);
	str = JS_NewStringCopyZ(ep->cx, name);
	AN(str);
	args[0] = STRING_TO_JSVAL(str);
	ret = JS_CallFunctionName(ep->cx, document, "createElement", 1, args,
	    &val);
	if (ret == JS_FALSE)
		return (NULL);
	assert(!JSVAL_IS_PRIMITIVE(val));
	return (JSVAL_TO_OBJECT(val));
}

void
EJS_documentAppendChild(void *arg, void *nodearg0, void *nodearg1)
{
	struct ejsconf *ep = (struct ejsconf *)arg;
	JSBool ret;
	JSObject *parent = (JSObject *)nodearg0;
	JSObject *child = (JSObject *)nodearg1;
	jsval args[1], val;

	if (parent == NULL) {
		parent = EJS_getWindowDocument(ep);
		AN(parent);
	}

	JSAutoRequest ar(ep->cx);
	JSAutoCompartment ac(ep->cx, ep->global);

	args[0] = OBJECT_TO_JSVAL(child);
	ret = JS_CallFunctionName(ep->cx, parent, "appendChild", 1, args, &val);
	assert(ret == JS_TRUE);
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
	reqarg = JS_GetPrivate(obj);
	AN(reqarg);
	if (!strcmp(name.ptr(), "url")) {
		JSString *valstr;

		valstr = JS_NewStringCopyZ(cx, RTJ_geturl(reqarg));
		AN(valstr);
		ret = JS_DefineProperty(cx, obj, name.ptr(),
		    STRING_TO_JSVAL(valstr), NULL, NULL, 0);
		if (ret == JS_FALSE)
			printf("JS_DefineProperty Failed.\n");
		objp.set(obj);
	} else if (!strcmp(name.ptr(), "enable_javascript")) {
		JSBool valbool;

		valbool = JS_FALSE;
		ret = JS_DefineProperty(cx, obj, name.ptr(),
		    BOOLEAN_TO_JSVAL(valbool), NULL, NULL, 0);
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
	} else
		printf("[ERROR] Unknown property %s is requested.\n",
		    name.ptr());
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

int
JCL_fetch(void *arg, void *reqarg)
{
	struct ejsconf *ep = (struct ejsconf *)arg;
	JSBool ret, rval;
	JSObject *obj;
	JSString *str;
	jsval args[1], val;

	if ((ep->flags & EJSCONF_F_CONFLOADED) == 0)
		return (1);

	JSAutoRequest ar(ep->cx);
	JSAutoCompartment ac(ep->cx, ep->global);
	obj = JS_NewObject(ep->cx, &jcl_class, NULL, NULL);
	AN(obj);
	JS_SetPrivate(obj, reqarg);
	args[0] = OBJECT_TO_JSVAL(obj);
	ret = JS_CallFunctionName(ep->cx, ep->global, "fetch", 1, args, &val);
	if (ret == JS_FALSE) {
		printf("[ERROR] JS_CallFunctionName failed\n");
		JS_SetPrivate(obj, NULL);
		return (-1);
	}
	if (!JSVAL_IS_BOOLEAN(val)) {
		printf("[ERROR] Wrong return type from `fetch' function.\n");
		JS_SetPrivate(obj, NULL);
		return (-1);
	}
	rval = JSVAL_TO_BOOLEAN(val);
	{
		ret = JS_GetProperty(ep->cx, obj, "url", &val);
		if (ret == JS_FALSE) {
			printf("JS_GetProperty failed\n");
			JS_SetPrivate(obj, NULL);
			return (-1);
		}
		str = JS_ValueToString(ep->cx, val);
		if (str == NULL) {
			printf("JS_ValueToString failed\n");
			JS_SetPrivate(obj, NULL);
			return (-1);
		}
		JSAutoByteString url(ep->cx, str);
		RTJ_replaceurl(reqarg, url.ptr());
	}
	{
		JSBool rval2;

		ret = JS_GetProperty(ep->cx, obj, "enable_javascript", &val);
		if (ret == JS_FALSE) {
			printf("JS_GetProperty failed\n");
			JS_SetPrivate(obj, NULL);
			return (-1);
		}
		ret = JS_ValueToBoolean(ep->cx, val, &rval2);
		if (ret == JS_FALSE) {
			printf("JS_ValueToBoolean failed\n");
			JS_SetPrivate(obj, NULL);
			return (-1);
		}
		RTJ_enable_javascript(reqarg, (int)rval2);
	}
	JS_SetPrivate(obj, NULL);
	if (rval == JS_FALSE)
		return (0);
	return (1);
}

/*----------------------------------------------------------------------*/

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
