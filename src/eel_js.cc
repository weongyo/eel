#include "config.h"

#include "jslock.h"

#include "eel.h"

static unsigned gStackBaseThreadIndex;

static JSRuntime *rt;

int
EJS_init(void)
{
	PRStatus ret;
	int stackDummy;

	ret = PR_NewThreadPrivateIndex(&gStackBaseThreadIndex, NULL);
	if (ret == PR_FAILURE)
		return (-1);
	ret = PR_SetThreadPrivate(gStackBaseThreadIndex, &stackDummy);
	if (ret == PR_FAILURE)
		return (-1);
	rt = JS_NewRuntime(32L * 1024L * 1024L);
	if (!rt)
		return (-1);
        return (0);
}
