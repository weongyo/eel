#include "config.h"

#include "jslock.h"

#include "eel.h"

#define DEFAULT_MAX_STACK_SIZE 500000
static size_t gMaxStackSize = DEFAULT_MAX_STACK_SIZE;
static unsigned gStackBaseThreadIndex;

static PRLock *gWatchdogLock = NULL;
static PRCondVar *gWatchdogWakeup = NULL;
static PRThread *gWatchdogThread = NULL;
static bool gWatchdogHasTimeout = false;
static int64_t gWatchdogTimeout = 0;

static PRCondVar *gSleepWakeup = NULL;

static JSRuntime *gRuntime = NULL;

static bool
InitWatchdog(JSRuntime *rt)
{
	JS_ASSERT(!gWatchdogThread);
	gWatchdogLock = PR_NewLock();
	if (gWatchdogLock) {
		gWatchdogWakeup = PR_NewCondVar(gWatchdogLock);
		if (gWatchdogWakeup) {
			gSleepWakeup = PR_NewCondVar(gWatchdogLock);
			if (gSleepWakeup)
				return true;
			PR_DestroyCondVar(gWatchdogWakeup);
		}
		PR_DestroyLock(gWatchdogLock);
	}
	return false;
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
	rt = JS_NewRuntime(32L * 1024L * 1024L);
	if (!rt)
		return (-1);
	JS_SetGCParameter(rt, JSGC_MAX_BYTES, 0xffffffff);
	JS_SetNativeStackQuota(rt, gMaxStackSize);
	if (!InitWatchdog(rt))
		return (-1);
	gRuntime = rt;
        return (0);
}
