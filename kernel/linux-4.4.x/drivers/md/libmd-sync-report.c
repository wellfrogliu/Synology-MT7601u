#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
// Copyright (c) 2000-2017 Synology Inc. All rights reserved.
#ifdef MY_ABC_HERE
#include <linux/bio.h>
#include <linux/synobios.h>
#include <linux/synolib.h>

#include <linux/raid/libmd-sync-report.h>
#include "md.h"

int (*funcSYNOSendRaidSyncEvent)(const char *, int, int, int) = NULL;

void SynoReportSyncStatus(const char *szSyncType, int isSyncFinish, int isSyncInterrupt, int md_minor)
{
	if (funcSYNOSendRaidSyncEvent) {
		funcSYNOSendRaidSyncEvent(szSyncType, isSyncFinish, isSyncInterrupt, md_minor);
	} else {
		printk(KERN_ERR "md%d: Failed to send sync event: (sync type: %s, finish: %d, interrupt: %d)\n",
				md_minor, szSyncType, isSyncFinish, isSyncInterrupt);
	}
}

EXPORT_SYMBOL(SynoReportSyncStatus);
EXPORT_SYMBOL(funcSYNOSendRaidSyncEvent);
#endif /* MY_ABC_HERE */
