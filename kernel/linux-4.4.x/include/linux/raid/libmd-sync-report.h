#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
// Copyright (c) 2000-2017 Synology Inc. All rights reserved.
#ifndef _LIBMD_SYNC_REPORT_H
#define _LIBMD_SYNC_REPORT_H

#ifdef MY_ABC_HERE
extern int (*funcSYNOSendRaidSyncEvent)(const char *szSyncType, int isSyncFinish, int isSyncInterrupt, int md_minor);
void SynoReportSyncStatus(const char *szSyncType, int isSyncFinish, int isSyncInterrupt, int md_minor);
#endif /* MY_ABC_HERE */
#endif /* _LIBMD_SYNC_REPORT_H */
