#!/bin/sh

in="$1"
out="$2"
my_abis=`echo "($3)" | tr ',' '|'`
prefix="$4"
offset="$5"

syno_syscalls()
{
cat << SYNO_SYSTEM_CALLS

#ifndef __KERNEL__
#include <bits/wordsize.h>

#define SYNOUtime(arg1, arg2)				syscall(__NR_SYNOUtime, arg1, arg2)

#define SYNOArchiveBit(arg1, arg2)			syscall(__NR_SYNOArchiveBit, arg1, arg2)

#define recvfile(arg1, arg2, arg3, arg4, arg5)		syscall(__NR_recvfile, arg1, arg2, arg3, arg4, arg5)

#define SYNOMTDAlloc(arg1)				syscall(__NR_SYNOMTDAlloc, arg1)

#define SYNOCaselessStat(arg1, arg2)			syscall(__NR_SYNOCaselessStat, arg1, arg2)
#define SYNOCaselessLStat(arg1, arg2)			syscall(__NR_SYNOCaselessLStat, arg1, arg2)

#define SYNOEcryptName(arg1, arg2)			syscall(__NR_SYNOEcryptName, arg1, arg2)
#define SYNODecryptName(arg1, arg2, arg3)		syscall(__NR_SYNODecryptName, arg1, arg2, arg3)

#define SYNOACLSysCheckPerm(arg1, arg2)			syscall(__NR_SYNOACLCheckPerm, arg1, arg2)
#define SYNOACLSysIsSupport(arg1, arg2, arg3)		syscall(__NR_SYNOACLIsSupport, arg1, arg2, arg3)
#define SYNOACLSysGetPerm(arg1, arg2)			syscall(__NR_SYNOACLGetPerm, arg1, arg2)

#define SYNOFlushAggregate(arg1)			syscall(__NR_SYNOFlushAggregate, arg1)

#if (__WORDSIZE == 64) || (_FILE_OFFSET_BITS == 64)
#define SYNOStat(arg1, arg2, arg3)				syscall(__NR_SYNOStat, arg1, arg2, arg3)
#define SYNOFStat(arg1, arg2, arg3)				syscall(__NR_SYNOFStat, arg1, arg2, arg3)
#define SYNOLStat(arg1, arg2, arg3)				syscall(__NR_SYNOLStat, arg1, arg2, arg3)
#endif /* (__WORDSIZE == 64) || (_FILE_OFFSET_BITS == 64) */

#define SYNONotifyInit(arg1)				syscall(__NR_SYNONotifyInit, arg1)
#define SYNONotifyAddWatch(arg1, arg2, arg3)		syscall(__NR_SYNONotifyAddWatch, arg1, arg2, arg3)
#define SYNONotifyRemoveWatch(arg1, arg2, arg3)		syscall(__NR_SYNONotifyRemoveWatch, arg1, arg2, arg3)
#define SYNONotifyAddWatch32(arg1, arg2, arg3)		syscall(__NR_SYNONotifyAddWatch32, arg1, arg2, arg3)
#define SYNONotifyRemoveWatch32(arg1, arg2, arg3)	syscall(__NR_SYNONotifyRemoveWatch32, arg1, arg2, arg3)

#define SYNOArchiveOverwrite(arg1, arg2)		syscall(__NR_SYNOArchiveOverwrite, arg1, arg2)
#endif

SYNO_SYSTEM_CALLS
}

fileguard=_ASM_X86_`basename "$out" | sed \
    -e 'y/abcdefghijklmnopqrstuvwxyz/ABCDEFGHIJKLMNOPQRSTUVWXYZ/' \
    -e 's/[^A-Z0-9_]/_/g' -e 's/__/_/g'`
grep -E "^[0-9A-Fa-fXx]+[[:space:]]+${my_abis}" "$in" | sort -n | (
    echo "#ifndef ${fileguard}"
    echo "#define ${fileguard} 1"
    echo ""

    while read nr abi name entry ; do
	if [ -z "$offset" ]; then
	    echo "#define __NR_${prefix}${name} $nr"
	else
	    echo "#define __NR_${prefix}${name} ($offset + $nr)"
        fi
    done

    syno_syscalls

    echo ""
    echo "#endif /* ${fileguard} */"
) > "$out"
