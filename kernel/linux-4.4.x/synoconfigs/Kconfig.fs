menu "File Systems"

menu "Basic"

config SYNO_FS_STAT
	bool "SYNOStat"
	default y
	depends on SYNO_SYSTEM_CALL

config SYNO_FS_XATTR
	bool "syno xattr"
	default y

config SYNO_FS_UNMOUNT
	bool "syno umount dump opened file"
	default y

config SYNO_FS_ARCHIVE_BIT
	bool "syno archive bit"
	default y

config SYNO_FS_ARCHIVE_VERSION
	bool "syno archive version"
	default y

config SYNO_FS_CREATE_TIME
	bool "syno create time"
	default y

config SYNO_FS_EXPORT_SYMBOL_FALLOCATE
	bool "Export symbol: do_fallocate"
	default y

config SYNO_FS_WINACL
	bool ""
	default y
	depends on SYNO_FS_ARCHIVE_BIT

config SYNO_FS_SKIP_RO_NEW_INODE_WARNING
	bool "Skip I_NEW WARN_ON when read-write on crached raid"
	default y

config SYNO_FS_RECVFILE
	bool "Support system call recvfile"
	default y

config SYNO_FS_EXT_SKIP_FSCK_REMINDER
	bool "Skip unused fsck remainder warning on ext2/3/4"
	default y
	depends on EXT2_FS || EXT4_FS

config SYNO_FS_CASELESS_STAT
	bool "Support caseless stat in filesystem "
	default y
	depends on SYNO_SYSTEM_CALL

config SYNO_FS_EXPORT_SYMBOL_LOOKUP_HASH
	bool "Export symbol: lookup_hash"
	default y

config SYNO_FS_REMOVE_RCU_WALK_PATH
	bool "Remove rcu path walk to prevent deadlock"
	default y

config SYNO_FS_NOTIFY
	bool "Support Synotify"
	default y
	depends on FSNOTIFY && ANON_INODES

config SYNO_FS_FIX_NOTIFY_CHANGE_WARN_ON
	bool "Fix notify_change warn_on on boot"
	default y

config SYNO_FS_RELATIME_PERIOD
	bool "Add mount option to set update period of relatime"
	default y

endmenu #Basic

menu "CIFS"
config SYNO_CIFS_REPLACE_NATIVE_OS
	bool "Identify Synology CIFS mount"
	default y

config SYNO_CIFS_TCON_RECONNECT_CODEPAGE_UTF8
	bool "Cifs with UTF8 code page"
	default y

config SYNO_CIFS_INIT_NLINK
	bool "Initialize fattr with cf_nlink=1 in cifs_dir_info_to_fattr"
	default y

config SYNO_CIFS_SPECIAL_CHAR_CONVER
	bool "CIFS convert special char for MAC"
	default y

config SYNO_CIFS_MOUNT_CASELESS
	bool "Caseless remote mount"
	default y

config SYNO_CIFS_NO_SPECIAL_CHAR_LOGON
	bool "STATUS_LOGON_FAILURE when password contains '/'"
	default y
	depends on SYNO_CIFS_SPECIAL_CHAR_CONVER

config SYNO_CIFS_FORCE_UMOUNT
	bool ""
	default y

config SYNO_CIFS_INCREASE_SENDMSG_TIMEOUT
	bool "increase the kernel_sendmsg EAGAIN timeout for more stability"
	default y

config SYNO_CIFS_SMB_OPS
	bool "add vers=syno for switch SMB1~3 from negotiate"
	default y
	depends on SYNO_CIFS_REPLACE_NATIVE_OS

endmenu #CIFS

menu "FAT"

config SYNO_FAT_DEFAULT_MNT_FLUSH
	bool "Set FAT default mount option 'flush'"
	default y
	depends on FAT_FS

config SYNO_FAT_LOAD_DEF_NLS_IF_FAIL
	bool "Try default nls as codepage setting when default codepage cannot be loaded"
	default y
	depends on FAT_FS

config SYNO_FAT_CREATE_TIME
	bool "FAT syno create time"
	default y
	depends on SYNO_FS_CREATE_TIME && FAT_FS

config SYNO_FAT_SYNOBOOT_LOG
	bool "synoboot access log"
	default y
	depends on FAT_FS

endmenu

menu "EXT3"

config SYNO_EXT3_STAT
	bool "Ext3 SYNOStat"
	default y
	depends on SYNO_FS_STAT && EXT3_FS

config SYNO_EXT3_XATTR
	bool "Ext3 syno xattr"
	default y
	depends on SYNO_FS_XATTR && EXT3_FS

config SYNO_EXT3_ARCHIVE_BIT
	bool "Ext3 syno archive bit"
	default y
	depends on SYNO_FS_ARCHIVE_BIT && EXT3_FS

config SYNO_EXT3_ARCHIVE_VERSION
	bool "Ext3 syno archive version"
	default y
	depends on SYNO_FS_ARCHIVE_VERSION && EXT3_FS && SYNO_EXT3_XATTR

config SYNO_EXT3_CREATE_TIME
	bool "Ext3 syno create time"
	default y
	depends on SYNO_FS_CREATE_TIME && EXT3_FS

endmenu #EXT3

menu "EXT4"

config SYNO_EXT4_LAZYINIT_INFO
	bool "Export lazyinit progress to sysfs"
	default y
	depends on EXT4_FS

config SYNO_EXT4_LAZYINIT_DYNAMIC_SPEED
	bool "Adjust lazyinit speed dynamically"
	default y
	depends on EXT4_FS

config SYNO_EXT4_LAZYINIT_WAIT_MULT
	int "Number of lazyinit wait multiplier"
	default 2
	depends on EXT4_FS

config SYNO_EXT4_STAT
	bool "Ext4 SYNOStat"
	default y
	depends on SYNO_FS_STAT && EXT4_FS

config SYNO_EXT4_XATTR
	bool "Ext4 syno xattr"
	default y
	depends on SYNO_FS_XATTR && EXT4_FS

config SYNO_EXT4_ARCHIVE_BIT
	bool "Ext4 syno archive bit"
	default y
	depends on SYNO_FS_ARCHIVE_BIT && EXT4_FS

config SYNO_EXT4_ARCHIVE_VERSION
	bool "Ext4 syno archive version"
	default y
	depends on SYNO_FS_ARCHIVE_VERSION && EXT4_FS && SYNO_EXT4_XATTR

config SYNO_EXT4_ARCHIVE_VERSION_FIX
	bool "Ext4 syno arhchive version fix"
	default y
	depends on SYNO_EXT4_ARCHIVE_VERSION

config SYNO_EXT4_CREATE_TIME
	bool "Ext4 syno create time"
	default y
	depends on SYNO_FS_CREATE_TIME && EXT4_FS

config SYNO_EXT4_CREATE_TIME_BIG_ENDIAN_SWAP
	bool "Ext4 syno create time swap for big endian"
	default y if SYNO_QORIQ || SYNO_MPC8533
	depends on SYNO_EXT4_CREATE_TIME

config SYNO_EXT4_DEFAULT_MNTOPT_JOURNAL_CKSUM
	bool "Ext4 set default mount option journal_checksum"
	default y
	depends on EXT4_FS

config SYNO_EXT4_DEFAULT_MNTOPT_NOBARRIER
	bool "Ext4 set default mount option barrier=0"
	default y
	depends on EXT4_FS

config SYNO_EXT4_DEFAULT_MNTOPT_BARRIER_ROOTFS
	bool "Ext4 set default mount option barrier=1 on root fs"
	default y
	depends on EXT4_FS

config SYNO_EXT4_ERROR_REPORT
	bool "Enable ext4 error report mechanism"
	default y
	depends on EXT4_FS

config SYNO_EXT4_INODE_NUM_OVERFLOW_FIX
	bool "Fix ext4 inode number overflow problem on large volume (>64TB)"
	default y
	depends on EXT4_FS && 64BIT

config SYNO_EXT4_CASELESS_STAT
	bool "Support caseless stat in ext4"
	default y
	depends on SYNO_FS_CASELESS_STAT && EXT4_FS

config SYNO_EXT4_SKIP_ADD_RESERVED_BLOCKS
	bool "Don't update reserved blocks on resize"
	default y
	depends on EXT4_FS

config SYNO_EXT4_SKIP_JOURNAL_SYMLINK
	bool "Use writeback mode instead of jounal mode when doing ext4 symlink"
	default y
	depends on EXT4_FS

config SYNO_EXT4_FORCE_UPDATE_DA_FILE_SIZE
	bool "Force update file size on buffer_delay if the file is growing"
	default y
	depends on EXT4_FS

config SYNO_EXT4_PARALLEL_GROUP_DESC_PREFETCH_WHEN_MOUNT
	bool "Add parallel group desc prefetching to enhance mount time."
	default y
	depends on EXT4_FS

config SYNO_EXT4_ADD_RETRY_MECH_FOR_SYMLINK
	bool "Add retry back for symlink to prevant ENOSPC error."
	default y
	depends on EXT4_FS

endmenu #EXT4

menu "BTRFS"

config SYNO_BTRFS_PORTING
	bool "Btrfs back porting"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_STAT
	bool "Btrfs SYNOStat"
	default y
	depends on SYNO_FS_STAT && BTRFS_FS

config SYNO_BTRFS_XATTR
	bool "Btrfs syno xattr"
	default y
	depends on SYNO_FS_XATTR && BTRFS_FS

config SYNO_BTRFS_ARCHIVE_BIT
	bool "Btrfs syno archive bit"
	default y
	depends on SYNO_FS_ARCHIVE_BIT && BTRFS_FS && SYNO_BTRFS_XATTR

config SYNO_BTRFS_PIN_LOG_ON_DELETE_INODE
	bool "Pin tree-log while unlink to prevent deadlock."
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_METADATA_OVERCOMMIT_POLICY
	bool "Change metadata over commit policy to prevent file system crash."
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_FLUSHONCOMMIT_THRESHOLD
	bool "Release btrfs ordered extent to prevent OOM"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_FIX_PAGE_LEAK_WHILE_CLONE_EXTENT_BUFFER
	bool "Fix btrfs memory leak on clone extent buffer."
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_CLONE_CHECK_QUOTA
	bool "Add quota check for IOC_CLONE ioctl command"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_FREE_EXTENT_MAPS
	bool "Add a machanisim to drop extent map cache"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_CLUSTER_RESERVE
	bool "Reserve meta block to suppress problem of extent tree loop"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_CREATE_TIME
	bool "Add syno create time for btrfs"
	default y
	depends on SYNO_FS_CREATE_TIME && SYNO_BTRFS_XATTR && BTRFS_FS

config SYNO_BTRFS_RESIZE_QUERY
	bool "Add a dry-run mode in BTRFS_IOC_RESIZE"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_SUBVOLUME_HIDE
	bool "Support subvolume hide flag"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_ARCHIVE_VERSION
	bool "Support syno archive version for btrfs"
	default y
	depends on SYNO_FS_ARCHIVE_VERSION && SYNO_BTRFS_XATTR && BTRFS_FS

config SYNO_BTRFS_SEND
	bool "Add syno btrfs send"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_FIX_ASYNC_DIRECT_IO_CSUM_FAILED
	bool "Disable btrfs async read on direct io."
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_SUPPORT_FULLY_CLONE_BETWEEN_CSUM_AND_NOCSUM_DIR
	bool "Fix cp --reflink failed between csum/nocsum"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_QGROUP_QUERY
	bool "Add ioctl for btrfs qgroup query"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_RENAME_READONLY_SUBVOL
	bool "Fix rename readonly subvol fail"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_CORRECT_SPACEINFO_LOCK
	bool "Correct btrfs statfs block group list lock"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_REMOVE_UNUSED_QGROUP
	bool "Remove qgroup item when snapshot got deleted"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_REVERT_WAIT_OR_COMMIT_SELF_TRANS
	bool "Revert commit: wait or commit self transaction"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_BIG_BLOCK_GROUP
	bool "Use big block group to reduce mount time on big volume"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_REVERT_BIO_COUNT_FOR_DEV_REPLACING
	bool "Fix btrfs hang on btrfs_end_io*"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_SEND_CALCULATE_TOTAL_DATA_SIZE
	bool "add btrfs calculate send data size"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_SEND_SUBVOL_FLAG
	bool "add btrfs send subvol flag"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_REVERT_DELAYED_DELETE_INODE
	bool "Fix dbench hang on delayed_delete_inode"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_UMOUNT_ERROR_VOLUME
	bool "Fix umount on a error Btrfs volume"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_DISABLE_CLONE_BETWEEN_COMPR_AND_NOCOMPR_DIR
	bool "Prevent clone files between compress/nocompress share folders"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_COMPR_CTL
	bool "Operate compressed files"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_COMPR_DEFAULT_SETTING
	bool "Apply default setting of syno compression"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_METADATA_RESERVE
	bool "Pre-allocate btrfs metadata chunk with metadata_ratio."
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_FIX_INCREMENTAL_SEND
	bool "fix btrfs send incremental send"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_AVOID_NULL_ACCESS_IN_PENDING_SNAPSHOT
	bool "Avoid NULL pointer dereference at create_pending_snapshots"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_ADD_LOCK_ON_FLUSH_ORDERED_EXTENT
	bool "Add mutex lock on btrfs ordered extent flush to prevent memory leak."
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_BLOCK_GROUP_HINT_TREE
	bool "Add a block group hint tree to speedup volume mount."
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_RESERVE_PROP_SPACE_FOR_COMPRESSION
	bool "Reserve space for compression props on start_transaction."
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_AVOID_TRIM_SYS_CHUNK
	bool "Avoid trim system chunk."
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_GLOBAL_RESERVE_MINIMAL_VALUE
	bool "Keep btrfs global reserve more than 256MB if the fs is larger than 10G."
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_REVERT_FITRIM_UNUSED_CHUNK_SPACE
	bool "Revert commit btrfs: iterate over unused chunk space in FITRIM"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_QGROUP_LIMIT
	bool "fix set qgroup limit to not check flag, because compatibility with old version"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_SEND_SUPPORT_PAUSE_RESUME
	bool "add btrfs send support pause/resume"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_TREE_LOG_RECOVER_FIX
	bool "Fix tree log recovery"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_AVOID_NULL_POINTER_DEREFERENCE_WHEN_MOUNT
	bool "avoid null pointer dereference when mount"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_MERGE_HOLES
	bool "file hole can be merged with both previous and next hole items"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_AVOID_DEADLOCK
	bool "avoid deadlock with btrfs-uuid and delete subvol"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_DEFRAG
	bool "add support for doing defrag on nocow file"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_FIX_PUNCH_HOLE_ENOSPC
	bool "fix punch hole no space when split leaf, may lead to BUG_ON"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_FIX_SNAPSHOT_HANG
	bool "fix snapshot hang"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_SEND_ASYNC_PAGECACHE_RA
	bool "btrfs send uses async page cache readhead to accelerate"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_BACKREF
	bool "provide backref walking mechanism framework"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_SNAPSHOT_SIZE_CALCULATION
	bool "add ioctl to calculate actual disk size of snapshots"
	default y
	depends on BTRFS_FS && SYNO_BTRFS_BACKREF

config SYNO_BTRFS_AVOID_CACHE_BLOCK_GROUP_SOFT_LOCKUP
	bool "Avoid soft lockup when cache_block_group with mount option nospace_cache"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_FIX_DELAYED_DATA_REF_OOM
	bool "fix oom when huge amount of file extent (running iozone + snapshot)"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_DEFAULT_SAPCE_CACHE_V2
	bool "default space cache v2"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_REDUCE_LOCK_CONTENTION_IMPROVE_IOPS
	bool "reduce lock contention for fs-tree and csum-tree with random write IOPS"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_FIX_MOUNT_OPTION_COMMIT_1S_NO_EFFECT
	bool "fix mount option commit=1 no effect, when race transaction blocked, will sleep 5s"
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_CHECK_INTEGRITY
	bool "Auto fix error in check_leaf()."
	default y
	depends on BTRFS_FS

config SYNO_BTRFS_FIX_TRIM_ENOSPC
	bool "Fix trim will lead to ENOSPC and lose data."
	default y
	depends on BTRFS_FS

endmenu #BTRFS

menu "ECRYPT"

config SYNO_ECRYPTFS_STAT
	bool "Ecryptfs SYNOStat"
	default y
	depends on SYNO_FS_STAT && ECRYPT_FS

config SYNO_ECRYPTFS_ARCHIVE_BIT
	bool "Ecryptfs archive bit"
	default y
	depends on SYNO_FS_ARCHIVE_BIT && ECRYPT_FS

config SYNO_ECRYPTFS_ARCHIVE_VERSION
	bool "Ecryptfs archive version"
	default y
	depends on SYNO_FS_ARCHIVE_VERSION && ECRYPT_FS

config SYNO_ECRYPTFS_CREATE_TIME
	bool "Ecryptfs syno create time"
	default y
	depends on SYNO_FS_CREATE_TIME && ECRYPT_FS

config SYNO_ECRYPTFS_SKIP_EDQUOT_WARNING
	bool "Ecryptfs skip EDQUOT, ENOSPC warning log"
	default y
	depends on ECRYPT_FS

config SYNO_ECRYPTFS_SKIP_AUTH_WARNING
	bool "Ecryptfs add ratelimit to auth tok not found error message"
	default y
	depends on ECRYPT_FS

config SYNO_ECRYPTFS_REMOVE_TRUNCATE_WRITE
	bool "Speed up ecryptfs truncate by skipping zeros write"
	default y
	depends on ECRYPT_FS

config SYNO_ECRYPTFS_CHECK_SYMLINK_LENGTH
	bool "Check ecryptfs symlink target length after encryption"
	default y
	depends on ECRYPT_FS

config SYNO_ECRYPTFS_FILENAME_SYSCALL
	bool "System calls to get encrypt or decrypt filename"
	default y
	depends on SYNO_SYSTEM_CALL && ECRYPT_FS

config SYNO_ECRYPTFS_OCF
	bool "enable ocf framework"
	default n
	depends on ECRYPT_FS && OCF_OCF

config SYNO_ECRYPTFS_LOWER_INIT
	bool "Ecryptfs always initial lower file with rw, ignore security check on initialization"
	default y
	depends on ECRYPT_FS

config SYNO_ECRYPTFS_SKIP_KERNEL_WRITE_CHECK
	bool "Skip security check during kernel_write."
	default y
	depends on ECRYPT_FS

config SYNO_ECRYPTFS_FAST_LOOKUP
	bool "Fast lookup, read i_size from xattr"
	default y
	depends on ECRYPT_FS

config SYNO_ECRYPTFS_SKIP_EQUAL_ISIZE_UPDATE
	bool "Update ecryptfs i_size only when they are different"
	default y
	depends on ECRYPT_FS

endmenu #ECRYPT
menu "NFS"

config SYNO_NFSD_WRITE_SIZE_MIN
	int "NFSD min packet size"
	default 131072

config SYNO_NFSD_UDP_PACKET
	bool "Provide a interface for user to set the udp packet size they want"
	default y

config SYNO_NFSD_UDP_MAX_PACKET_SIZE
	int "Provide a interface for user to set the udp packet size they want"
	default 32768
	depends on SYNO_NFSD_UDP_PACKET

config SYNO_NFSD_UDP_MIN_PACKET_SIZE
	int "Provide a interface for user to set the udp packet size they want"
	default	4096
	depends on SYNO_NFSD_UDP_PACKET

config SYNO_NFSD_UDP_DEF_PACKET_SIZE
	int "Provide a interface for user to set the udp packet size they want"
	default 8192
	depends on SYNO_NFSD_UDP_PACKET

config SYNO_NFSD_UNIX_PRI
	bool "Provide a interface for user to enable command chmod or not on ACL share"
	default y

config SYNO_NFS4_DISABLE_UDP
	bool "disable NFSv4 over UDP"
	default y

config SYNO_NFSD_HIDDEN_FILE
	bool "Hide system directories"
	default y

config SYNO_NFSD_AVOID_HUNG_TASK_WHEN_UNLINK_BIG_FILE
	bool "Avoid parent mutex hung task when unlink big file"
	default y

endmenu #NFS

menu "HFSPLUS"

config SYNO_HFSPLUS_MAX_FILENAME_CHECK
	bool "HFS+ return error when filename's length > 255"
	default y
	depends on HFSPLUS_FS

config SYNO_HFSPLUS_DONT_ZERO_ON_NEW_FILE
	bool "HFS+ don't zero a newly created file"
	default y
	depends on HFSPLUS_FS

config SYNO_HFSPLUS_ADD_MUTEX_FOR_VFS_OPERATION
	bool "HFS+ add mutex lock on all vsf operation"
	default y
	depends on HFSPLUS_FS

config SYNO_HFSPLUS_ERROR_HANDLE_ENHANCE
	bool "HFS+ change some WARN_ON to warning message and RO fs"
	default y
	depends on HFSPLUS_FS

config SYNO_HFSPLUS_SHOW_CASELESS_INFO
	bool "HFS+ show caseless option"
	default y
	depends on HFSPLUS_FS

config SYNO_HFSPLUS_CASELESS_CREATE_BY_NEW_NAME
	bool "HFS+ create caseless dentry by new name"
	default y
	depends on HFSPLUS_FS

config SYNO_HFSPLUS_EA
	bool "HFS+ enable EA support"
	default y
	depends on HFSPLUS_FS

config SYNO_HFSPLUS_BREC_FIND_RET_CHECK
	bool "Check brec_find return value while update parent"
	default y
	depends on HFSPLUS_FS

endmenu #HFSPLUS

menu "UDF"
config SYNO_UDF_CASELESS
	bool "UDF use caseless lookup"
	default y
	depends on UDF_FS

config SYNO_UDF_UINT_UID_GID
	bool "UDF uses unsigned int UID/GID"
	default y

endmenu #UDF

menu "ISOFS"

config SYNO_ISOFS_UINT_UID_GID
	bool "ISOFS uses unsigned int UID/GID"
	default y

endmenu #ISOFS

menu "FUSE"

config SYNO_FUSE_GLUSTER
	bool "Let fuse handle gluster specifically"
	default y
	depends on FUSE_FS

config SYNO_FUSE_STAT
	bool "Gluster FS support synostat and caseless stat"
	default y
	depends on FUSE_FS && SYNO_FS_STAT && SYNO_FS_CASELESS_STAT

config SYNO_FUSE_ARCHIVE_VERSION
	bool "Gluster FS support archive verion"
	default y
	depends on FUSE_FS && SYNO_FS_ARCHIVE_VERSION

config SYNO_FUSE_CREATE_TIME
	bool "Gluster FS support syno create time"
	default y
	depends on FUSE_FS && SYNO_FS_CREATE_TIME

config SYNO_FUSE_WINACL
	bool "Gluster FS support synoacl"
	default y
	depends on FUSE_FS && SYNO_FS_WINACL && SYNO_FS_ARCHIVE_BIT && SYNO_FUSE_GLUSTER

config SYNO_FUSE_ARCHIVE_BIT
	bool "Gluster FS support syno archive bit"
	default y
	depends on FUSE_FS && SYNO_FS_ARCHIVE_BIT && SYNO_FUSE_GLUSTER

endmenu #FUSE

menu "ConfigFS"

config SYNO_FS_CONFIGFS_BACKPORT
	bool "backport commits for configfs"
	default y

endmenu #ConfigFS

endmenu #File Systems
