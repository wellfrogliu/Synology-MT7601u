#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef _CIFS_GLOB_H
#define _CIFS_GLOB_H

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/slab.h>
#include <linux/mempool.h>
#include <linux/workqueue.h>
#include "cifs_fs_sb.h"
#include "cifsacl.h"
#include <crypto/internal/hash.h>
#include <linux/scatterlist.h>
#include <uapi/linux/cifs/cifs_mount.h>
#ifdef CONFIG_CIFS_SMB2
#include "smb2pdu.h"
#endif

#define CIFS_MAGIC_NUMBER 0xFF534D42       

#define MAX_UID_INFO 16
#define MAX_SES_INFO 2
#define MAX_TCON_INFO 4

#define MAX_TREE_SIZE (2 + CIFS_NI_MAXHOST + 1 + CIFS_MAX_SHARE_LEN + 1)

#define CIFS_MIN_RCV_POOL 4

#define MAX_REOPEN_ATT	5  
 
#define CIFS_DEF_ACTIMEO (1 * HZ)

#define CIFS_MAX_ACTIMEO (1 << 30)

#define CIFS_MAX_REQ 32767

#define RFC1001_NAME_LEN 15
#define RFC1001_NAME_LEN_WITH_NULL (RFC1001_NAME_LEN + 1)

#define SERVER_NAME_LENGTH 40
#define SERVER_NAME_LEN_WITH_NULL     (SERVER_NAME_LENGTH + 1)

#define SMB_ECHO_INTERVAL (60 * HZ)

#include "cifspdu.h"

#ifndef XATTR_DOS_ATTRIB
#define XATTR_DOS_ATTRIB "user.DOSATTRIB"
#endif

enum statusEnum {
	CifsNew = 0,
	CifsGood,
	CifsExiting,
	CifsNeedReconnect,
	CifsNeedNegotiate
};

enum securityEnum {
	Unspecified = 0,	 
	LANMAN,			 
	NTLM,			 
	NTLMv2,			 
	RawNTLMSSP,		 
	Kerberos,		 
};

struct session_key {
	unsigned int len;
	char *response;
};

struct sdesc {
	struct shash_desc shash;
	char ctx[];
};

struct cifs_secmech {
	struct crypto_shash *hmacmd5;  
	struct crypto_shash *md5;  
	struct crypto_shash *hmacsha256;  
	struct crypto_shash *cmacaes;  
	struct sdesc *sdeschmacmd5;   
	struct sdesc *sdescmd5;  
	struct sdesc *sdeschmacsha256;   
	struct sdesc *sdesccmacaes;   
};

struct ntlmssp_auth {
	bool sesskey_per_smbsess;  
	__u32 client_flags;  
	__u32 server_flags;  
	unsigned char ciphertext[CIFS_CPHTXT_SIZE];  
	char cryptkey[CIFS_CRYPTO_KEY_SIZE];  
};

struct cifs_cred {
	int uid;
	int gid;
	int mode;
	int cecount;
	struct cifs_sid osid;
	struct cifs_sid gsid;
	struct cifs_ntace *ntaces;
	struct cifs_ace *aces;
};

struct smb_rqst {
	struct kvec	*rq_iov;	 
	unsigned int	rq_nvec;	 
	struct page	**rq_pages;	 
	unsigned int	rq_npages;	 
	unsigned int	rq_pagesz;	 
	unsigned int	rq_tailsz;	 
};

enum smb_version {
	Smb_1 = 1,
#ifdef MY_ABC_HERE
	Smb_Syno,
#endif  
	Smb_20,
	Smb_21,
	Smb_30,
	Smb_302,
#ifdef CONFIG_CIFS_SMB311
	Smb_311,
#endif  
	Smb_version_err
};

struct mid_q_entry;
struct TCP_Server_Info;
struct cifsFileInfo;
struct cifs_ses;
struct cifs_tcon;
struct dfs_info3_param;
struct cifs_fattr;
struct smb_vol;
struct cifs_fid;
struct cifs_readdata;
struct cifs_writedata;
struct cifs_io_parms;
struct cifs_search_info;
struct cifsInodeInfo;
struct cifs_open_parms;

struct smb_version_operations {
	int (*send_cancel)(struct TCP_Server_Info *, void *,
			   struct mid_q_entry *);
	bool (*compare_fids)(struct cifsFileInfo *, struct cifsFileInfo *);
	 
	struct mid_q_entry *(*setup_request)(struct cifs_ses *,
						struct smb_rqst *);
	 
	struct mid_q_entry *(*setup_async_request)(struct TCP_Server_Info *,
						struct smb_rqst *);
	 
	int (*check_receive)(struct mid_q_entry *, struct TCP_Server_Info *,
			     bool);
	void (*add_credits)(struct TCP_Server_Info *, const unsigned int,
			    const int);
	void (*set_credits)(struct TCP_Server_Info *, const int);
	int * (*get_credits_field)(struct TCP_Server_Info *, const int);
	unsigned int (*get_credits)(struct mid_q_entry *);
	__u64 (*get_next_mid)(struct TCP_Server_Info *);
	 
	unsigned int (*read_data_offset)(char *);
	 
	unsigned int (*read_data_length)(char *);
	 
	int (*map_error)(char *, bool);
	 
	struct mid_q_entry * (*find_mid)(struct TCP_Server_Info *, char *);
	void (*dump_detail)(void *);
	void (*clear_stats)(struct cifs_tcon *);
	void (*print_stats)(struct seq_file *m, struct cifs_tcon *);
	void (*dump_share_caps)(struct seq_file *, struct cifs_tcon *);
	 
	int (*check_message)(char *, unsigned int);
	bool (*is_oplock_break)(char *, struct TCP_Server_Info *);
	void (*downgrade_oplock)(struct TCP_Server_Info *,
					struct cifsInodeInfo *, bool);
	 
	bool (*check_trans2)(struct mid_q_entry *, struct TCP_Server_Info *,
			     char *, int);
	 
	bool (*need_neg)(struct TCP_Server_Info *);
	 
	int (*negotiate)(const unsigned int, struct cifs_ses *);
	 
	unsigned int (*negotiate_wsize)(struct cifs_tcon *, struct smb_vol *);
	 
	unsigned int (*negotiate_rsize)(struct cifs_tcon *, struct smb_vol *);
	 
	int (*sess_setup)(const unsigned int, struct cifs_ses *,
			  const struct nls_table *);
	 
	int (*logoff)(const unsigned int, struct cifs_ses *);
	 
	int (*tree_connect)(const unsigned int, struct cifs_ses *, const char *,
			    struct cifs_tcon *, const struct nls_table *);
	 
	int (*tree_disconnect)(const unsigned int, struct cifs_tcon *);
	 
	int (*get_dfs_refer)(const unsigned int, struct cifs_ses *,
			     const char *, struct dfs_info3_param **,
			     unsigned int *, const struct nls_table *, int);
	 
	void (*qfs_tcon)(const unsigned int, struct cifs_tcon *);
	 
	int (*is_path_accessible)(const unsigned int, struct cifs_tcon *,
				  struct cifs_sb_info *, const char *);
	 
	int (*query_path_info)(const unsigned int, struct cifs_tcon *,
			       struct cifs_sb_info *, const char *,
			       FILE_ALL_INFO *, bool *, bool *);
	 
	int (*query_file_info)(const unsigned int, struct cifs_tcon *,
			       struct cifs_fid *, FILE_ALL_INFO *);
	 
	int (*get_srv_inum)(const unsigned int, struct cifs_tcon *,
			    struct cifs_sb_info *, const char *,
			    u64 *uniqueid, FILE_ALL_INFO *);
	 
	int (*set_path_size)(const unsigned int, struct cifs_tcon *,
			     const char *, __u64, struct cifs_sb_info *, bool);
	 
	int (*set_file_size)(const unsigned int, struct cifs_tcon *,
			     struct cifsFileInfo *, __u64, bool);
	 
	int (*set_file_info)(struct inode *, const char *, FILE_BASIC_INFO *,
			     const unsigned int);
	int (*set_compression)(const unsigned int, struct cifs_tcon *,
			       struct cifsFileInfo *);
	 
	bool (*can_echo)(struct TCP_Server_Info *);
	 
	int (*echo)(struct TCP_Server_Info *);
	 
	int (*mkdir)(const unsigned int, struct cifs_tcon *, const char *,
		     struct cifs_sb_info *);
	 
	void (*mkdir_setinfo)(struct inode *, const char *,
			      struct cifs_sb_info *, struct cifs_tcon *,
			      const unsigned int);
	 
	int (*rmdir)(const unsigned int, struct cifs_tcon *, const char *,
		     struct cifs_sb_info *);
	 
	int (*unlink)(const unsigned int, struct cifs_tcon *, const char *,
		      struct cifs_sb_info *);
	 
	int (*rename_pending_delete)(const char *, struct dentry *,
				     const unsigned int);
	 
	int (*rename)(const unsigned int, struct cifs_tcon *, const char *,
		      const char *, struct cifs_sb_info *);
	 
	int (*create_hardlink)(const unsigned int, struct cifs_tcon *,
			       const char *, const char *,
			       struct cifs_sb_info *);
	 
	int (*query_symlink)(const unsigned int, struct cifs_tcon *,
			     const char *, char **, struct cifs_sb_info *);
	 
	int (*open)(const unsigned int, struct cifs_open_parms *,
		    __u32 *, FILE_ALL_INFO *);
	 
	void (*set_fid)(struct cifsFileInfo *, struct cifs_fid *, __u32);
	 
	void (*close)(const unsigned int, struct cifs_tcon *,
		      struct cifs_fid *);
	 
	int (*flush)(const unsigned int, struct cifs_tcon *, struct cifs_fid *);
	 
	int (*async_readv)(struct cifs_readdata *);
	 
	int (*async_writev)(struct cifs_writedata *,
			    void (*release)(struct kref *));
	 
	int (*sync_read)(const unsigned int, struct cifs_fid *,
			 struct cifs_io_parms *, unsigned int *, char **,
			 int *);
	 
	int (*sync_write)(const unsigned int, struct cifs_fid *,
			  struct cifs_io_parms *, unsigned int *, struct kvec *,
			  unsigned long);
	 
	int (*query_dir_first)(const unsigned int, struct cifs_tcon *,
			       const char *, struct cifs_sb_info *,
			       struct cifs_fid *, __u16,
			       struct cifs_search_info *);
	 
	int (*query_dir_next)(const unsigned int, struct cifs_tcon *,
			      struct cifs_fid *,
			      __u16, struct cifs_search_info *srch_inf);
	 
	int (*close_dir)(const unsigned int, struct cifs_tcon *,
			 struct cifs_fid *);
	 
	unsigned int (*calc_smb_size)(void *);
	 
	bool (*is_status_pending)(char *, struct TCP_Server_Info *, int);
	 
	int (*oplock_response)(struct cifs_tcon *, struct cifs_fid *,
			       struct cifsInodeInfo *);
	 
	int (*queryfs)(const unsigned int, struct cifs_tcon *,
		       struct kstatfs *);
	 
	int (*mand_lock)(const unsigned int, struct cifsFileInfo *, __u64,
			 __u64, __u32, int, int, bool);
	 
	int (*mand_unlock_range)(struct cifsFileInfo *, struct file_lock *,
				 const unsigned int);
	 
	int (*push_mand_locks)(struct cifsFileInfo *);
	 
	void (*get_lease_key)(struct inode *, struct cifs_fid *);
	 
	void (*set_lease_key)(struct inode *, struct cifs_fid *);
	 
	void (*new_lease_key)(struct cifs_fid *);
	int (*generate_signingkey)(struct cifs_ses *);
	int (*calc_signature)(struct smb_rqst *, struct TCP_Server_Info *);
	int (*set_integrity)(const unsigned int, struct cifs_tcon *tcon,
			     struct cifsFileInfo *src_file);
	int (*query_mf_symlink)(unsigned int, struct cifs_tcon *,
				struct cifs_sb_info *, const unsigned char *,
				char *, unsigned int *);
	int (*create_mf_symlink)(unsigned int, struct cifs_tcon *,
				 struct cifs_sb_info *, const unsigned char *,
				 char *, unsigned int *);
	 
#ifdef MY_ABC_HERE
	bool (*is_read_op)(struct TCP_Server_Info *, __u32);
#else
	bool (*is_read_op)(__u32);
#endif  
	 
	void (*set_oplock_level)(struct cifsInodeInfo *, __u32, unsigned int,
				 bool *);
	 
#ifdef MY_ABC_HERE
	char * (*create_lease_buf)(struct TCP_Server_Info *, u8 *, u8);
#else
	char * (*create_lease_buf)(u8 *, u8);
#endif  
	 
#ifdef MY_ABC_HERE
	__u8 (*parse_lease_buf)(struct TCP_Server_Info *, void *, unsigned int *);
#else
	__u8 (*parse_lease_buf)(void *, unsigned int *);
#endif  
	int (*clone_range)(const unsigned int, struct cifsFileInfo *src_file,
			struct cifsFileInfo *target_file, u64 src_off, u64 len,
			u64 dest_off);
	int (*duplicate_extents)(const unsigned int, struct cifsFileInfo *src,
			struct cifsFileInfo *target_file, u64 src_off, u64 len,
			u64 dest_off);
	int (*validate_negotiate)(const unsigned int, struct cifs_tcon *);
	ssize_t (*query_all_EAs)(const unsigned int, struct cifs_tcon *,
			const unsigned char *, const unsigned char *, char *,
			size_t, const struct nls_table *, int);
	int (*set_EA)(const unsigned int, struct cifs_tcon *, const char *,
			const char *, const void *, const __u16,
			const struct nls_table *, int);
	struct cifs_ntsd * (*get_acl)(struct cifs_sb_info *, struct inode *,
			const char *, u32 *);
	struct cifs_ntsd * (*get_acl_by_fid)(struct cifs_sb_info *,
			const struct cifs_fid *, u32 *);
	int (*set_acl)(struct cifs_ntsd *, __u32, struct inode *, const char *,
			int);
	 
	unsigned int (*wp_retry_size)(struct inode *);
	 
	int (*wait_mtu_credits)(struct TCP_Server_Info *, unsigned int,
				unsigned int *, unsigned int *);
	 
	bool (*dir_needs_close)(struct cifsFileInfo *);
	long (*fallocate)(struct file *, struct cifs_tcon *, int, loff_t,
			  loff_t);
};

struct smb_version_values {
	char		*version_string;
	__u16		protocol_id;
	__u32		req_capabilities;
	__u32		large_lock_type;
	__u32		exclusive_lock_type;
	__u32		shared_lock_type;
	__u32		unlock_lock_type;
	size_t		header_size;
	size_t		max_header_size;
	size_t		read_rsp_size;
	__le16		lock_cmd;
	unsigned int	cap_unix;
	unsigned int	cap_nt_find;
	unsigned int	cap_large_files;
	__u16		signing_enabled;
	__u16		signing_required;
	size_t		create_lease_size;
};

#define HEADER_SIZE(server) (server->vals->header_size)
#define MAX_HEADER_SIZE(server) (server->vals->max_header_size)

struct smb_vol {
	char *username;
	char *password;
	char *domainname;
	char *UNC;
	char *iocharset;   
	char source_rfc1001_name[RFC1001_NAME_LEN_WITH_NULL];  
	char target_rfc1001_name[RFC1001_NAME_LEN_WITH_NULL];  
	kuid_t cred_uid;
	kuid_t linux_uid;
	kgid_t linux_gid;
	kuid_t backupuid;
	kgid_t backupgid;
	umode_t file_mode;
	umode_t dir_mode;
	enum securityEnum sectype;  
	bool sign;  
	bool retry:1;
	bool intr:1;
	bool setuids:1;
	bool override_uid:1;
	bool override_gid:1;
	bool dynperm:1;
	bool noperm:1;
	bool no_psx_acl:1;  
	bool cifs_acl:1;
	bool backupuid_specified;  
	bool backupgid_specified;  
	bool no_xattr:1;    
	bool server_ino:1;  
	bool direct_io:1;
	bool strict_io:1;  
	bool remap:1;       
	bool sfu_remap:1;   
	bool posix_paths:1;  
	bool no_linux_ext:1;
	bool sfu_emul:1;
	bool nullauth:1;    
	bool nocase:1;      
	bool nobrl:1;       
	bool mand_lock:1;   
	bool seal:1;        
	bool nodfs:1;       
	bool local_lease:1;  
	bool noblocksnd:1;
	bool noautotune:1;
	bool nostrictsync:1;  
	bool fsc:1;	 
	bool mfsymlinks:1;  
	bool multiuser:1;
	bool rwpidforward:1;  
	bool nosharesock:1;
	bool persistent:1;
	bool nopersistent:1;
	bool resilient:1;  
	unsigned int rsize;
	unsigned int wsize;
	bool sockopt_tcp_nodelay:1;
	unsigned long actimeo;  
	struct smb_version_operations *ops;
	struct smb_version_values *vals;
	char *prepath;
	struct sockaddr_storage dstaddr;  
	struct sockaddr_storage srcaddr;  
	struct nls_table *local_nls;
};

#define CIFS_MOUNT_MASK (CIFS_MOUNT_NO_PERM | CIFS_MOUNT_SET_UID | \
			 CIFS_MOUNT_SERVER_INUM | CIFS_MOUNT_DIRECT_IO | \
			 CIFS_MOUNT_NO_XATTR | CIFS_MOUNT_MAP_SPECIAL_CHR | \
			 CIFS_MOUNT_MAP_SFM_CHR | \
			 CIFS_MOUNT_UNX_EMUL | CIFS_MOUNT_NO_BRL | \
			 CIFS_MOUNT_CIFS_ACL | CIFS_MOUNT_OVERR_UID | \
			 CIFS_MOUNT_OVERR_GID | CIFS_MOUNT_DYNPERM | \
			 CIFS_MOUNT_NOPOSIXBRL | CIFS_MOUNT_NOSSYNC | \
			 CIFS_MOUNT_FSCACHE | CIFS_MOUNT_MF_SYMLINKS | \
			 CIFS_MOUNT_MULTIUSER | CIFS_MOUNT_STRICT_IO | \
			 CIFS_MOUNT_CIFS_BACKUPUID | CIFS_MOUNT_CIFS_BACKUPGID)

#define CIFS_MS_MASK (MS_RDONLY | MS_MANDLOCK | MS_NOEXEC | MS_NOSUID | \
		      MS_NODEV | MS_SYNCHRONOUS)

struct cifs_mnt_data {
	struct cifs_sb_info *cifs_sb;
	struct smb_vol *vol;
	int flags;
};

static inline unsigned int
get_rfc1002_length(void *buf)
{
	return be32_to_cpu(*((__be32 *)buf)) & 0xffffff;
}

static inline void
inc_rfc1001_len(void *buf, int count)
{
	be32_add_cpu((__be32 *)buf, count);
}

struct TCP_Server_Info {
	struct list_head tcp_ses_list;
	struct list_head smb_ses_list;
	int srv_count;  
	 
	char server_RFC1001_name[RFC1001_NAME_LEN_WITH_NULL];
	struct smb_version_operations	*ops;
	struct smb_version_values	*vals;
#ifdef MY_ABC_HERE
	struct smb_version_values	values;
#endif  
	enum statusEnum tcpStatus;  
	char *hostname;  
	struct socket *ssocket;
	struct sockaddr_storage dstaddr;
	struct sockaddr_storage srcaddr;  
#ifdef CONFIG_NET_NS
	struct net *net;
#endif
	wait_queue_head_t response_q;
	wait_queue_head_t request_q;  
	struct list_head pending_mid_q;
	bool noblocksnd;		 
	bool noautotune;		 
	bool tcp_nodelay;
	int credits;   
	unsigned int in_flight;   
	spinlock_t req_lock;   
	struct mutex srv_mutex;
	struct task_struct *tsk;
	char server_GUID[16];
	__u16 sec_mode;
	bool sign;  
	bool session_estab;  
#ifdef CONFIG_CIFS_SMB2
	int echo_credits;   
	int oplock_credits;   
	bool echoes:1;  
	__u8 client_guid[SMB2_CLIENT_GUID_SIZE];  
#endif
	u16 dialect;  
	bool oplocks:1;  
	unsigned int maxReq;	 
	 
	unsigned int maxBuf;	 
	 
	unsigned int max_rw;	 
	 
	unsigned int capabilities;  
	int timeAdj;   
	__u64 CurrentMid;          
	char cryptkey[CIFS_CRYPTO_KEY_SIZE];  
	 
	char workstation_RFC1001_name[RFC1001_NAME_LEN_WITH_NULL];
	__u32 sequence_number;  
	struct session_key session_key;
	unsigned long lstrp;  
	struct cifs_secmech secmech;  
#define	CIFS_NEGFLAVOR_LANMAN	0	 
#define	CIFS_NEGFLAVOR_UNENCAP	1	 
#define	CIFS_NEGFLAVOR_EXTENDED	2	 
	char	negflavor;	 
	 
	bool	sec_ntlmssp;		 
	bool	sec_kerberosu2u;	 
	bool	sec_kerberos;		 
	bool	sec_mskerberos;		 
	bool	large_buf;		 
	struct delayed_work	echo;  
	struct kvec *iov;	 
	unsigned int nr_iov;	 
	char	*smallbuf;	 
	char	*bigbuf;	 
	unsigned int total_read;  
#ifdef CONFIG_CIFS_FSCACHE
	struct fscache_cookie   *fscache;  
#endif
#ifdef CONFIG_CIFS_STATS2
	atomic_t in_send;  
	atomic_t num_waiters;    
#endif
#ifdef CONFIG_CIFS_SMB2
	unsigned int	max_read;
	unsigned int	max_write;
	struct delayed_work reconnect;  
	struct mutex reconnect_mutex;  
#endif  
};

static inline unsigned int
in_flight(struct TCP_Server_Info *server)
{
	unsigned int num;
	spin_lock(&server->req_lock);
	num = server->in_flight;
	spin_unlock(&server->req_lock);
	return num;
}

static inline bool
has_credits(struct TCP_Server_Info *server, int *credits)
{
	int num;
	spin_lock(&server->req_lock);
	num = *credits;
	spin_unlock(&server->req_lock);
	return num > 0;
}

static inline void
add_credits(struct TCP_Server_Info *server, const unsigned int add,
	    const int optype)
{
	server->ops->add_credits(server, add, optype);
}

static inline void
add_credits_and_wake_if(struct TCP_Server_Info *server, const unsigned int add,
			const int optype)
{
	if (add) {
		server->ops->add_credits(server, add, optype);
		wake_up(&server->request_q);
	}
}

static inline void
set_credits(struct TCP_Server_Info *server, const int val)
{
	server->ops->set_credits(server, val);
}

static inline __le64
get_next_mid64(struct TCP_Server_Info *server)
{
	return cpu_to_le64(server->ops->get_next_mid(server));
}

static inline __le16
get_next_mid(struct TCP_Server_Info *server)
{
	__u16 mid = server->ops->get_next_mid(server);
	 
	return cpu_to_le16(mid);
}

static inline __u16
get_mid(const struct smb_hdr *smb)
{
	return le16_to_cpu(smb->Mid);
}

static inline bool
compare_mid(__u16 mid, const struct smb_hdr *smb)
{
	return mid == le16_to_cpu(smb->Mid);
}

#define CIFS_MAX_WSIZE ((1<<24) - 1 - sizeof(WRITE_REQ) + 4)
#define CIFS_MAX_RSIZE ((1<<24) - sizeof(READ_RSP) + 4)

#define CIFS_MAX_RFC1002_WSIZE ((1<<17) - 1 - sizeof(WRITE_REQ) + 4)
#define CIFS_MAX_RFC1002_RSIZE ((1<<17) - 1 - sizeof(READ_RSP) + 4)

#define CIFS_DEFAULT_IOSIZE (1024 * 1024)

#define CIFS_DEFAULT_NON_POSIX_RSIZE (60 * 1024)
#define CIFS_DEFAULT_NON_POSIX_WSIZE (65536)

#ifdef CONFIG_NET_NS

static inline struct net *cifs_net_ns(struct TCP_Server_Info *srv)
{
	return srv->net;
}

static inline void cifs_set_net_ns(struct TCP_Server_Info *srv, struct net *net)
{
	srv->net = net;
}

#else

static inline struct net *cifs_net_ns(struct TCP_Server_Info *srv)
{
	return &init_net;
}

static inline void cifs_set_net_ns(struct TCP_Server_Info *srv, struct net *net)
{
}

#endif

struct cifs_ses {
	struct list_head smb_ses_list;
	struct list_head tcon_list;
	struct mutex session_mutex;
	struct TCP_Server_Info *server;	 
	int ses_count;		 
	enum statusEnum status;
	unsigned overrideSecFlg;   
	__u16 ipc_tid;		 
	char *serverOS;		 
	char *serverNOS;	 
	char *serverDomain;	 
	__u64 Suid;		 
	kuid_t linux_uid;	 
	kuid_t cred_uid;	 
	unsigned int capabilities;
	char serverName[SERVER_NAME_LEN_WITH_NULL * 2];	 
	char *user_name;	 
	char *domainName;
	char *password;
	struct session_key auth_key;
	struct ntlmssp_auth *ntlmssp;  
	enum securityEnum sectype;  
	bool sign;		 
	bool need_reconnect:1;  
#ifdef CONFIG_CIFS_SMB2
	__u16 session_flags;
	char smb3signingkey[SMB3_SIGN_KEY_SIZE];  
#endif  
};

static inline bool
cap_unix(struct cifs_ses *ses)
{
	return ses->server->vals->cap_unix & ses->capabilities;
}

struct cifs_tcon {
	struct list_head tcon_list;
	int tc_count;
	struct list_head rlist;  
	struct list_head openFileList;
	spinlock_t open_file_lock;  
	struct cifs_ses *ses;	 
	char treeName[MAX_TREE_SIZE + 1];  
	char *nativeFileSystem;
	char *password;		 
	__u32 tid;		 
	__u16 Flags;		 
	enum statusEnum tidStatus;
#ifdef CONFIG_CIFS_STATS
	atomic_t num_smbs_sent;
	union {
		struct {
			atomic_t num_writes;
			atomic_t num_reads;
			atomic_t num_flushes;
			atomic_t num_oplock_brks;
			atomic_t num_opens;
			atomic_t num_closes;
			atomic_t num_deletes;
			atomic_t num_mkdirs;
			atomic_t num_posixopens;
			atomic_t num_posixmkdirs;
			atomic_t num_rmdirs;
			atomic_t num_renames;
			atomic_t num_t2renames;
			atomic_t num_ffirst;
			atomic_t num_fnext;
			atomic_t num_fclose;
			atomic_t num_hardlinks;
			atomic_t num_symlinks;
			atomic_t num_locks;
			atomic_t num_acl_get;
			atomic_t num_acl_set;
		} cifs_stats;
#ifdef CONFIG_CIFS_SMB2
		struct {
			atomic_t smb2_com_sent[NUMBER_OF_SMB2_COMMANDS];
			atomic_t smb2_com_failed[NUMBER_OF_SMB2_COMMANDS];
		} smb2_stats;
#endif  
	} stats;
#ifdef CONFIG_CIFS_STATS2
	unsigned long long time_writes;
	unsigned long long time_reads;
	unsigned long long time_opens;
	unsigned long long time_deletes;
	unsigned long long time_closes;
	unsigned long long time_mkdirs;
	unsigned long long time_rmdirs;
	unsigned long long time_renames;
	unsigned long long time_t2renames;
	unsigned long long time_ffirst;
	unsigned long long time_fnext;
	unsigned long long time_fclose;
#endif  
	__u64    bytes_read;
	__u64    bytes_written;
	spinlock_t stat_lock;   
#endif  
	FILE_SYSTEM_DEVICE_INFO fsDevInfo;
	FILE_SYSTEM_ATTRIBUTE_INFO fsAttrInfo;  
	FILE_SYSTEM_UNIX_INFO fsUnixInfo;
	bool ipc:1;		 
	bool retry:1;
	bool nocase:1;
	bool seal:1;       
	bool unix_ext:1;   
	bool local_lease:1;  
	bool broken_posix_open;  
	bool broken_sparse_sup;  
	bool need_reconnect:1;  
	bool use_resilient:1;  
	bool use_persistent:1;  
#ifdef CONFIG_CIFS_SMB2
	bool print:1;		 
	bool bad_network_name:1;  
	__le32 capabilities;
	__u32 share_flags;
	__u32 maximal_access;
	__u32 vol_serial_number;
	__le64 vol_create_time;
	__u32 ss_flags;		 
	__u32 perf_sector_size;  
	__u32 max_chunks;
	__u32 max_bytes_chunk;
	__u32 max_bytes_copy;
#endif  
#ifdef CONFIG_CIFS_FSCACHE
	u64 resource_id;		 
	struct fscache_cookie *fscache;	 
#endif
	struct list_head pending_opens;	 
	 
};

struct tcon_link {
	struct rb_node		tl_rbnode;
	kuid_t			tl_uid;
	unsigned long		tl_flags;
#define TCON_LINK_MASTER	0
#define TCON_LINK_PENDING	1
#define TCON_LINK_IN_TREE	2
	unsigned long		tl_time;
	atomic_t		tl_count;
	struct cifs_tcon	*tl_tcon;
};

extern struct tcon_link *cifs_sb_tlink(struct cifs_sb_info *cifs_sb);

static inline struct cifs_tcon *
tlink_tcon(struct tcon_link *tlink)
{
	return tlink->tl_tcon;
}

extern void cifs_put_tlink(struct tcon_link *tlink);

static inline struct tcon_link *
cifs_get_tlink(struct tcon_link *tlink)
{
	if (tlink && !IS_ERR(tlink))
		atomic_inc(&tlink->tl_count);
	return tlink;
}

extern struct cifs_tcon *cifs_sb_master_tcon(struct cifs_sb_info *cifs_sb);

#define CIFS_OPLOCK_NO_CHANGE 0xfe

struct cifs_pending_open {
	struct list_head olist;
	struct tcon_link *tlink;
	__u8 lease_key[16];
	__u32 oplock;
};

struct cifsLockInfo {
	struct list_head llist;	 
	struct list_head blist;  
	wait_queue_head_t block_q;
	__u64 offset;
	__u64 length;
	__u32 pid;
	__u32 type;
};

struct cifs_search_info {
	loff_t index_of_last_entry;
	__u16 entries_in_buffer;
	__u16 info_level;
	__u32 resume_key;
	char *ntwrk_buf_start;
	char *srch_entries_start;
	char *last_entry;
	const char *presume_name;
	unsigned int resume_name_len;
	bool endOfSearch:1;
	bool emptyDir:1;
	bool unicode:1;
	bool smallBuf:1;  
};

struct cifs_open_parms {
	struct cifs_tcon *tcon;
	struct cifs_sb_info *cifs_sb;
	int disposition;
	int desired_access;
	int create_options;
	const char *path;
	struct cifs_fid *fid;
	bool reconnect:1;
};

struct cifs_fid {
	__u16 netfid;
#ifdef CONFIG_CIFS_SMB2
	__u64 persistent_fid;	 
	__u64 volatile_fid;	 
	__u8 lease_key[SMB2_LEASE_KEY_SIZE];	 
	__u8 create_guid[16];
#endif
	struct cifs_pending_open *pending_open;
	unsigned int epoch;
	bool purge_cache;
};

struct cifs_fid_locks {
	struct list_head llist;
	struct cifsFileInfo *cfile;	 
	struct list_head locks;		 
};

struct cifsFileInfo {
	 
	struct list_head tlist;	 
	struct list_head flist;	 
	 
	struct cifs_fid_locks *llist;	 
	kuid_t uid;		 
	__u32 pid;		 
	struct cifs_fid fid;	 
	  ;
	 
	struct dentry *dentry;
	struct tcon_link *tlink;
	unsigned int f_flags;
	bool invalidHandle:1;	 
	bool oplock_break_cancelled:1;
	int count;
	spinlock_t file_info_lock;  
	struct mutex fh_mutex;  
	struct cifs_search_info srch_inf;
	struct work_struct oplock_break;  
};

struct cifs_io_parms {
	__u16 netfid;
#ifdef CONFIG_CIFS_SMB2
	__u64 persistent_fid;	 
	__u64 volatile_fid;	 
#endif
	__u32 pid;
	__u64 offset;
	unsigned int length;
	struct cifs_tcon *tcon;
};

struct cifs_readdata;

struct cifs_readdata {
	struct kref			refcount;
	struct list_head		list;
	struct completion		done;
	struct cifsFileInfo		*cfile;
	struct address_space		*mapping;
	__u64				offset;
	unsigned int			bytes;
	unsigned int			got_bytes;
	pid_t				pid;
	int				result;
	struct work_struct		work;
	int (*read_into_pages)(struct TCP_Server_Info *server,
				struct cifs_readdata *rdata,
				unsigned int len);
	struct kvec			iov;
	unsigned int			pagesz;
	unsigned int			tailsz;
	unsigned int			credits;
	unsigned int			nr_pages;
	struct page			*pages[];
};

struct cifs_writedata;

struct cifs_writedata {
	struct kref			refcount;
	struct list_head		list;
	struct completion		done;
	enum writeback_sync_modes	sync_mode;
	struct work_struct		work;
	struct cifsFileInfo		*cfile;
	__u64				offset;
	pid_t				pid;
	unsigned int			bytes;
	int				result;
	unsigned int			pagesz;
	unsigned int			tailsz;
	unsigned int			credits;
	unsigned int			nr_pages;
	struct page			*pages[];
};

static inline void
cifsFileInfo_get_locked(struct cifsFileInfo *cifs_file)
{
	++cifs_file->count;
}

struct cifsFileInfo *cifsFileInfo_get(struct cifsFileInfo *cifs_file);
void cifsFileInfo_put(struct cifsFileInfo *cifs_file);

#define CIFS_CACHE_READ_FLG	1
#define CIFS_CACHE_HANDLE_FLG	2
#define CIFS_CACHE_RH_FLG	(CIFS_CACHE_READ_FLG | CIFS_CACHE_HANDLE_FLG)
#define CIFS_CACHE_WRITE_FLG	4
#define CIFS_CACHE_RW_FLG	(CIFS_CACHE_READ_FLG | CIFS_CACHE_WRITE_FLG)
#define CIFS_CACHE_RHW_FLG	(CIFS_CACHE_RW_FLG | CIFS_CACHE_HANDLE_FLG)

#define CIFS_CACHE_READ(cinode) (cinode->oplock & CIFS_CACHE_READ_FLG)
#define CIFS_CACHE_HANDLE(cinode) (cinode->oplock & CIFS_CACHE_HANDLE_FLG)
#define CIFS_CACHE_WRITE(cinode) (cinode->oplock & CIFS_CACHE_WRITE_FLG)

struct cifsInodeInfo {
	bool can_cache_brlcks;
	struct list_head llist;	 
	struct rw_semaphore lock_sem;	 
	 
	struct list_head openFileList;
	__u32 cifsAttrs;  
	unsigned int oplock;		 
	unsigned int epoch;		 
#define CIFS_INODE_PENDING_OPLOCK_BREAK   (0)  
#define CIFS_INODE_PENDING_WRITERS	  (1)  
#define CIFS_INODE_DOWNGRADE_OPLOCK_TO_L2 (2)  
#define CIFS_INO_DELETE_PENDING		  (3)  
#define CIFS_INO_INVALID_MAPPING	  (4)  
#define CIFS_INO_LOCK			  (5)  
	unsigned long flags;
	spinlock_t writers_lock;
	unsigned int writers;		 
	unsigned long time;		 
	u64  server_eof;		 
	u64  uniqueid;			 
	u64  createtime;		 
#ifdef CONFIG_CIFS_SMB2
	__u8 lease_key[SMB2_LEASE_KEY_SIZE];	 
#endif
#ifdef CONFIG_CIFS_FSCACHE
	struct fscache_cookie *fscache;
#endif
	struct inode vfs_inode;
};

static inline struct cifsInodeInfo *
CIFS_I(struct inode *inode)
{
	return container_of(inode, struct cifsInodeInfo, vfs_inode);
}

static inline struct cifs_sb_info *
CIFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct cifs_sb_info *
CIFS_FILE_SB(struct file *file)
{
	return CIFS_SB(file_inode(file)->i_sb);
}

static inline char CIFS_DIR_SEP(const struct cifs_sb_info *cifs_sb)
{
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_POSIX_PATHS)
		return '/';
	else
		return '\\';
}

static inline void
convert_delimiter(char *path, char delim)
{
	char old_delim, *pos;

	if (delim == '/')
		old_delim = '\\';
	else
		old_delim = '/';

	pos = path;
	while ((pos = strchr(pos, old_delim)))
		*pos = delim;
}

#ifdef CONFIG_CIFS_STATS
#define cifs_stats_inc atomic_inc

static inline void cifs_stats_bytes_written(struct cifs_tcon *tcon,
					    unsigned int bytes)
{
	if (bytes) {
		spin_lock(&tcon->stat_lock);
		tcon->bytes_written += bytes;
		spin_unlock(&tcon->stat_lock);
	}
}

static inline void cifs_stats_bytes_read(struct cifs_tcon *tcon,
					 unsigned int bytes)
{
	spin_lock(&tcon->stat_lock);
	tcon->bytes_read += bytes;
	spin_unlock(&tcon->stat_lock);
}
#else

#define  cifs_stats_inc(field) do {} while (0)
#define  cifs_stats_bytes_written(tcon, bytes) do {} while (0)
#define  cifs_stats_bytes_read(tcon, bytes) do {} while (0)

#endif

typedef int (mid_receive_t)(struct TCP_Server_Info *server,
			    struct mid_q_entry *mid);

typedef void (mid_callback_t)(struct mid_q_entry *mid);

struct mid_q_entry {
	struct list_head qhead;	 
	struct TCP_Server_Info *server;	 
	__u64 mid;		 
	__u32 pid;		 
	__u32 sequence_number;   
	unsigned long when_alloc;   
#ifdef CONFIG_CIFS_STATS2
	unsigned long when_sent;  
	unsigned long when_received;  
#endif
	mid_receive_t *receive;  
	mid_callback_t *callback;  
	void *callback_data;	   
	void *resp_buf;		 
	int mid_state;	 
	__le16 command;		 
	bool large_buf:1;	 
	bool multiRsp:1;	 
	bool multiEnd:1;	 
};

#ifdef CONFIG_CIFS_STATS2

static inline void cifs_in_send_inc(struct TCP_Server_Info *server)
{
	atomic_inc(&server->in_send);
}

static inline void cifs_in_send_dec(struct TCP_Server_Info *server)
{
	atomic_dec(&server->in_send);
}

static inline void cifs_num_waiters_inc(struct TCP_Server_Info *server)
{
	atomic_inc(&server->num_waiters);
}

static inline void cifs_num_waiters_dec(struct TCP_Server_Info *server)
{
	atomic_dec(&server->num_waiters);
}

static inline void cifs_save_when_sent(struct mid_q_entry *mid)
{
	mid->when_sent = jiffies;
}
#else
static inline void cifs_in_send_inc(struct TCP_Server_Info *server)
{
}
static inline void cifs_in_send_dec(struct TCP_Server_Info *server)
{
}

static inline void cifs_num_waiters_inc(struct TCP_Server_Info *server)
{
}

static inline void cifs_num_waiters_dec(struct TCP_Server_Info *server)
{
}

static inline void cifs_save_when_sent(struct mid_q_entry *mid)
{
}
#endif

struct dir_notify_req {
	struct list_head lhead;
	__le16 Pid;
	__le16 PidHigh;
	__u16 Mid;
	__u16 Tid;
	__u16 Uid;
	__u16 netfid;
	__u32 filter;  
	int multishot;
	struct file *pfile;
};

struct dfs_info3_param {
	int flags;  
	int path_consumed;
	int server_type;
	int ref_flag;
	char *path_name;
	char *node_name;
};

#define CIFS_FATTR_DFS_REFERRAL		0x1
#define CIFS_FATTR_DELETE_PENDING	0x2
#define CIFS_FATTR_NEED_REVAL		0x4
#define CIFS_FATTR_INO_COLLISION	0x8
#define CIFS_FATTR_UNKNOWN_NLINK	0x10

struct cifs_fattr {
	u32		cf_flags;
	u32		cf_cifsattrs;
	u64		cf_uniqueid;
	u64		cf_eof;
	u64		cf_bytes;
	u64		cf_createtime;
	kuid_t		cf_uid;
	kgid_t		cf_gid;
	umode_t		cf_mode;
	dev_t		cf_rdev;
	unsigned int	cf_nlink;
	unsigned int	cf_dtype;
	struct timespec	cf_atime;
	struct timespec	cf_mtime;
	struct timespec	cf_ctime;
};

static inline void free_dfs_info_param(struct dfs_info3_param *param)
{
	if (param) {
		kfree(param->path_name);
		kfree(param->node_name);
		kfree(param);
	}
}

static inline void free_dfs_info_array(struct dfs_info3_param *param,
				       int number_of_items)
{
	int i;
	if ((number_of_items == 0) || (param == NULL))
		return;
	for (i = 0; i < number_of_items; i++) {
		kfree(param[i].path_name);
		kfree(param[i].node_name);
	}
	kfree(param);
}

#define   MID_FREE 0
#define   MID_REQUEST_ALLOCATED 1
#define   MID_REQUEST_SUBMITTED 2
#define   MID_RESPONSE_RECEIVED 4
#define   MID_RETRY_NEEDED      8  
#define   MID_RESPONSE_MALFORMED 0x10
#define   MID_SHUTDOWN		 0x20

#define   CIFS_NO_BUFFER        0     
#define   CIFS_SMALL_BUFFER     1
#define   CIFS_LARGE_BUFFER     2
#define   CIFS_IOVEC            4     

#define   CIFS_BLOCKING_OP      1     
#define   CIFS_ASYNC_OP         2     
#define   CIFS_TIMEOUT_MASK 0x003     
#define   CIFS_LOG_ERROR    0x010     
#define   CIFS_LARGE_BUF_OP 0x020     
#define   CIFS_NO_RESP      0x040     

#define   CIFS_ECHO_OP      0x080     
#define   CIFS_OBREAK_OP   0x0100     
#define   CIFS_NEG_OP      0x0200     
#define   CIFS_OP_MASK     0x0380     
#define   CIFS_HAS_CREDITS 0x0400     

#define   CIFSSEC_MAY_SIGN	0x00001
#define   CIFSSEC_MAY_NTLM	0x00002
#define   CIFSSEC_MAY_NTLMV2	0x00004
#define   CIFSSEC_MAY_KRB5	0x00008
#ifdef CONFIG_CIFS_WEAK_PW_HASH
#define   CIFSSEC_MAY_LANMAN	0x00010
#define   CIFSSEC_MAY_PLNTXT	0x00020
#else
#define   CIFSSEC_MAY_LANMAN    0
#define   CIFSSEC_MAY_PLNTXT    0
#endif  
#define   CIFSSEC_MAY_SEAL	0x00040  
#define   CIFSSEC_MAY_NTLMSSP	0x00080  

#define   CIFSSEC_MUST_SIGN	0x01001
 
#define   CIFSSEC_MUST_NTLM	0x02002
#define   CIFSSEC_MUST_NTLMV2	0x04004
#define   CIFSSEC_MUST_KRB5	0x08008
#ifdef CONFIG_CIFS_WEAK_PW_HASH
#define   CIFSSEC_MUST_LANMAN	0x10010
#define   CIFSSEC_MUST_PLNTXT	0x20020
#ifdef CONFIG_CIFS_UPCALL
#define   CIFSSEC_MASK          0xBF0BF  
#else
#define   CIFSSEC_MASK          0xB70B7  
#endif  
#else  
#define   CIFSSEC_MUST_LANMAN	0
#define   CIFSSEC_MUST_PLNTXT	0
#ifdef CONFIG_CIFS_UPCALL
#define   CIFSSEC_MASK          0x8F08F  
#else
#define	  CIFSSEC_MASK          0x87087  
#endif  
#endif  
#define   CIFSSEC_MUST_SEAL	0x40040  
#define   CIFSSEC_MUST_NTLMSSP	0x80080  

#define   CIFSSEC_DEF (CIFSSEC_MAY_SIGN | CIFSSEC_MAY_NTLMV2 | CIFSSEC_MAY_NTLMSSP)
#define   CIFSSEC_MAX (CIFSSEC_MUST_SIGN | CIFSSEC_MUST_NTLMV2)
#define   CIFSSEC_AUTH_MASK (CIFSSEC_MAY_NTLM | CIFSSEC_MAY_NTLMV2 | CIFSSEC_MAY_LANMAN | CIFSSEC_MAY_PLNTXT | CIFSSEC_MAY_KRB5 | CIFSSEC_MAY_NTLMSSP)
 
#define UID_HASH (16)

#ifdef DECLARE_GLOBALS_HERE
#define GLOBAL_EXTERN
#else
#define GLOBAL_EXTERN extern
#endif

GLOBAL_EXTERN struct list_head		cifs_tcp_ses_list;

GLOBAL_EXTERN spinlock_t		cifs_tcp_ses_lock;

#ifdef CONFIG_CIFS_DNOTIFY_EXPERIMENTAL  
 
GLOBAL_EXTERN struct list_head GlobalDnotifyReqList;
 
GLOBAL_EXTERN struct list_head GlobalDnotifyRsp_Q;
#endif  

GLOBAL_EXTERN unsigned int GlobalCurrentXid;	 
GLOBAL_EXTERN unsigned int GlobalTotalActiveXid;  
GLOBAL_EXTERN unsigned int GlobalMaxActiveXid;	 
GLOBAL_EXTERN spinlock_t GlobalMid_Lock;   
					   
GLOBAL_EXTERN atomic_t sesInfoAllocCount;
GLOBAL_EXTERN atomic_t tconInfoAllocCount;
GLOBAL_EXTERN atomic_t tcpSesAllocCount;
GLOBAL_EXTERN atomic_t tcpSesReconnectCount;
GLOBAL_EXTERN atomic_t tconInfoReconnectCount;

GLOBAL_EXTERN atomic_t bufAllocCount;     
#ifdef CONFIG_CIFS_STATS2
GLOBAL_EXTERN atomic_t totBufAllocCount;  
GLOBAL_EXTERN atomic_t totSmBufAllocCount;
#endif
GLOBAL_EXTERN atomic_t smBufAllocCount;
GLOBAL_EXTERN atomic_t midCount;

GLOBAL_EXTERN bool enable_oplocks;  
GLOBAL_EXTERN bool lookupCacheEnabled;
GLOBAL_EXTERN unsigned int global_secflags;	 
GLOBAL_EXTERN unsigned int sign_CIFS_PDUs;   
#ifdef MY_ABC_HERE
GLOBAL_EXTERN unsigned int SynoPosixSemanticsEnabled; 
#endif  
GLOBAL_EXTERN bool linuxExtEnabled; 
GLOBAL_EXTERN unsigned int CIFSMaxBufSize;   
GLOBAL_EXTERN unsigned int cifs_min_rcv;     
GLOBAL_EXTERN unsigned int cifs_min_small;   
GLOBAL_EXTERN unsigned int cifs_max_pending;  

GLOBAL_EXTERN unsigned short echo_retries;

#ifdef CONFIG_CIFS_ACL
GLOBAL_EXTERN struct rb_root uidtree;
GLOBAL_EXTERN struct rb_root gidtree;
GLOBAL_EXTERN spinlock_t siduidlock;
GLOBAL_EXTERN spinlock_t sidgidlock;
GLOBAL_EXTERN struct rb_root siduidtree;
GLOBAL_EXTERN struct rb_root sidgidtree;
GLOBAL_EXTERN spinlock_t uidsidlock;
GLOBAL_EXTERN spinlock_t gidsidlock;
#endif  

void cifs_oplock_break(struct work_struct *work);

extern const struct slow_work_ops cifs_oplock_break_ops;
extern struct workqueue_struct *cifsiod_wq;

extern mempool_t *cifs_mid_poolp;

#define SMB1_VERSION_STRING	"1.0"
extern struct smb_version_operations smb1_operations;
extern struct smb_version_values smb1_values;
#ifdef MY_ABC_HERE
#define SYNO_VERSION_STRING	"syno"
extern struct smb_version_operations synocifs_operations;
extern struct smb_version_values synocifs_values;
#endif  
#define SMB20_VERSION_STRING	"2.0"
extern struct smb_version_operations smb20_operations;
extern struct smb_version_values smb20_values;
#define SMB21_VERSION_STRING	"2.1"
extern struct smb_version_operations smb21_operations;
extern struct smb_version_values smb21_values;
#define SMB30_VERSION_STRING	"3.0"
extern struct smb_version_operations smb30_operations;
extern struct smb_version_values smb30_values;
#define SMB302_VERSION_STRING	"3.02"
   
extern struct smb_version_values smb302_values;
#define SMB311_VERSION_STRING	"3.1.1"
#define ALT_SMB311_VERSION_STRING "3.11"
extern struct smb_version_operations smb311_operations;
extern struct smb_version_values smb311_values;
#endif	 
