#include <linux/pagemap.h>
#include <linux/vfs.h>
#include <linux/falloc.h>
#include "cifsglob.h"
#include "smb2pdu.h"
#include "smb2proto.h"
#include "cifsproto.h"
#include "cifs_debug.h"
#include "cifs_unicode.h"
#include "smb2status.h"
#include "smb2glob.h"

static struct {
	char *name;
} smb1_dialects_array[] = {
	{"\2NT LM 0.12"},
	{"\2Synology"},
	{"\2SMB 2.002"},
	{"\2SMB 2.???"},
	{NULL}
};
static __u16 smb2_dialects_array[] = {
	SMB20_PROT_ID,
	SMB21_PROT_ID,
#ifdef CONFIG_CRYPTO_CMAC
	/**
	 *  SMB3 or above need cmac.ko to do smb signing
	 *  If CMAC not enable, the SMB3 will fail when packets need signing.
	 *  So we need to disable it
	 */ 
	SMB30_PROT_ID,
	SMB302_PROT_ID,
#endif /* CONFIG_CRYPTO_CMAC */
	BAD_PROT_ID
};

#define SYNOWRAP0_SERVER_SMB20(rtype, function) \
	static rtype syno_##function(struct TCP_Server_Info *server) {\
		if (SMB20_PROT_ID > server->dialect) {\
			return smb1_operations.function(server);\
		}\
		return smb20_operations.function(server);\
	}

#define SYNOWRAP1_SERVER_SMB20(rtype, function, type, arg) \
	static rtype syno_##function(struct TCP_Server_Info *server, type arg) {\
		if (SMB20_PROT_ID > server->dialect) {\
			return smb1_operations.function(server, arg);\
		}\
		return smb20_operations.function(server, arg);\
	}

#define SYNOWRAP_SES_SMB20(rtype, function, type, arg) \
	static rtype syno_##function(struct cifs_ses *ses, type arg) {\
		if (ses && ses->server && SMB20_PROT_ID > ses->server->dialect) {\
			return smb1_operations.function(ses, arg);\
		}\
		return smb20_operations.function(ses, arg);\
	}

#define SYNOWRAP0_BUF_SMB20(rtype, function, btype) \
	static rtype syno_##function(btype buf) {\
		__u8 *ubuf = (__u8 *) buf;\
		if (0xFF == ubuf[4]) {\
			return smb1_operations.function(buf);\
		}\
		return smb20_operations.function(buf);\
	}
#define SYNOWRAP1_BUF_SMB20(rtype, function, type, arg) \
	static rtype syno_##function(char *buf, type arg) {\
		if (0xFF == (__u8)buf[4]) {\
			return smb1_operations.function(buf, arg);\
		}\
		return smb20_operations.function(buf, arg);\
	}

//	int (*send_cancel)(struct TCP_Server_Info *, void *,  struct mid_q_entry *);
static int
syno_send_cancel(struct TCP_Server_Info *server, void *buf,
	       struct mid_q_entry *mid)
{
	//The function is called by transport.c and SMB1 only.
	//If the function is not support, return 0
	if (SMB20_PROT_ID > server->dialect) {
		return smb1_operations.send_cancel(server, buf, mid);
	}
	return 0;
}

//	bool (*compare_fids)(struct cifsFileInfo *, struct cifsFileInfo *);
static bool
syno_compare_fids(struct cifsFileInfo *ob1, struct cifsFileInfo *ob2)
{
	return (ob1->fid.netfid == ob2->fid.netfid &&
		ob1->fid.persistent_fid == ob2->fid.persistent_fid &&
		ob1->fid.volatile_fid == ob2->fid.volatile_fid);
}

//	struct mid_q_entry *(*setup_request)(struct cifs_ses *, struct smb_rqst *);
SYNOWRAP_SES_SMB20(struct mid_q_entry *, setup_request, struct smb_rqst *, rqst)

//	struct mid_q_entry *(*setup_async_request)(struct TCP_Server_Info *, struct smb_rqst *);
SYNOWRAP1_SERVER_SMB20(struct mid_q_entry *, setup_async_request, struct smb_rqst *, rqst)

//	int (*check_receive)(struct mid_q_entry *, struct TCP_Server_Info *, bool);
static int
syno_check_receive(struct mid_q_entry *mid, struct TCP_Server_Info *server,
		   bool log_error)
{
	if (SMB20_PROT_ID > server->dialect) {
		return smb1_operations.check_receive(mid, server, log_error);
	}
	return smb20_operations.check_receive(mid, server, log_error);
}

//	void (*add_credits)(struct TCP_Server_Info *, const unsigned int, const int);
static void
syno_add_credits(struct TCP_Server_Info *server, const unsigned int add,
		 const int optype)
{
	if (SMB20_PROT_ID > server->dialect) {
		return smb1_operations.add_credits(server, add, optype);
	}
	return smb20_operations.add_credits(server, add, optype);
}

//	void (*set_credits)(struct TCP_Server_Info *, const int);
static void syno_set_credits(struct TCP_Server_Info *server, const int val) {
	if (SMB20_PROT_ID > server->dialect) {
		smb1_operations.set_credits(server, val);
		return;
	}
	smb20_operations.set_credits(server, val);
}

//	int * (*get_credits_field)(struct TCP_Server_Info *, const int);
SYNOWRAP1_SERVER_SMB20(int *, get_credits_field, const int, optype)

//	unsigned int (*get_credits)(struct mid_q_entry *);
static unsigned int
syno_get_credits(struct mid_q_entry *mid)
{
	if (mid->server && SMB20_PROT_ID > mid->server->dialect) {
		return smb1_operations.get_credits(mid);
	}
	return smb20_operations.get_credits(mid);
}

//	__u64 (*get_next_mid)(struct TCP_Server_Info *);
/**
 * This method smb1_operations and smb20_operations have different logic.
 * because the smb1 mid is only 16 bits. smb2 mid is 64 bits.
 * And smb1 negotiate can start with any mid.
 * smb2 negotiate must start with mid=0.
 * (Even if we start with 1, the server also reply 0)
 *
 * The origin implement:
 *   smb1 implement is silmilar to return ++CurrentMid
 *   smb2 return CurrentMid++
 *
 * So align the implement behavior for syno ops
 *
 */
static __u64
smb1_get_next_mid(struct TCP_Server_Info *server)
{
	__u64 mid = 0;
	__u16 last_mid, cur_mid;
	bool collision;

	spin_lock(&GlobalMid_Lock);

	/* mid is 16 bit only for CIFS/SMB */
	cur_mid = (__u16)((server->CurrentMid) & 0xffff);
	/* we do not want to loop forever */
	last_mid = cur_mid;

	/*
	 * This nested loop looks more expensive than it is.
	 * In practice the list of pending requests is short,
	 * fewer than 50, and the mids are likely to be unique
	 * on the first pass through the loop unless some request
	 * takes longer than the 64 thousand requests before it
	 * (and it would also have to have been a request that
	 * did not time out).
	 */
	do {
		struct mid_q_entry *mid_entry;
		unsigned int num_mids;

		collision = false;

		num_mids = 0;
		list_for_each_entry(mid_entry, &server->pending_mid_q, qhead) {
			++num_mids;
			if (mid_entry->mid == cur_mid &&
			    mid_entry->mid_state == MID_REQUEST_SUBMITTED) {
				/* This mid is in use, try a different one */
				collision = true;
				break;
			}
		}

		/*
		 * if we have more than 32k mids in the list, then something
		 * is very wrong. Possibly a local user is trying to DoS the
		 * box by issuing long-running calls and SIGKILL'ing them. If
		 * we get to 2^16 mids then we're in big trouble as this
		 * function could loop forever.
		 *
		 * Go ahead and assign out the mid in this situation, but force
		 * an eventual reconnect to clean out the pending_mid_q.
		 */
		if (num_mids > 32768)
			server->tcpStatus = CifsNeedReconnect;

		if (!collision) {
			mid = (__u64)cur_mid;
			server->CurrentMid = mid + 1;
			break;
		}
		cur_mid++;
	} while (cur_mid != last_mid);
	spin_unlock(&GlobalMid_Lock);
	return mid;
}
static __u64
syno_get_next_mid(struct TCP_Server_Info *server)
{
	if (SMB20_PROT_ID > server->dialect) {
		return smb1_get_next_mid(server);
	}
	return smb20_operations.get_next_mid(server);
}

//	unsigned int (*read_data_offset)(char *);
SYNOWRAP0_BUF_SMB20(unsigned int, read_data_offset, char *)

//	unsigned int (*read_data_length)(char *);
SYNOWRAP0_BUF_SMB20(unsigned int, read_data_length, char *)

//	int (*map_error)(char *, bool);
SYNOWRAP1_BUF_SMB20(int, map_error, bool, log_err)

//	struct mid_q_entry * (*find_mid)(struct TCP_Server_Info *, char *);
struct mid_q_entry *
syno_find_mid(struct TCP_Server_Info *server, char *buf)
{
	struct mid_q_entry *mid;
	struct smb2_hdr *hdr = (struct smb2_hdr *)buf;
	__u64 wire_mid = le64_to_cpu(hdr->MessageId);

	if (0xFF == (__u8)buf[4]) {
		return smb1_operations.find_mid(server, buf);
	}

	spin_lock(&GlobalMid_Lock);
	// smb2 part
	list_for_each_entry(mid, &server->pending_mid_q, qhead) {
		if ((mid->mid == wire_mid) &&
		    (mid->mid_state == MID_REQUEST_SUBMITTED) &&
		    (mid->command == hdr->Command ||
		     //negotiate rqst might be come from SMB1
		     (mid->command == 0x72 && hdr->Command == 0)))
		{
			spin_unlock(&GlobalMid_Lock);
			return mid;
		}
	}
	spin_unlock(&GlobalMid_Lock);
	return NULL;
}

//	void (*dump_detail)(void *);
static void syno_dump_detail(void *buf)
{
	__u8 *ubuf = (__u8 *) buf;
	if (0xFF == ubuf[4]) {
		smb1_operations.dump_detail(buf);
		return;
	}
	smb20_operations.dump_detail(buf);
}

//	void (*clear_stats)(struct cifs_tcon *);
static void
syno_clear_stats(struct cifs_tcon *tcon)
{
	smb1_operations.clear_stats(tcon);
	smb20_operations.clear_stats(tcon);
}

//	void (*print_stats)(struct seq_file *m, struct cifs_tcon *);
static void
syno_print_stats(struct seq_file *m, struct cifs_tcon *tcon)
{
	smb1_operations.print_stats(m, tcon);
	smb20_operations.print_stats(m, tcon);
}

//	void (*dump_share_caps)(struct seq_file *, struct cifs_tcon *);
static void
syno_dump_share_caps(struct seq_file *m, struct cifs_tcon *tcon)
{
#ifdef CONFIG_CRYPTO_CMAC
	if (tcon && tcon->ses && tcon->ses->server && SMB30_PROT_ID <= tcon->ses->server->dialect) {
		smb30_operations.dump_share_caps(m, tcon);
	}
#endif /* CONFIG_CRYPTO_CMAC */
}

//	int (*check_message)(char *, unsigned int);
SYNOWRAP1_BUF_SMB20(int, check_message, unsigned int, length)

//	bool (*is_oplock_break)(char *, struct TCP_Server_Info *);
SYNOWRAP1_BUF_SMB20(bool, is_oplock_break, struct TCP_Server_Info *, server)

//	void (*downgrade_oplock)(struct TCP_Server_Info *, struct cifsInodeInfo *, bool);
static void
syno_downgrade_oplock(struct TCP_Server_Info *server,
			struct cifsInodeInfo *cinode, bool set_level2)
{
	if (SMB20_PROT_ID > server->dialect) {
		smb1_operations.downgrade_oplock(server, cinode, set_level2);
		return;
	}
	smb20_operations.downgrade_oplock(server, cinode, set_level2);
	return;
}

//	bool (*check_trans2)(struct mid_q_entry *, struct TCP_Server_Info *, char *, int);
static bool
syno_check_trans2(struct mid_q_entry *mid, struct TCP_Server_Info *server,
		  char *buf, int malformed)
{
	if (SMB20_PROT_ID > server->dialect) {
		return smb1_operations.check_trans2(mid, server, buf, malformed);
	}
	return false;
}

//	bool (*need_neg)(struct TCP_Server_Info *);
SYNOWRAP0_SERVER_SMB20(bool, need_neg)

//	int (*negotiate)(const unsigned int, struct cifs_ses *);
static bool
should_set_ext_sec_flag(enum securityEnum sectype)
{
	switch (sectype) {
	case RawNTLMSSP:
	case Kerberos:
		return true;
	case Unspecified:
		if (global_secflags &
		    (CIFSSEC_MAY_KRB5 | CIFSSEC_MAY_NTLMSSP))
			return true;
		/* Fallthrough */
	default:
		return false;
	}
}
static int
decode_ext_sec_blob(struct cifs_ses *ses, NEGOTIATE_RSP *pSMBr)
{
	int	rc = 0;
	u16	count;
	char	*guid = pSMBr->u.extended_response.GUID;
	struct TCP_Server_Info *server = ses->server;

	count = get_bcc(&pSMBr->hdr);
	if (count < SMB1_CLIENT_GUID_SIZE)
		return -EIO;

	spin_lock(&cifs_tcp_ses_lock);
	if (server->srv_count > 1) {
		spin_unlock(&cifs_tcp_ses_lock);
		if (memcmp(server->server_GUID, guid, SMB1_CLIENT_GUID_SIZE) != 0) {
			memcpy(server->server_GUID, guid, SMB1_CLIENT_GUID_SIZE);
		}
	} else {
		spin_unlock(&cifs_tcp_ses_lock);
		memcpy(server->server_GUID, guid, SMB1_CLIENT_GUID_SIZE);
	}

	if (count == SMB1_CLIENT_GUID_SIZE) {
		server->sec_ntlmssp = true;
	} else {
		count -= SMB1_CLIENT_GUID_SIZE;
		rc = decode_negTokenInit(
			pSMBr->u.extended_response.SecurityBlob, count, server);
		if (rc != 1)
			return -EINVAL;
	}

	return 0;
}
static int
syno_check_smb1_nego_rsp(struct cifs_ses *ses, NEGOTIATE_RSP *pSMBr)
{
	int rc = 0;
	struct TCP_Server_Info *server = ses->server;

	server->dialect = le16_to_cpu(pSMBr->DialectIndex);
	server->values = smb1_values;
	server->values.version_string = SYNO_VERSION_STRING;
	/* Check wct = 1 error case */
	if ((pSMBr->hdr.WordCount < 13) || (server->dialect == BAD_PROT)) {
		/* core returns wct = 1, but we do not ask for core - otherwise
		small wct just comes when dialect index is -1 indicating we
		could not negotiate a common dialect */
		rc = -EOPNOTSUPP;
		goto neg_err_exit;
	} else if (pSMBr->hdr.WordCount == 13) {
		server->negflavor = CIFS_NEGFLAVOR_LANMAN;
		rc = -EOPNOTSUPP;
		goto neg_err_exit;
	} else if (pSMBr->hdr.WordCount != 17) {
		/* unknown wct */
		rc = -EOPNOTSUPP;
		goto neg_err_exit;
	}
	/* else wct == 17, NTLM or better */

	server->sec_mode = pSMBr->SecurityMode;
	if ((server->sec_mode & SECMODE_USER) == 0)
		cifs_dbg(FYI, "share mode security\n");

	/* one byte, so no need to convert this or EncryptionKeyLen from
	   little endian */
	server->maxReq = min_t(unsigned int, le16_to_cpu(pSMBr->MaxMpxCount),
			       cifs_max_pending);
	set_credits(server, server->maxReq);
	/* probably no need to store and check maxvcs */
	server->maxBuf = le32_to_cpu(pSMBr->MaxBufferSize);
	server->max_rw = le32_to_cpu(pSMBr->MaxRawSize);
	cifs_dbg(NOISY, "Max buf = %d\n", ses->server->maxBuf);
	server->capabilities = le32_to_cpu(pSMBr->Capabilities);
	server->timeAdj = (int)(__s16)le16_to_cpu(pSMBr->ServerTimeZone);
	server->timeAdj *= 60;

	if (pSMBr->EncryptionKeyLength == CIFS_CRYPTO_KEY_SIZE) {
		server->negflavor = CIFS_NEGFLAVOR_UNENCAP;
		memcpy(ses->server->cryptkey, pSMBr->u.EncryptionKey,
		       CIFS_CRYPTO_KEY_SIZE);
	} else if (pSMBr->hdr.Flags2 & SMBFLG2_EXT_SEC ||
			server->capabilities & CAP_EXTENDED_SECURITY) {
		server->negflavor = CIFS_NEGFLAVOR_EXTENDED;
		rc = decode_ext_sec_blob(ses, pSMBr);
	} else if (server->sec_mode & SECMODE_PW_ENCRYPT) {
		rc = -EIO; /* no crypt key only if plain text pwd */
	} else {
		server->negflavor = CIFS_NEGFLAVOR_UNENCAP;
		server->capabilities &= ~CAP_EXTENDED_SECURITY;
	}

	if (!rc)
		rc = cifs_enable_signing(server, ses->sign);
neg_err_exit:
	return rc;
}
static int
syno_check_smb2_nego_rsp(struct cifs_ses *ses, struct smb2_negotiate_rsp *rsp)
{
	int rc = 0;
	struct TCP_Server_Info *server = ses->server;
	int blob_offset, blob_length;
	char *security_blob;

	/*
	 * No tcon so can't do
	 * cifs_stats_inc(&tcon->stats.smb2_stats.smb2_com_fail[SMB2...]);
	 */

	cifs_dbg(FYI, "mode 0x%x\n", rsp->SecurityMode);

	/* BB we may eventually want to match the negotiated vs. requested
	   dialect, even though we are only requesting one at a time */
	if (rsp->DialectRevision == cpu_to_le16(SMB20_PROT_ID)) {
		cifs_dbg(FYI, "negotiated smb2.0 dialect\n");
		server->values = smb20_values;
		server->values.version_string = SYNO_VERSION_STRING;
	} else if (rsp->DialectRevision == cpu_to_le16(SMB21_PROT_ID)) {
		cifs_dbg(FYI, "negotiated smb2.1 dialect\n");
		server->values = smb21_values;
		server->values.version_string = SYNO_VERSION_STRING;
#ifdef CONFIG_CRYPTO_CMAC
	} else if (rsp->DialectRevision == cpu_to_le16(SMB30_PROT_ID)) {
		cifs_dbg(FYI, "negotiated smb3.0 dialect\n");
		server->values = smb30_values;
		server->values.version_string = SYNO_VERSION_STRING;
	} else if (rsp->DialectRevision == cpu_to_le16(SMB302_PROT_ID)) {
		cifs_dbg(FYI, "negotiated smb3.02 dialect\n");
		server->values = smb302_values;
		server->values.version_string = SYNO_VERSION_STRING;
#endif /* CONFIG_CRYPTO_CMAC */
#if defined(CONFIG_CIFS_SMB311) && defined(CONFIG_CRYPTO_CMAC)
	} else if (rsp->DialectRevision == cpu_to_le16(SMB311_PROT_ID)) {
		cifs_dbg(FYI, "negotiated smb3.1.1 dialect\n");
		server->values = smb311_values;
		server->values.version_string = SYNO_VERSION_STRING;
#endif /* SMB311 && CONFIG_CRYPTO_CMAC */
	} else if (rsp->DialectRevision == cpu_to_le16(0x02ff)) {
		cifs_dbg(FYI, "negotiated smb2.FF dialect\n");
	} else {
		cifs_dbg(VFS, "Illegal dialect returned by server 0x%x\n",
			 le16_to_cpu(rsp->DialectRevision));
		rc = -EIO;
		goto neg_exit;
	}
	server->dialect = le16_to_cpu(rsp->DialectRevision);
	if (rsp->DialectRevision == cpu_to_le16(0x02ff)) {
		server->dialect = cpu_to_le16(SMB20_PROT_ID);
	}

	/* SMB2 only has an extended negflavor */
	server->negflavor = CIFS_NEGFLAVOR_EXTENDED;
	server->maxBuf = le32_to_cpu(rsp->MaxTransactSize);
	/* set it to the maximum buffer size value we can send with 1 credit */
	server->maxBuf = min_t(unsigned int, le32_to_cpu(rsp->MaxTransactSize),
			       SMB2_MAX_BUFFER_SIZE);
	server->max_read = le32_to_cpu(rsp->MaxReadSize);
	server->max_write = le32_to_cpu(rsp->MaxWriteSize);
	/* BB Do we need to validate the SecurityMode? */
	server->sec_mode = le16_to_cpu(rsp->SecurityMode);
	server->capabilities = le32_to_cpu(rsp->Capabilities);
	/* Internal types */
	server->capabilities |= SMB2_NT_FIND | SMB2_LARGE_FILES;

	security_blob = smb2_get_data_area_len(&blob_offset, &blob_length,
					       &rsp->hdr);
	/*
	 * See MS-SMB2 section 2.2.4: if no blob, client picks default which
	 * for us will be
	 *	ses->sectype = RawNTLMSSP;
	 * but for time being this is our only auth choice so doesn't matter.
	 * We just found a server which sets blob length to zero expecting raw.
	 */
	if (blob_length == 0)
		cifs_dbg(FYI, "missing security blob on negprot\n");

	rc = cifs_enable_signing(server, ses->sign);
	if (rc)
		goto neg_exit;
	if (blob_length) {
		rc = decode_negTokenInit(security_blob, blob_length, server);
		if (rc == 1)
			rc = 0;
		else if (rc == 0)
			rc = -EIO;
	}
neg_exit:
	return rc;
}

static int
small_smb1_nego_init(__le16 smb_command, void **request_buf)
{
	int rc = 0;

	/* BB eventually switch this to SMB2 specific small buf size */
	*request_buf = cifs_small_buf_get();
	if (*request_buf == NULL) {
		/* BB should we add a retry in here if not a writepage? */
		return -ENOMEM;
	}

	header_assemble((struct smb_hdr *) *request_buf, smb_command, NULL, 0);

	return rc;
}

static int
SYNO_negotiate_SMB1_start(const unsigned int xid, struct cifs_ses *ses)
{
	NEGOTIATE_REQ *pSMB;
	struct smb2_negotiate_rsp *rsp;
	struct smb_hdr *buffer = NULL;

	struct kvec iov[1];
	int resp_buftype;
	int rc = 0;
	int i;
	struct TCP_Server_Info *server = ses->server;
	int flags = CIFS_NEG_OP;
	u16 count;
	__u8 *ubuf = NULL;

	if (!server) {
		WARN(1, "%s: server is NULL!\n", __func__);
		return -EIO;
	}
	server->dialect = 0;

	rc = small_smb1_nego_init(SMB_COM_NEGOTIATE, (void **) &pSMB);
	if (rc)
		return rc;

	pSMB->hdr.Mid = get_next_mid(server);
	pSMB->hdr.Flags2 |= (SMBFLG2_UNICODE | SMBFLG2_ERR_STATUS);

	if (should_set_ext_sec_flag(ses->sectype)) {
		pSMB->hdr.Flags2 |= SMBFLG2_EXT_SEC;
	}

	count = 0;
	for (i = 0; NULL != smb1_dialects_array[i].name; i++) {
		strncpy(pSMB->DialectsArray+count, smb1_dialects_array[i].name, 16);
		count += strlen(smb1_dialects_array[i].name) + 1;
		/* null at end of source and target buffers anyway */
	}
	inc_rfc1001_len(pSMB, count);
	pSMB->ByteCount = cpu_to_le16(count);
	buffer = (struct smb_hdr *)pSMB;

	iov[0].iov_base = buffer;
	iov[0].iov_len = be32_to_cpu(buffer->smb_buf_length) + 4;
	rc = SendReceive2(xid, ses, iov, 1, &resp_buftype, flags);

	rsp = (struct smb2_negotiate_rsp *)iov[0].iov_base;
	if (rc != 0)
		goto neg_err_exit;

	ubuf = (__u8 *)iov[0].iov_base;
	if (0xFF == ubuf[4]) {
		//check smb1 response.
		//extract from the cifssmb.c CIFSSMBNegotiate response process
		rc = syno_check_smb1_nego_rsp(ses, iov[0].iov_base);
		if (0 != rc) {
			//force dialect to SMB2.02 for retry
			server->dialect = SMB20_PROT_ID;
		}
	} else {
		//check smb2 response
		rc = syno_check_smb2_nego_rsp(ses, iov[0].iov_base);
	}
neg_err_exit:
	free_rsp_buf(resp_buftype, rsp);

	cifs_dbg(FYI, "negprot rc %d\n", rc);
	return rc;
}

static int
small_smb2_nego_init(__le16 smb2_command, void **request_buf)
{
	int rc = 0;

	/* BB eventually switch this to SMB2 specific small buf size */
	*request_buf = cifs_small_buf_get();
	if (*request_buf == NULL) {
		/* BB should we add a retry in here if not a writepage? */
		return -ENOMEM;
	}

	smb2_hdr_assemble((struct smb2_hdr *) *request_buf, smb2_command, NULL);

	return rc;
}
static int
syno_SMB2_negotiate(const unsigned int xid, struct cifs_ses *ses)
{
	struct smb2_negotiate_req *req;
	struct smb2_negotiate_rsp *rsp;
	struct kvec iov[1];
	int i;
	u16 count;
	int rc = 0;
	int resp_buftype;
	struct TCP_Server_Info *server = ses->server;
	int flags = CIFS_NEG_OP;

	if (!server) {
		WARN(1, "%s: server is NULL!\n", __func__);
		return -EIO;
	}

	rc = small_smb2_nego_init(SMB2_NEGOTIATE, (void **) &req);
	if (rc)
		return rc;

	req->hdr.SessionId = 0;

	req->Dialects[0] = cpu_to_le16(ses->server->vals->protocol_id);
	count = 0;
	for (i = 0; BAD_PROT_ID != smb2_dialects_array[i]; i++) {
		*(req->Dialects+count) = smb2_dialects_array[i];
		count ++;
	}

	req->DialectCount = cpu_to_le16(count);
	inc_rfc1001_len(req, count*2);	//1 dialect = 2 bytes

	/* only one of SMB2 signing flags may be set in SMB2 request */
	if (ses->sign)
		req->SecurityMode = cpu_to_le16(SMB2_NEGOTIATE_SIGNING_REQUIRED);
	else if (global_secflags & CIFSSEC_MAY_SIGN)
		req->SecurityMode = cpu_to_le16(SMB2_NEGOTIATE_SIGNING_ENABLED);
	else
		req->SecurityMode = 0;

	req->Capabilities = cpu_to_le32(ses->server->vals->req_capabilities);

	/* ClientGUID must be zero for SMB2.02 dialect */
	if (ses->server->vals->protocol_id == SMB20_PROT_ID)
		memset(req->ClientGUID, 0, SMB2_CLIENT_GUID_SIZE);
	else {
		memcpy(req->ClientGUID, server->client_guid,
			SMB2_CLIENT_GUID_SIZE);
		//if (ses->server->vals->protocol_id == SMB311_PROT_ID)
		//	assemble_neg_contexts(req);
	}
	iov[0].iov_base = (char *)req;
	/* 4 for rfc1002 length field */
	iov[0].iov_len = get_rfc1002_length(req) + 4;

	rc = SendReceive2(xid, ses, iov, 1, &resp_buftype, flags);

	rsp = (struct smb2_negotiate_rsp *)iov[0].iov_base;
	/*
	 * No tcon so can't do
	 * cifs_stats_inc(&tcon->stats.smb2_stats.smb2_com_fail[SMB2...]);
	 */
	if (rc != 0)
		goto neg_exit;

	rc = syno_check_smb2_nego_rsp(ses, iov[0].iov_base);
neg_exit:
	free_rsp_buf(resp_buftype, rsp);
	return rc;
}
static int
syno_negotiate(const unsigned int xid, struct cifs_ses *ses)
{
	int rc;
	ses->server->CurrentMid = 0;
	rc = SYNO_negotiate_SMB1_start(xid, ses);
	if (0 != rc) {
		ses->server->CurrentMid = 0;
	} else if (SMB20_PROT_ID > ses->server->dialect) {
		goto END;
	}
	rc = syno_SMB2_negotiate(xid, ses);
	/* BB we probably don't need to retry with modern servers */
END:
	if (rc == -EAGAIN)
		rc = -EHOSTDOWN;
	return rc;
}

//	unsigned int (*negotiate_wsize)(struct cifs_tcon *, struct smb_vol *);
static unsigned int
syno_negotiate_wsize(struct cifs_tcon *tcon, struct smb_vol *volume_info)
{
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.negotiate_wsize(tcon, volume_info);
	}
	return smb20_operations.negotiate_wsize(tcon, volume_info);
}

//	unsigned int (*negotiate_rsize)(struct cifs_tcon *, struct smb_vol *);
static unsigned int
syno_negotiate_rsize(struct cifs_tcon *tcon, struct smb_vol *volume_info)
{
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.negotiate_rsize(tcon, volume_info);
	}
	return smb20_operations.negotiate_rsize(tcon, volume_info);
}

//	int (*sess_setup)(const unsigned int, struct cifs_ses *, const struct nls_table *);
static int
syno_sess_setup(const unsigned int xid, struct cifs_ses *ses,
		const struct nls_table *nls_cp)
{
	if (ses && ses->server && SMB20_PROT_ID > ses->server->dialect) {
		return smb1_operations.sess_setup(xid, ses, nls_cp);
	}
	return smb20_operations.sess_setup(xid, ses, nls_cp);
}

//	int (*logoff)(const unsigned int, struct cifs_ses *);
static int
syno_logoff(const unsigned int xid, struct cifs_ses *ses)
{
	if (ses && ses->server && SMB20_PROT_ID > ses->server->dialect) {
		return smb1_operations.logoff(xid, ses);
	}
	return smb20_operations.logoff(xid, ses);
}

//	int (*tree_connect)(const unsigned int, struct cifs_ses *, const char *, struct cifs_tcon *, const struct nls_table *);
static int
syno_tree_connect(const unsigned int xid, struct cifs_ses *ses, const char *tree,
	  struct cifs_tcon *tcon, const struct nls_table *cp)
{
	if (ses && ses->server && SMB20_PROT_ID > ses->server->dialect) {
		return smb1_operations.tree_connect(xid, ses, tree, tcon, cp);
	}
	return smb20_operations.tree_connect(xid, ses, tree, tcon, cp);
}

//	int (*tree_disconnect)(const unsigned int, struct cifs_tcon *);
static int
syno_tree_disconnect(const unsigned int xid, struct cifs_tcon *tcon)
{
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.tree_disconnect(xid, tcon);
	}
	return smb20_operations.tree_disconnect(xid, tcon);
}

//	int (*get_dfs_refer)(const unsigned int, struct cifs_ses *, const char *, struct dfs_info3_param **, unsigned int *, const struct nls_table *, int);
static int
syno_get_dfs_refer(const unsigned int xid, struct cifs_ses *ses,
		const char *search_name, struct dfs_info3_param **target_nodes,
		unsigned int *num_of_nodes,
		const struct nls_table *nls_codepage, int remap)
{
	if (ses && ses->server && SMB20_PROT_ID > ses->server->dialect) {
		return smb1_operations.get_dfs_refer(xid, ses, search_name, target_nodes,
			num_of_nodes, nls_codepage, remap);
	}
	return -EOPNOTSUPP;
}

//	void (*qfs_tcon)(const unsigned int, struct cifs_tcon *);
static void
syno_qfs_tcon(const unsigned int xid, struct cifs_tcon *tcon)
{
	if (tcon && tcon->ses && tcon->ses->server) {
		if (SMB20_PROT_ID > tcon->ses->server->dialect) {
			return smb1_operations.qfs_tcon(xid, tcon);
#ifdef CONFIG_CRYPTO_CMAC
		} else if (SMB30_PROT_ID <= tcon->ses->server->dialect) {
			return smb30_operations.qfs_tcon(xid, tcon);
#endif /* CONFIG_CRYPTO_CMAC */
		}
	}
	return smb20_operations.qfs_tcon(xid, tcon);
}

//	int (*is_path_accessible)(const unsigned int, struct cifs_tcon *, struct cifs_sb_info *, const char *);
static int
syno_is_path_accessible(const unsigned int xid, struct cifs_tcon *tcon,
			struct cifs_sb_info *cifs_sb, const char *full_path)
{
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.is_path_accessible(xid, tcon, cifs_sb, full_path);
	}
	return smb20_operations.is_path_accessible(xid, tcon, cifs_sb, full_path);
}

//	int (*query_path_info)(const unsigned int, struct cifs_tcon *, struct cifs_sb_info *, const char *, FILE_ALL_INFO *, bool *, bool *);
static int
syno_query_path_info(const unsigned int xid, struct cifs_tcon *tcon,
		     struct cifs_sb_info *cifs_sb, const char *full_path,
		     FILE_ALL_INFO *data, bool *adjustTZ, bool *symlink)
{
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.query_path_info(xid, tcon, cifs_sb, full_path, data, adjustTZ, symlink);
	}
	return smb20_operations.query_path_info(xid, tcon, cifs_sb, full_path, data, adjustTZ, symlink);
}

//	int (*query_file_info)(const unsigned int, struct cifs_tcon *, struct cifs_fid *, FILE_ALL_INFO *);
static int
syno_query_file_info(const unsigned int xid, struct cifs_tcon *tcon,
		     struct cifs_fid *fid, FILE_ALL_INFO *data)
{
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.query_file_info(xid, tcon, fid, data);
	}
	return smb20_operations.query_file_info(xid, tcon, fid, data);
}

//	int (*get_srv_inum)(const unsigned int, struct cifs_tcon *, struct cifs_sb_info *, const char *, u64 *uniqueid, FILE_ALL_INFO *);
static int
syno_get_srv_inum(const unsigned int xid, struct cifs_tcon *tcon,
		  struct cifs_sb_info *cifs_sb, const char *full_path,
		  u64 *uniqueid, FILE_ALL_INFO *data)
{
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.get_srv_inum(xid, tcon, cifs_sb, full_path, uniqueid, data);
	}
	return smb20_operations.get_srv_inum(xid, tcon, cifs_sb, full_path, uniqueid, data);
}

//	int (*set_path_size)(const unsigned int, struct cifs_tcon *, const char *, __u64, struct cifs_sb_info *, bool);
static int
syno_set_path_size(const unsigned int xid, struct cifs_tcon *tcon,
		   const char *full_path, __u64 size,
		   struct cifs_sb_info *cifs_sb, bool set_alloc)
{
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.set_path_size(xid, tcon, full_path, size, cifs_sb, set_alloc);
	}
	return smb20_operations.set_path_size(xid, tcon, full_path, size, cifs_sb, set_alloc);
}

//	int (*set_file_size)(const unsigned int, struct cifs_tcon *, struct cifsFileInfo *, __u64, bool);
static int
syno_set_file_size(const unsigned int xid, struct cifs_tcon *tcon,
		   struct cifsFileInfo *cfile, __u64 size, bool set_alloc)
{
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.set_file_size(xid, tcon, cfile, size, set_alloc);
	}
	return smb20_operations.set_file_size(xid, tcon, cfile, size, set_alloc);
}

//	int (*set_file_info)(struct inode *, const char *, FILE_BASIC_INFO *, const unsigned int);
static int
syno_set_file_info(struct inode *inode, const char *full_path,
		   FILE_BASIC_INFO *buf, const unsigned int xid)
{
	struct cifs_sb_info *cifs_sb = CIFS_SB(inode->i_sb);
	struct tcon_link *tlink = NULL;
	struct cifs_tcon *tcon = NULL;

	tlink = cifs_sb_tlink(cifs_sb);
	if (IS_ERR(tlink))
		return PTR_ERR(tlink);

	tcon = tlink_tcon(tlink);
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.set_file_info(inode, full_path, buf, xid);
	}
	return smb20_operations.set_file_info(inode, full_path, buf, xid);
}

//	int (*set_compression)(const unsigned int, struct cifs_tcon *, struct cifsFileInfo *);
static int
syno_set_compression(const unsigned int xid, struct cifs_tcon *tcon,
		   struct cifsFileInfo *cfile)
{
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.set_compression(xid, tcon, cfile);
	}
	return smb20_operations.set_compression(xid, tcon, cfile);
}

//	bool (*can_echo)(struct TCP_Server_Info *);
static bool
syno_can_echo(struct TCP_Server_Info *server)
{
	if (SMB20_PROT_ID <= server->dialect) {
		return smb20_operations.can_echo(server);
	}
	//this function only used by connect.c: (server->ops->can_echo && !server->ops->can_echo(server))
	//SMB1 don't have this ops, so can_echo will not exist. But we need use it for SMB2.
	//Therefore we force can_echo return true to break this condition when using SMB1.
	return true;
}

//	int (*echo)(struct TCP_Server_Info *);
SYNOWRAP0_SERVER_SMB20(int, echo)

//	int (*mkdir)(const unsigned int, struct cifs_tcon *, const char *, struct cifs_sb_info *);
static int
syno_mkdir(const unsigned int xid, struct cifs_tcon *tcon, const char *name,
	   struct cifs_sb_info *cifs_sb)
{
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.mkdir(xid, tcon, name, cifs_sb);
	}
	return smb20_operations.mkdir(xid, tcon, name, cifs_sb);
}

//	void (*mkdir_setinfo)(struct inode *, const char *, struct cifs_sb_info *, struct cifs_tcon *, const unsigned int);
static void
syno_mkdir_setinfo(struct inode *inode, const char *name,
		   struct cifs_sb_info *cifs_sb, struct cifs_tcon *tcon,
		   const unsigned int xid)
{
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.mkdir_setinfo(inode, name, cifs_sb, tcon, xid);
	}
	return smb20_operations.mkdir_setinfo(inode, name, cifs_sb, tcon, xid);
}

//	int (*rmdir)(const unsigned int, struct cifs_tcon *, const char *, struct cifs_sb_info *);
static int
syno_rmdir(const unsigned int xid, struct cifs_tcon *tcon, const char *name,
	   struct cifs_sb_info *cifs_sb)
{
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.rmdir(xid, tcon, name, cifs_sb);
	}
	return smb20_operations.rmdir(xid, tcon, name, cifs_sb);
}

//	int (*unlink)(const unsigned int, struct cifs_tcon *, const char *, struct cifs_sb_info *);
static int
syno_unlink(const unsigned int xid, struct cifs_tcon *tcon, const char *name,
	    struct cifs_sb_info *cifs_sb)
{
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.unlink(xid, tcon, name, cifs_sb);
	}
	return smb20_operations.unlink(xid, tcon, name, cifs_sb);
}

//	int (*rename_pending_delete)(const char *, struct dentry *, const unsigned int);
static int
syno_rename_pending_delete(const char *full_path, struct dentry *dentry,
			   const unsigned int xid)
{
	struct inode *inode = dentry->d_inode;
	struct cifs_sb_info *cifs_sb = CIFS_SB(inode->i_sb);
	struct tcon_link *tlink = NULL;
	struct cifs_tcon *tcon = NULL;

	tlink = cifs_sb_tlink(cifs_sb);
	if (IS_ERR(tlink))
		return PTR_ERR(tlink);
	tcon = tlink_tcon(tlink);
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.rename_pending_delete(full_path, dentry, xid);
	}
	return -EOPNOTSUPP;;
}

//	int (*rename)(const unsigned int, struct cifs_tcon *, const char *, const char *, struct cifs_sb_info *);
static int
syno_rename(const unsigned int xid, struct cifs_tcon *tcon,
		 const char *from_name, const char *to_name,
		 struct cifs_sb_info *cifs_sb)
{
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.rename(xid, tcon, from_name, to_name, cifs_sb);
	}
	return smb20_operations.rename(xid, tcon, from_name, to_name, cifs_sb);
}

//	int (*create_hardlink)(const unsigned int, struct cifs_tcon *, const char *, const char *, struct cifs_sb_info *);
static int
syno_create_hardlink(const unsigned int xid, struct cifs_tcon *tcon,
		     const char *from_name, const char *to_name,
		     struct cifs_sb_info *cifs_sb)
{
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.create_hardlink(xid, tcon, from_name, to_name, cifs_sb);
	}
	return smb20_operations.create_hardlink(xid, tcon, from_name, to_name, cifs_sb);
}

//	int (*query_symlink)(const unsigned int, struct cifs_tcon *, const char *, char **, struct cifs_sb_info *);
static int
syno_query_symlink(const unsigned int xid, struct cifs_tcon *tcon,
		   const char *full_path, char **target_path,
		   struct cifs_sb_info *cifs_sb)
{
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.query_symlink(xid, tcon, full_path, target_path, cifs_sb);
	}
	return smb20_operations.query_symlink(xid, tcon, full_path, target_path, cifs_sb);
}

//	int (*open)(const unsigned int, struct cifs_open_parms *, __u32 *, FILE_ALL_INFO *);
static int
syno_open(const unsigned int xid, struct cifs_open_parms *oparms,
	       __u32 *oplock, FILE_ALL_INFO *buf)
{
	if (oparms && oparms->tcon && oparms->tcon->ses && oparms->tcon->ses->server &&
		SMB20_PROT_ID > oparms->tcon->ses->server->dialect) {
		return smb1_operations.open(xid, oparms, oplock, buf);
	}
	return smb20_operations.open(xid, oparms, oplock, buf);
}

//	void (*set_fid)(struct cifsFileInfo *, struct cifs_fid *, __u32);
static void
syno_set_fid(struct cifsFileInfo *cfile, struct cifs_fid *fid, __u32 oplock)
{
	struct TCP_Server_Info *server = tlink_tcon(cfile->tlink)->ses->server;
	if (SMB20_PROT_ID > server->dialect) {
		return smb1_operations.set_fid(cfile, fid, oplock);
	}
	return smb20_operations.set_fid(cfile, fid, oplock);
}

//	void (*close)(const unsigned int, struct cifs_tcon *, struct cifs_fid *);
static void
syno_close(const unsigned int xid, struct cifs_tcon *tcon,
		struct cifs_fid *fid)
{
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		smb1_operations.close(xid, tcon, fid);
		return;
	}
	smb20_operations.close(xid, tcon, fid);
}

//	int (*flush)(const unsigned int, struct cifs_tcon *, struct cifs_fid *);
static int
syno_flush(const unsigned int xid, struct cifs_tcon *tcon,
		struct cifs_fid *fid)
{
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.flush(xid, tcon, fid);
	}
	return smb20_operations.flush(xid, tcon, fid);
}

//	int (*async_readv)(struct cifs_readdata *);
static int
syno_async_readv(struct cifs_readdata *rdata)
{
	struct cifs_tcon *tcon = tlink_tcon(rdata->cfile->tlink);
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.async_readv(rdata);
	}
	return smb20_operations.async_readv(rdata);
}

//	int (*async_writev)(struct cifs_writedata *, void (*release)(struct kref *));
static int
syno_async_writev(struct cifs_writedata *wdata,
		  void (*release)(struct kref *kref))
{
	struct cifs_tcon *tcon = tlink_tcon(wdata->cfile->tlink);
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.async_writev(wdata, release);
	}
	return smb20_operations.async_writev(wdata, release);
}

//	int (*sync_read)(const unsigned int, struct cifs_fid *, struct cifs_io_parms *, unsigned int *, char **, int *);
static int
syno_sync_read(const unsigned int xid, struct cifs_fid *pfid,
	       struct cifs_io_parms *parms, unsigned int *bytes_read,
	       char **buf, int *buf_type)
{
	struct cifs_tcon *tcon = parms->tcon;
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.sync_read(xid, pfid, parms, bytes_read, buf, buf_type);
	}
	return smb20_operations.sync_read(xid, pfid, parms, bytes_read, buf, buf_type);
}

//	int (*sync_write)(const unsigned int, struct cifs_fid *, struct cifs_io_parms *, unsigned int *, struct kvec *, unsigned long);
static int
syno_sync_write(const unsigned int xid, struct cifs_fid *pfid,
		struct cifs_io_parms *parms, unsigned int *written,
		struct kvec *iov, unsigned long nr_segs)
{
	struct cifs_tcon *tcon = parms->tcon;
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.sync_write(xid, pfid, parms, written, iov, nr_segs);
	}
	return smb20_operations.sync_write(xid, pfid, parms, written, iov, nr_segs);
}

//	int (*query_dir_first)(const unsigned int, struct cifs_tcon *, const char *, struct cifs_sb_info *, struct cifs_fid *, __u16, struct cifs_search_info *);
static int
syno_query_dir_first(const unsigned int xid, struct cifs_tcon *tcon,
		     const char *path, struct cifs_sb_info *cifs_sb,
		     struct cifs_fid *fid, __u16 search_flags,
		     struct cifs_search_info *srch_inf)
{
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.query_dir_first(xid, tcon, path, cifs_sb, fid, search_flags, srch_inf);
	}
	return smb20_operations.query_dir_first(xid, tcon, path, cifs_sb, fid, search_flags, srch_inf);
}

//	int (*query_dir_next)(const unsigned int, struct cifs_tcon *, struct cifs_fid *, __u16, struct cifs_search_info *srch_inf);
static int
syno_query_dir_next(const unsigned int xid, struct cifs_tcon *tcon,
		    struct cifs_fid *fid, __u16 search_flags,
		    struct cifs_search_info *srch_inf)
{
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.query_dir_next(xid, tcon, fid, search_flags, srch_inf);
	}
	return smb20_operations.query_dir_next(xid, tcon, fid, search_flags, srch_inf);
}

//	int (*close_dir)(const unsigned int, struct cifs_tcon *, struct cifs_fid *);
static int
syno_close_dir(const unsigned int xid, struct cifs_tcon *tcon,
	       struct cifs_fid *fid)
{
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.close_dir(xid, tcon, fid);
	}
	return smb20_operations.close_dir(xid, tcon, fid);
}

//	unsigned int (*calc_smb_size)(void *);
SYNOWRAP0_BUF_SMB20(unsigned int, calc_smb_size, void *)

//	bool (*is_status_pending)(char *, struct TCP_Server_Info *, int);
static bool
syno_is_status_pending(char *buf, struct TCP_Server_Info *server, int length)
{
	if (0xFF == (__u8)buf[4]) {
		return false;
	}
	return smb20_operations.is_status_pending(buf, server, length);
}

//	int (*oplock_response)(struct cifs_tcon *, struct cifs_fid *, struct cifsInodeInfo *);
static int
syno_oplock_response(struct cifs_tcon *tcon, struct cifs_fid *fid,
		     struct cifsInodeInfo *cinode)
{
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.oplock_response(tcon, fid, cinode);
	}
	return smb20_operations.oplock_response(tcon, fid, cinode);
}

//	int (*queryfs)(const unsigned int, struct cifs_tcon *, struct kstatfs *);
static int
syno_queryfs(const unsigned int xid, struct cifs_tcon *tcon,
	     struct kstatfs *buf)
{
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.queryfs(xid, tcon, buf);
	}
	return smb20_operations.queryfs(xid, tcon, buf);
}

//	int (*mand_lock)(const unsigned int, struct cifsFileInfo *, __u64, __u64, __u32, int, int, bool);
static int
syno_mand_lock(const unsigned int xid, struct cifsFileInfo *cfile, __u64 offset,
	       __u64 length, __u32 type, int lock, int unlock, bool wait)
{
	struct cifs_tcon *tcon = tlink_tcon(cfile->tlink);
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.mand_lock(xid, cfile, offset, length, type, lock, unlock, wait);
	}
	return smb20_operations.mand_lock(xid, cfile, offset, length, type, lock, unlock, wait);
}

//	int (*mand_unlock_range)(struct cifsFileInfo *, struct file_lock *, const unsigned int);
static int
syno_unlock_range(struct cifsFileInfo *cfile, struct file_lock *flock,
		  const unsigned int xid)
{
	struct cifs_tcon *tcon = tlink_tcon(cfile->tlink);
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.mand_unlock_range(cfile, flock, xid);
	}
	return smb20_operations.mand_unlock_range(cfile, flock, xid);
}

//	int (*push_mand_locks)(struct cifsFileInfo *);
static int
syno_push_mand_locks(struct cifsFileInfo *cfile)
{
	struct cifs_tcon *tcon = tlink_tcon(cfile->tlink);
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID > tcon->ses->server->dialect) {
		return smb1_operations.push_mand_locks(cfile);
	}
	return smb20_operations.push_mand_locks(cfile);
}

//	void (*get_lease_key)(struct inode *, struct cifs_fid *);
static void
syno_get_lease_key(struct inode *inode, struct cifs_fid *fid)
{
	struct cifs_sb_info *cifs_sb = CIFS_SB(inode->i_sb);
	struct tcon_link *tlink = NULL;
	struct cifs_tcon *tcon = NULL;

	tlink = cifs_sb_tlink(cifs_sb);
	if (IS_ERR(tlink))
		return;

	tcon = tlink_tcon(tlink);
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID <= tcon->ses->server->dialect) {
		return smb20_operations.get_lease_key(inode, fid);
	}
}

//	void (*set_lease_key)(struct inode *, struct cifs_fid *);
static void
syno_set_lease_key(struct inode *inode, struct cifs_fid *fid)
{
	struct cifs_sb_info *cifs_sb = CIFS_SB(inode->i_sb);
	struct tcon_link *tlink = NULL;
	struct cifs_tcon *tcon = NULL;

	tlink = cifs_sb_tlink(cifs_sb);
	if (IS_ERR(tlink))
		return;

	tcon = tlink_tcon(tlink);
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID <= tcon->ses->server->dialect) {
		return smb20_operations.set_lease_key(inode, fid);
	}
}

//	void (*new_lease_key)(struct cifs_fid *);
static void
syno_new_lease_key(struct cifs_fid *fid)
{
	//no any argument to distiguish SMB1 or SMB2
	smb20_operations.new_lease_key(fid);
}

//	int (*generate_signingkey)(struct cifs_ses *);
static int
syno_generate_signingkey(struct cifs_ses *ses)
{
#ifdef CONFIG_CRYPTO_CMAC
	if (ses && ses->server && SMB30_PROT_ID <= ses->server->dialect) {
		return smb30_operations.generate_signingkey(ses);
	}
#endif /* CONFIG_CRYPTO_CMAC */
	return -EOPNOTSUPP;
}

//	int (*calc_signature)(struct smb_rqst *, struct TCP_Server_Info *);
static int
syno_calc_signature(struct smb_rqst *rqst, struct TCP_Server_Info *server)
{
	if (SMB20_PROT_ID > server->dialect) {
		// this function only call by smb2transport, so it is imposible enter here
		return -EOPNOTSUPP;
	} else if (SMB30_PROT_ID > server->dialect) {
		return smb20_operations.calc_signature(rqst, server);
	}
#ifdef CONFIG_CRYPTO_CMAC
	return smb30_operations.calc_signature(rqst, server);
#else
	return -EOPNOTSUPP;
#endif /* CONFIG_CRYPTO_CMAC */
}

//	int (*set_integrity)(const unsigned int, struct cifs_tcon *tcon, struct cifsFileInfo *src_file);
static int
syno_set_integrity(const unsigned int xid, struct cifs_tcon *tcon,
		   struct cifsFileInfo *cfile)
{
#ifdef CONFIG_CRYPTO_CMAC
	// this function call by ioctl only. not support protocol also return -EOPNOTSUPP
	if (tcon && tcon->ses && tcon->ses->server && SMB30_PROT_ID <= tcon->ses->server->dialect) {
		return smb30_operations.set_integrity(xid, tcon, cfile);
	}
#endif /* CONFIG_CRYPTO_CMAC */
	return -EOPNOTSUPP;
}

//	int (*query_mf_symlink)(unsigned int, struct cifs_tcon *, struct cifs_sb_info *, const unsigned char *, char *, unsigned int *);
static int
syno_query_mf_symlink(unsigned int xid, struct cifs_tcon *tcon,
		      struct cifs_sb_info *cifs_sb, const unsigned char *path,
		      char *pbuf, unsigned int *pbytes_read)
{
	// this function call by link.c. and not support protcol return -ENOSYS
	if (tcon && tcon->ses && tcon->ses->server) {
		if (SMB20_PROT_ID > tcon->ses->server->dialect) {
			return smb1_operations.query_mf_symlink(xid, tcon, cifs_sb, path, pbuf, pbytes_read);
#ifdef CONFIG_CRYPTO_CMAC
		} else if (SMB30_PROT_ID <= tcon->ses->server->dialect) {
			return smb30_operations.query_mf_symlink(xid, tcon, cifs_sb, path, pbuf, pbytes_read);
#endif /* CONFIG_CRYPTO_CMAC */
		}
	}
	return -ENOSYS;
}

//	int (*create_mf_symlink)(unsigned int, struct cifs_tcon *, struct cifs_sb_info *, const unsigned char *, char *, unsigned int *);
static int
syno_create_mf_symlink(unsigned int xid, struct cifs_tcon *tcon,
		       struct cifs_sb_info *cifs_sb, const unsigned char *path,
		       char *pbuf, unsigned int *pbytes_written)
{
	// this function call by link.c. and not support protcol return -EOPNOTSUPP
	if (tcon && tcon->ses && tcon->ses->server) {
		if (SMB20_PROT_ID > tcon->ses->server->dialect) {
			return smb1_operations.create_mf_symlink(xid, tcon, cifs_sb, path, pbuf, pbytes_written);
#ifdef CONFIG_CRYPTO_CMAC
		} else if (SMB30_PROT_ID <= tcon->ses->server->dialect) {
			return smb30_operations.create_mf_symlink(xid, tcon, cifs_sb, path, pbuf, pbytes_written);
#endif /* CONFIG_CRYPTO_CMAC */
		}
	}
	return -EOPNOTSUPP;
}

//	bool (*is_read_op)(__u32);
static bool
syno_is_read_op(struct TCP_Server_Info *server, __u32 oplock)
{
	//need modify interface due to oplock define conflict
	if (SMB20_PROT_ID > server->dialect) {
		return smb1_operations.is_read_op(server, oplock);
	} else if (SMB20_PROT_ID == server->dialect) {
		return smb20_operations.is_read_op(server, oplock);
	}
	return smb21_operations.is_read_op(server, oplock);
}

//	void (*set_oplock_level)(struct cifsInodeInfo *, __u32, unsigned int, bool *);
static void
syno_set_oplock_level(struct cifsInodeInfo *cinode, __u32 oplock,
		       unsigned int epoch, bool *purge_cache)
{
	struct cifs_sb_info *cifs_sb = CIFS_SB(cinode->vfs_inode.i_sb);
	struct cifs_tcon *tcon = cifs_sb_master_tcon(cifs_sb);
	if (tcon && tcon->ses && tcon->ses->server) {
		if (SMB20_PROT_ID == tcon->ses->server->dialect) {
			smb20_operations.set_oplock_level(cinode, oplock, epoch, purge_cache);
		} else if (SMB21_PROT_ID == tcon->ses->server->dialect) {
			smb21_operations.set_oplock_level(cinode, oplock, epoch, purge_cache);
#ifdef CONFIG_CRYPTO_CMAC
		} else if (SMB30_PROT_ID <= tcon->ses->server->dialect) {
			smb30_operations.set_oplock_level(cinode, oplock, epoch, purge_cache);
#endif /* CONFIG_CRYPTO_CMAC */
		}
	}
}

//	char * (*create_lease_buf)(u8 *, u8);
static char *
syno_create_lease_buf(struct TCP_Server_Info *server, u8 *lease_key, u8 oplock)
{
	if (SMB20_PROT_ID > server->dialect) {
		//this function should be used by smb2 only
		return NULL;
	} else if (SMB30_PROT_ID > server->dialect) {
		return smb20_operations.create_lease_buf(server, lease_key, oplock);
	}
#ifdef CONFIG_CRYPTO_CMAC
	return smb30_operations.create_lease_buf(server, lease_key, oplock);
#else
	return NULL;
#endif /* CONFIG_CRYPTO_CMAC */
}

//	__u8 (*parse_lease_buf)(void *, unsigned int *);
static __u8
syno_parse_lease_buf(struct TCP_Server_Info *server, void *buf, unsigned int *epoch)
{
	if (SMB20_PROT_ID > server->dialect) {
		//this function should be used by smb2 only
		return -EOPNOTSUPP;
	} else if (SMB30_PROT_ID > server->dialect) {
		return smb20_operations.parse_lease_buf(server, buf, epoch);
	}
#ifdef CONFIG_CRYPTO_CMAC
	return smb30_operations.parse_lease_buf(server, buf, epoch);
#else
	return -EOPNOTSUPP;
#endif /* CONFIG_CRYPTO_CMAC */
}

//	int (*clone_range)(const unsigned int, struct cifsFileInfo *src_file, struct cifsFileInfo *target_file, u64 src_off, u64 len, u64 dest_off);
static int
syno_clone_range(const unsigned int xid,
			struct cifsFileInfo *srcfile,
			struct cifsFileInfo *trgtfile, u64 src_off,
			u64 len, u64 dest_off)
{
	// this function call by ioctl.c. and not support protcol return -EOPNOTSUPP
	struct cifs_tcon *tcon = tlink_tcon(srcfile->tlink);
	if (tcon && tcon->ses && tcon->ses->server && SMB20_PROT_ID < tcon->ses->server->dialect) {
		return smb20_operations.clone_range(xid, srcfile, trgtfile, src_off, len, dest_off);
	}
	return -EOPNOTSUPP;
}

//	int (*duplicate_extents)(const unsigned int, struct cifsFileInfo *src, struct cifsFileInfo *target_file, u64 src_off, u64 len, u64 dest_off);
static int
syno_duplicate_extents(const unsigned int xid,
			struct cifsFileInfo *srcfile,
			struct cifsFileInfo *trgtfile, u64 src_off,
			u64 len, u64 dest_off)
{
#ifdef CONFIG_CRYPTO_CMAC
	// this function call by ioctl.c. and not support protcol return -EOPNOTSUPP
	struct cifs_tcon *tcon = tlink_tcon(trgtfile->tlink);
	if (tcon && tcon->ses && tcon->ses->server && SMB30_PROT_ID <= tcon->ses->server->dialect) {
		return smb30_operations.duplicate_extents(xid, srcfile, trgtfile, src_off, len, dest_off);
	}
#endif /* CONFIG_CRYPTO_CMAC */
	return -EOPNOTSUPP;
}

//	int (*validate_negotiate)(const unsigned int, struct cifs_tcon *);
static int
syno_validate_negotiate(const unsigned int xid, struct cifs_tcon *tcon)
{
#ifdef CONFIG_CRYPTO_CMAC
	//this function call by SMB2_tcon. if not supported protocol will keep return value (0)
	if (tcon && tcon->ses && tcon->ses->server && SMB30_PROT_ID == tcon->ses->server->dialect) {
		return smb30_operations.validate_negotiate(xid, tcon);
	}
#endif /* CONFIG_CRYPTO_CMAC */
	return 0;
}
//only SMB1 with XATTR config
//	ssize_t (*query_all_EAs)(const unsigned int, struct cifs_tcon *, const unsigned char *, const unsigned char *, char *, size_t, const struct nls_table *, int);
//	int (*set_EA)(const unsigned int, struct cifs_tcon *, const char *, const char *, const void *, const __u16, const struct nls_table *, int);

//acl depend on XATTR
//	struct cifs_ntsd * (*get_acl)(struct cifs_sb_info *, struct inode *, const char *, u32 *);
//	struct cifs_ntsd * (*get_acl_by_fid)(struct cifs_sb_info *, const struct cifs_fid *, u32 *);
//	int (*set_acl)(struct cifs_ntsd *, __u32, struct inode *, const char *, int);

//	unsigned int (*wp_retry_size)(struct inode *);
static unsigned int
syno_wp_retry_size(struct inode *inode)
{
	// this function used by cifs_writev_requeue use min size of SMB1/SMB2
	return min_t(unsigned int, CIFS_SB(inode->i_sb)->wsize,
		     SMB2_MAX_BUFFER_SIZE);
}

//	int (*wait_mtu_credits)(struct TCP_Server_Info *, unsigned int, unsigned int *, unsigned int *);
static int
syno_wait_mtu_credits(struct TCP_Server_Info *server, unsigned int size,
		      unsigned int *num, unsigned int *credits)
{
	if (SMB20_PROT_ID >= server->dialect) {
		return smb1_operations.wait_mtu_credits(server, size, num, credits);
	}
	return smb21_operations.wait_mtu_credits(server, size, num, credits);
}

//	bool (*dir_needs_close)(struct cifsFileInfo *);
static bool
syno_dir_needs_close(struct cifsFileInfo *cfile)
{
	struct TCP_Server_Info *server = tlink_tcon(cfile->tlink)->ses->server;
	if (SMB20_PROT_ID > server->dialect) {
		return smb1_operations.dir_needs_close(cfile);
	}
	return smb20_operations.dir_needs_close(cfile);
}

//	long (*fallocate)(struct file *, struct cifs_tcon *, int, loff_t, loff_t);
static long syno_fallocate(struct file *file, struct cifs_tcon *tcon, int mode,
			   loff_t off, loff_t len)
{
#ifdef CONFIG_CRYPTO_CMAC
	// this function used by cifs_fallocate. if protocol no this function return -EOPNOTSUPP
	if (tcon && tcon->ses && tcon->ses->server && SMB30_PROT_ID <= tcon->ses->server->dialect) {
		return smb30_operations.fallocate(file, tcon, mode, off, len);
	}
#endif /* CONFIG_CRYPTO_CMAC */
	return -EOPNOTSUPP;
}

struct smb_version_operations synocifs_operations = {
	.send_cancel = syno_send_cancel,
	.compare_fids = syno_compare_fids,
	.setup_request = syno_setup_request,
	.setup_async_request = syno_setup_async_request,
	.check_receive = syno_check_receive,
	.add_credits = syno_add_credits,
	.set_credits = syno_set_credits,
	.get_credits_field = syno_get_credits_field,
	.get_credits = syno_get_credits,
	.wait_mtu_credits = syno_wait_mtu_credits,
	.get_next_mid = syno_get_next_mid,
	.read_data_offset = syno_read_data_offset,
	.read_data_length = syno_read_data_length,
	.map_error = syno_map_error,
	.find_mid = syno_find_mid,
	.check_message = syno_check_message,
	.dump_detail = syno_dump_detail,
	.clear_stats = syno_clear_stats,
	.print_stats = syno_print_stats,
	.dump_share_caps = syno_dump_share_caps,
	.is_oplock_break = syno_is_oplock_break,
	.downgrade_oplock = syno_downgrade_oplock,
	.check_trans2 = syno_check_trans2,
	.need_neg = syno_need_neg,
	.negotiate = syno_negotiate,
	.negotiate_wsize = syno_negotiate_wsize,
	.negotiate_rsize = syno_negotiate_rsize,
	.sess_setup = syno_sess_setup,
	.logoff = syno_logoff,
	.tree_connect = syno_tree_connect,
	.tree_disconnect = syno_tree_disconnect,
	.get_dfs_refer = syno_get_dfs_refer,
	.qfs_tcon = syno_qfs_tcon,
	.is_path_accessible = syno_is_path_accessible,
	.can_echo = syno_can_echo,
	.echo = syno_echo,
	.query_path_info = syno_query_path_info,
	.get_srv_inum = syno_get_srv_inum,
	.query_file_info = syno_query_file_info,
	.set_path_size = syno_set_path_size,
	.set_file_size = syno_set_file_size,
	.set_file_info = syno_set_file_info,
	.set_compression = syno_set_compression,
	.mkdir = syno_mkdir,
	.mkdir_setinfo = syno_mkdir_setinfo,
	.rmdir = syno_rmdir,
	.unlink = syno_unlink,
	.rename_pending_delete = syno_rename_pending_delete,
	.rename = syno_rename,
	.create_hardlink = syno_create_hardlink,
	.query_symlink = syno_query_symlink,
	.query_mf_symlink = syno_query_mf_symlink,
	.create_mf_symlink = syno_create_mf_symlink,
	.open = syno_open,
	.set_fid = syno_set_fid,
	.close = syno_close,
	.flush = syno_flush,
	.async_readv = syno_async_readv,
	.async_writev = syno_async_writev,
	.sync_read = syno_sync_read,
	.sync_write = syno_sync_write,
	.query_dir_first = syno_query_dir_first,
	.query_dir_next = syno_query_dir_next,
	.close_dir = syno_close_dir,
	.calc_smb_size = syno_calc_smb_size,
	.is_status_pending = syno_is_status_pending,
	.oplock_response = syno_oplock_response,
	.queryfs = syno_queryfs,
	.mand_lock = syno_mand_lock,
	.mand_unlock_range = syno_unlock_range,
	.push_mand_locks = syno_push_mand_locks,
	.get_lease_key = syno_get_lease_key,
	.set_lease_key = syno_set_lease_key,
	.new_lease_key = syno_new_lease_key,
	.generate_signingkey = syno_generate_signingkey,
	.calc_signature = syno_calc_signature,
	.set_integrity  = syno_set_integrity,
	.is_read_op = syno_is_read_op,
	.set_oplock_level = syno_set_oplock_level,
	.create_lease_buf = syno_create_lease_buf,
	.parse_lease_buf = syno_parse_lease_buf,
	.clone_range = syno_clone_range,
	.duplicate_extents = syno_duplicate_extents,
	.validate_negotiate = syno_validate_negotiate,
	.wp_retry_size = syno_wp_retry_size,
	.dir_needs_close = syno_dir_needs_close,
	.fallocate = syno_fallocate,
};

struct smb_version_values synocifs_values = {
	.version_string = SYNO_VERSION_STRING,
	.protocol_id = SMB21_PROT_ID,	//should set after negotiate
	.req_capabilities = 0, /* MBZ on negotiate req until SMB3 dialect */
	.large_lock_type = 0,
	.exclusive_lock_type = SMB2_LOCKFLAG_EXCLUSIVE_LOCK,
	.shared_lock_type = SMB2_LOCKFLAG_SHARED_LOCK,
	.unlock_lock_type = SMB2_LOCKFLAG_UNLOCK,
	.header_size = sizeof(struct smb2_hdr),
	.max_header_size = MAX_SMB2_HDR_SIZE,
	.read_rsp_size = sizeof(struct smb2_read_rsp) - 1,
	.lock_cmd = SMB2_LOCK,
	.cap_unix = 0,
	.cap_nt_find = SMB2_NT_FIND,
	.cap_large_files = SMB2_LARGE_FILES,
	.signing_enabled = SMB2_NEGOTIATE_SIGNING_ENABLED | SMB2_NEGOTIATE_SIGNING_REQUIRED,
	.signing_required = SMB2_NEGOTIATE_SIGNING_REQUIRED,
	.create_lease_size = sizeof(struct create_lease),
};
