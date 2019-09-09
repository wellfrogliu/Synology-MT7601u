#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/fs.h>
#include <linux/slab.h>
#include "cifs_fs_sb.h"
#include "cifs_unicode.h"
#include "cifs_uniupr.h"
#include "cifspdu.h"
#include "cifsglob.h"
#include "cifs_debug.h"

int cifs_remap(struct cifs_sb_info *cifs_sb)
{
	int map_type;

	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_MAP_SFM_CHR)
		map_type = SFM_MAP_UNI_RSVD;
	else if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_MAP_SPECIAL_CHR)
		map_type = SFU_MAP_UNI_RSVD;
	else
		map_type = NO_MAP_UNI_RSVD;

	return map_type;
}

static bool
convert_sfu_char(const __u16 src_char, char *target)
{
	 
	switch (src_char) {
	case UNI_COLON:
		*target = ':';
		break;
	case UNI_ASTERISK:
		*target = '*';
		break;
	case UNI_QUESTION:
		*target = '?';
		break;
	case UNI_PIPE:
		*target = '|';
		break;
	case UNI_GRTRTHAN:
		*target = '>';
		break;
	case UNI_LESSTHAN:
		*target = '<';
		break;
#ifdef MY_ABC_HERE
	case UNI_DQUOT:
		*target = '"';
		break;
	case UNI_DIVSLASH:
		*target = '/';
		break;
	case UNI_CRGRET:
		*target = '\r';
		break;
#endif  
	default:
		return false;
	}
	return true;
}

static bool
convert_sfm_char(const __u16 src_char, char *target)
{
	switch (src_char) {
	case SFM_COLON:
		*target = ':';
		break;
	case SFM_ASTERISK:
		*target = '*';
		break;
	case SFM_QUESTION:
		*target = '?';
		break;
	case SFM_PIPE:
		*target = '|';
		break;
	case SFM_GRTRTHAN:
		*target = '>';
		break;
	case SFM_LESSTHAN:
		*target = '<';
		break;
	case SFM_SLASH:
		*target = '\\';
		break;
	case SFM_SPACE:
		*target = ' ';
		break;
	case SFM_PERIOD:
		*target = '.';
		break;
#ifdef MY_ABC_HERE
	 
	case UNI_DIVSLASH:
		*target = '/';
		break;
	case UNI_CRGRET:
		*target = '\r';
		break;
#endif  
	default:
		return false;
	}
	return true;
}

static int
cifs_mapchar(char *target, const __u16 *from, const struct nls_table *cp,
	     int maptype)
{
	int len = 1;
	__u16 src_char;

	src_char = *from;

	if ((maptype == SFM_MAP_UNI_RSVD) && convert_sfm_char(src_char, target))
		return len;
	else if ((maptype == SFU_MAP_UNI_RSVD) &&
		  convert_sfu_char(src_char, target))
		return len;

	len = cp->uni2char(src_char, target, NLS_MAX_CHARSET_SIZE);
	if (len <= 0)
		goto surrogate_pair;

	return len;

surrogate_pair:
	 
	if (strcmp(cp->charset, "utf8"))
		goto unknown;
	len = utf16s_to_utf8s(from, 3, UTF16_LITTLE_ENDIAN, target, 6);
	if (len <= 0)
		goto unknown;
	return len;

unknown:
	*target = '?';
	len = 1;
	return len;
}

int
cifs_from_utf16(char *to, const __le16 *from, int tolen, int fromlen,
		const struct nls_table *codepage, int map_type)
{
	int i, charlen, safelen;
	int outlen = 0;
	int nullsize = nls_nullsize(codepage);
	int fromwords = fromlen / 2;
	char tmp[NLS_MAX_CHARSET_SIZE];
	__u16 ftmp[3];		 

	safelen = tolen - (NLS_MAX_CHARSET_SIZE + nullsize);

	for (i = 0; i < fromwords; i++) {
		ftmp[0] = get_unaligned_le16(&from[i]);
		if (ftmp[0] == 0)
			break;
		if (i + 1 < fromwords)
			ftmp[1] = get_unaligned_le16(&from[i + 1]);
		else
			ftmp[1] = 0;
		if (i + 2 < fromwords)
			ftmp[2] = get_unaligned_le16(&from[i + 2]);
		else
			ftmp[2] = 0;

		if (outlen >= safelen) {
			charlen = cifs_mapchar(tmp, ftmp, codepage, map_type);
			if ((outlen + charlen) > (tolen - nullsize))
				break;
		}

		charlen = cifs_mapchar(&to[outlen], ftmp, codepage, map_type);
		outlen += charlen;

		if (charlen == 4)
			i++;
		else if (charlen >= 5)
			 
			i += 2;
	}

	for (i = 0; i < nullsize; i++)
		to[outlen++] = 0;

	return outlen;
}

#ifdef MY_ABC_HERE
int
cifs_strtoUTF16_NoSpecialChar(__le16 *to, const char *from, int len,
	      const struct nls_table *codepage)
{
	int charlen;
	int i;
	wchar_t wchar_to;  

	for (i = 0; len && *from; i++, from += charlen, len -= charlen) {
		charlen = codepage->char2uni(from, len, &wchar_to);
		if (charlen < 1) {
			cifs_dbg(VFS, "strtoUTF16: char2uni of 0x%x returned %d",
				*from, charlen);
			 
			wchar_to = 0x003f;
			charlen = 1;
		}
		put_unaligned_le16(wchar_to, &to[i]);
	}

	put_unaligned_le16(0, &to[i]);
	return i;
}
#endif  
 
int
cifs_strtoUTF16(__le16 *to, const char *from, int len,
	      const struct nls_table *codepage)
{
	int charlen;
	int i;
	wchar_t wchar_to;  

#ifdef MY_ABC_HERE
	 
#else
	 
	if (!strcmp(codepage->charset, "utf8")) {
		 
		i  = utf8s_to_utf16s(from, len, UTF16_LITTLE_ENDIAN,
				       (wchar_t *) to, len);

		if (i >= 0)
			goto success;
		 
	}
#endif  

	for (i = 0; len && *from; i++, from += charlen, len -= charlen) {
#ifdef MY_ABC_HERE
		if (0x0d == *from) {     
			to[i] = cpu_to_le16(0xf00d);
			charlen = 1;
		} else if (0x2a == *from) {      
			to[i] = cpu_to_le16(0xf02a);
			charlen = 1;
		} else if (0x2f == *from) {      
			to[i] = cpu_to_le16(0xf02f);
			charlen = 1;
		} else if (0x3c == *from) {      
			to[i] = cpu_to_le16(0xf03c);
			charlen = 1;
		} else if (0x3e == *from) {      
			to[i] = cpu_to_le16(0xf03e);
			charlen = 1;
		} else if (0x3f == *from) {      
			to[i] = cpu_to_le16(0xf03f);
			charlen = 1;
		} else if (0x7c== *from) {       
			to[i] = cpu_to_le16(0xf07c);
			charlen = 1;
		} else if (0x3a== *from) {       
			to[i] = cpu_to_le16(0xf022);
			charlen = 1;
		} else if (0x22== *from) {       
			to[i] = cpu_to_le16(0xf020);
			charlen = 1;
		} else {
#endif  
		charlen = codepage->char2uni(from, len, &wchar_to);
		if (charlen < 1) {
#ifdef MY_ABC_HERE
			 
#else
			cifs_dbg(VFS, "strtoUTF16: char2uni of 0x%x returned %d\n",
				 *from, charlen);
#endif  
			 
			wchar_to = 0x003f;
			charlen = 1;
		}
		put_unaligned_le16(wchar_to, &to[i]);
#ifdef MY_ABC_HERE
		}
#endif  
	}

#ifdef MY_ABC_HERE
	 
#else
success:
#endif  
	put_unaligned_le16(0, &to[i]);
	return i;
}

int
cifs_utf16_bytes(const __le16 *from, int maxbytes,
		const struct nls_table *codepage)
{
	int i;
	int charlen, outlen = 0;
	int maxwords = maxbytes / 2;
	char tmp[NLS_MAX_CHARSET_SIZE];
	__u16 ftmp[3];

	for (i = 0; i < maxwords; i++) {
		ftmp[0] = get_unaligned_le16(&from[i]);
		if (ftmp[0] == 0)
			break;
		if (i + 1 < maxwords)
			ftmp[1] = get_unaligned_le16(&from[i + 1]);
		else
			ftmp[1] = 0;
		if (i + 2 < maxwords)
			ftmp[2] = get_unaligned_le16(&from[i + 2]);
		else
			ftmp[2] = 0;

		charlen = cifs_mapchar(tmp, ftmp, codepage, NO_MAP_UNI_RSVD);
		outlen += charlen;
	}

	return outlen;
}

char *
cifs_strndup_from_utf16(const char *src, const int maxlen,
			const bool is_unicode, const struct nls_table *codepage)
{
	int len;
	char *dst;

	if (is_unicode) {
		len = cifs_utf16_bytes((__le16 *) src, maxlen, codepage);
		len += nls_nullsize(codepage);
		dst = kmalloc(len, GFP_KERNEL);
		if (!dst)
			return NULL;
		cifs_from_utf16(dst, (__le16 *) src, len, maxlen, codepage,
			       NO_MAP_UNI_RSVD);
	} else {
		len = strnlen(src, maxlen);
		len++;
		dst = kmalloc(len, GFP_KERNEL);
		if (!dst)
			return NULL;
		strlcpy(dst, src, len);
	}

	return dst;
}

static __le16 convert_to_sfu_char(char src_char)
{
	__le16 dest_char;

	switch (src_char) {
	case ':':
		dest_char = cpu_to_le16(UNI_COLON);
		break;
	case '*':
		dest_char = cpu_to_le16(UNI_ASTERISK);
		break;
	case '?':
		dest_char = cpu_to_le16(UNI_QUESTION);
		break;
	case '<':
		dest_char = cpu_to_le16(UNI_LESSTHAN);
		break;
	case '>':
		dest_char = cpu_to_le16(UNI_GRTRTHAN);
		break;
	case '|':
		dest_char = cpu_to_le16(UNI_PIPE);
		break;
#ifdef MY_ABC_HERE
	case '"':
		dest_char = cpu_to_le16(UNI_DQUOT);
		break;
	case '/':
		dest_char = cpu_to_le16(UNI_DIVSLASH);
		break;
	case '\r':
		dest_char = cpu_to_le16(UNI_CRGRET);
		break;
#endif  
	default:
		dest_char = 0;
	}

	return dest_char;
}

static __le16 convert_to_sfm_char(char src_char, bool end_of_string)
{
	__le16 dest_char;

	switch (src_char) {
	case ':':
		dest_char = cpu_to_le16(SFM_COLON);
		break;
	case '*':
		dest_char = cpu_to_le16(SFM_ASTERISK);
		break;
	case '?':
		dest_char = cpu_to_le16(SFM_QUESTION);
		break;
	case '<':
		dest_char = cpu_to_le16(SFM_LESSTHAN);
		break;
	case '>':
		dest_char = cpu_to_le16(SFM_GRTRTHAN);
		break;
	case '|':
		dest_char = cpu_to_le16(SFM_PIPE);
		break;
	case '.':
		if (end_of_string)
			dest_char = cpu_to_le16(SFM_PERIOD);
		else
			dest_char = 0;
		break;
	case ' ':
		if (end_of_string)
			dest_char = cpu_to_le16(SFM_SPACE);
		else
			dest_char = 0;
		break;
#ifdef MY_ABC_HERE
	 
	case '/':
		dest_char = cpu_to_le16(UNI_DIVSLASH);
		break;
	case '\r':
		dest_char = cpu_to_le16(UNI_CRGRET);
		break;
#endif  
	default:
		dest_char = 0;
	}

	return dest_char;
}

int
cifsConvertToUTF16(__le16 *target, const char *source, int srclen,
		 const struct nls_table *cp, int map_chars)
{
	int i, charlen;
	int j = 0;
	char src_char;
	__le16 dst_char;
	wchar_t tmp;
	wchar_t *wchar_to;	 
	int ret;
	unicode_t u;

	if (map_chars == NO_MAP_UNI_RSVD)
		return cifs_strtoUTF16(target, source, PATH_MAX, cp);

	wchar_to = kzalloc(6, GFP_KERNEL);

	for (i = 0; i < srclen; j++) {
		src_char = source[i];
		charlen = 1;

		if (src_char == 0)
			goto ctoUTF16_out;

		if (map_chars == SFU_MAP_UNI_RSVD)
			dst_char = convert_to_sfu_char(src_char);
		else if (map_chars == SFM_MAP_UNI_RSVD) {
			bool end_of_string;

			if (i == srclen - 1)
				end_of_string = true;
			else
				end_of_string = false;

			dst_char = convert_to_sfm_char(src_char, end_of_string);
		} else
			dst_char = 0;
		 
		if (dst_char == 0) {
			charlen = cp->char2uni(source + i, srclen - i, &tmp);
			dst_char = cpu_to_le16(tmp);

			if (charlen > 0)
				goto ctoUTF16;

			if (strcmp(cp->charset, "utf8") || !wchar_to)
				goto unknown;
			if (*(source + i) & 0x80) {
				charlen = utf8_to_utf32(source + i, 6, &u);
				if (charlen < 0)
					goto unknown;
			} else
				goto unknown;
			ret  = utf8s_to_utf16s(source + i, charlen,
					       UTF16_LITTLE_ENDIAN,
					       wchar_to, 6);
			if (ret < 0)
				goto unknown;

			i += charlen;
			dst_char = cpu_to_le16(*wchar_to);
			if (charlen <= 3)
				 
				put_unaligned(dst_char, &target[j]);
			else if (charlen == 4) {
				 
				put_unaligned(dst_char, &target[j]);
				dst_char = cpu_to_le16(*(wchar_to + 1));
				j++;
				put_unaligned(dst_char, &target[j]);
			} else if (charlen >= 5) {
				 
				put_unaligned(dst_char, &target[j]);
				dst_char = cpu_to_le16(*(wchar_to + 1));
				j++;
				put_unaligned(dst_char, &target[j]);
				dst_char = cpu_to_le16(*(wchar_to + 2));
				j++;
				put_unaligned(dst_char, &target[j]);
			}
			continue;

unknown:
			dst_char = cpu_to_le16(0x003f);
			charlen = 1;
		}

ctoUTF16:
		 
		i += charlen;
		put_unaligned(dst_char, &target[j]);
	}

ctoUTF16_out:
	put_unaligned(0, &target[j]);  
	kfree(wchar_to);
	return j;
}

#ifdef CONFIG_CIFS_SMB2
 
static int
cifs_local_to_utf16_bytes(const char *from, int len,
			  const struct nls_table *codepage)
{
	int charlen;
	int i;
	wchar_t wchar_to;

	for (i = 0; len && *from; i++, from += charlen, len -= charlen) {
		charlen = codepage->char2uni(from, len, &wchar_to);
		 
		if (charlen < 1)
			charlen = 1;
	}
	return 2 * i;  
}

__le16 *
cifs_strndup_to_utf16(const char *src, const int maxlen, int *utf16_len,
		      const struct nls_table *cp, int remap)
{
	int len;
	__le16 *dst;

	len = cifs_local_to_utf16_bytes(src, maxlen, cp);
	len += 2;  
	dst = kmalloc(len, GFP_KERNEL);
	if (!dst) {
		*utf16_len = 0;
		return NULL;
	}
	cifsConvertToUTF16(dst, src, strlen(src), cp, remap);
	*utf16_len = len;
	return dst;
}
#endif  
