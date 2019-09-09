#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef __LINUX_SND_SOC_H
#define __LINUX_SND_SOC_H

#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/types.h>
#include <linux/notifier.h>
#include <linux/workqueue.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#if defined(MY_ABC_HERE)
#else  
#include <linux/regmap.h>
#endif  
#include <linux/log2.h>
#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/compress_driver.h>
#include <sound/control.h>
#include <sound/ac97_codec.h>
#include <sound/soc-topology.h>

#define SOC_DOUBLE_VALUE(xreg, shift_left, shift_right, xmax, xinvert, xautodisable) \
	((unsigned long)&(struct soc_mixer_control) \
	{.reg = xreg, .rreg = xreg, .shift = shift_left, \
	.rshift = shift_right, .max = xmax, .platform_max = xmax, \
	.invert = xinvert, .autodisable = xautodisable})
#define SOC_DOUBLE_S_VALUE(xreg, shift_left, shift_right, xmin, xmax, xsign_bit, xinvert, xautodisable) \
	((unsigned long)&(struct soc_mixer_control) \
	{.reg = xreg, .rreg = xreg, .shift = shift_left, \
	.rshift = shift_right, .min = xmin, .max = xmax, .platform_max = xmax, \
	.sign_bit = xsign_bit, .invert = xinvert, .autodisable = xautodisable})
#define SOC_SINGLE_VALUE(xreg, xshift, xmax, xinvert, xautodisable) \
	SOC_DOUBLE_VALUE(xreg, xshift, xshift, xmax, xinvert, xautodisable)
#define SOC_SINGLE_VALUE_EXT(xreg, xmax, xinvert) \
	((unsigned long)&(struct soc_mixer_control) \
	{.reg = xreg, .max = xmax, .platform_max = xmax, .invert = xinvert})
#define SOC_DOUBLE_R_VALUE(xlreg, xrreg, xshift, xmax, xinvert) \
	((unsigned long)&(struct soc_mixer_control) \
	{.reg = xlreg, .rreg = xrreg, .shift = xshift, .rshift = xshift, \
	.max = xmax, .platform_max = xmax, .invert = xinvert})
#define SOC_DOUBLE_R_S_VALUE(xlreg, xrreg, xshift, xmin, xmax, xsign_bit, xinvert) \
	((unsigned long)&(struct soc_mixer_control) \
	{.reg = xlreg, .rreg = xrreg, .shift = xshift, .rshift = xshift, \
	.max = xmax, .min = xmin, .platform_max = xmax, .sign_bit = xsign_bit, \
	.invert = xinvert})
#define SOC_DOUBLE_R_RANGE_VALUE(xlreg, xrreg, xshift, xmin, xmax, xinvert) \
	((unsigned long)&(struct soc_mixer_control) \
	{.reg = xlreg, .rreg = xrreg, .shift = xshift, .rshift = xshift, \
	.min = xmin, .max = xmax, .platform_max = xmax, .invert = xinvert})
#define SOC_SINGLE(xname, reg, shift, max, invert) \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = xname, \
	.info = snd_soc_info_volsw, .get = snd_soc_get_volsw,\
	.put = snd_soc_put_volsw, \
	.private_value = SOC_SINGLE_VALUE(reg, shift, max, invert, 0) }
#define SOC_SINGLE_RANGE(xname, xreg, xshift, xmin, xmax, xinvert) \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = (xname),\
	.info = snd_soc_info_volsw_range, .get = snd_soc_get_volsw_range, \
	.put = snd_soc_put_volsw_range, \
	.private_value = (unsigned long)&(struct soc_mixer_control) \
		{.reg = xreg, .rreg = xreg, .shift = xshift, \
		 .rshift = xshift,  .min = xmin, .max = xmax, \
		 .platform_max = xmax, .invert = xinvert} }
#define SOC_SINGLE_TLV(xname, reg, shift, max, invert, tlv_array) \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = xname, \
	.access = SNDRV_CTL_ELEM_ACCESS_TLV_READ |\
		 SNDRV_CTL_ELEM_ACCESS_READWRITE,\
	.tlv.p = (tlv_array), \
	.info = snd_soc_info_volsw, .get = snd_soc_get_volsw,\
	.put = snd_soc_put_volsw, \
	.private_value = SOC_SINGLE_VALUE(reg, shift, max, invert, 0) }
#define SOC_SINGLE_SX_TLV(xname, xreg, xshift, xmin, xmax, tlv_array) \
{       .iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = xname, \
	.access = SNDRV_CTL_ELEM_ACCESS_TLV_READ | \
	SNDRV_CTL_ELEM_ACCESS_READWRITE, \
	.tlv.p  = (tlv_array),\
	.info = snd_soc_info_volsw_sx, \
	.get = snd_soc_get_volsw_sx,\
	.put = snd_soc_put_volsw_sx, \
	.private_value = (unsigned long)&(struct soc_mixer_control) \
		{.reg = xreg, .rreg = xreg, \
		.shift = xshift, .rshift = xshift, \
		.max = xmax, .min = xmin} }
#define SOC_SINGLE_RANGE_TLV(xname, xreg, xshift, xmin, xmax, xinvert, tlv_array) \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = (xname),\
	.access = SNDRV_CTL_ELEM_ACCESS_TLV_READ |\
		 SNDRV_CTL_ELEM_ACCESS_READWRITE,\
	.tlv.p = (tlv_array), \
	.info = snd_soc_info_volsw_range, \
	.get = snd_soc_get_volsw_range, .put = snd_soc_put_volsw_range, \
	.private_value = (unsigned long)&(struct soc_mixer_control) \
		{.reg = xreg, .rreg = xreg, .shift = xshift, \
		 .rshift = xshift, .min = xmin, .max = xmax, \
		 .platform_max = xmax, .invert = xinvert} }
#define SOC_DOUBLE(xname, reg, shift_left, shift_right, max, invert) \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = (xname),\
	.info = snd_soc_info_volsw, .get = snd_soc_get_volsw, \
	.put = snd_soc_put_volsw, \
	.private_value = SOC_DOUBLE_VALUE(reg, shift_left, shift_right, \
					  max, invert, 0) }
#define SOC_DOUBLE_R(xname, reg_left, reg_right, xshift, xmax, xinvert) \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = (xname), \
	.info = snd_soc_info_volsw, \
	.get = snd_soc_get_volsw, .put = snd_soc_put_volsw, \
	.private_value = SOC_DOUBLE_R_VALUE(reg_left, reg_right, xshift, \
					    xmax, xinvert) }
#define SOC_DOUBLE_R_RANGE(xname, reg_left, reg_right, xshift, xmin, \
			   xmax, xinvert)		\
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = (xname),\
	.info = snd_soc_info_volsw_range, \
	.get = snd_soc_get_volsw_range, .put = snd_soc_put_volsw_range, \
	.private_value = SOC_DOUBLE_R_RANGE_VALUE(reg_left, reg_right, \
					    xshift, xmin, xmax, xinvert) }
#define SOC_DOUBLE_TLV(xname, reg, shift_left, shift_right, max, invert, tlv_array) \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = (xname),\
	.access = SNDRV_CTL_ELEM_ACCESS_TLV_READ |\
		 SNDRV_CTL_ELEM_ACCESS_READWRITE,\
	.tlv.p = (tlv_array), \
	.info = snd_soc_info_volsw, .get = snd_soc_get_volsw, \
	.put = snd_soc_put_volsw, \
	.private_value = SOC_DOUBLE_VALUE(reg, shift_left, shift_right, \
					  max, invert, 0) }
#define SOC_DOUBLE_R_TLV(xname, reg_left, reg_right, xshift, xmax, xinvert, tlv_array) \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = (xname),\
	.access = SNDRV_CTL_ELEM_ACCESS_TLV_READ |\
		 SNDRV_CTL_ELEM_ACCESS_READWRITE,\
	.tlv.p = (tlv_array), \
	.info = snd_soc_info_volsw, \
	.get = snd_soc_get_volsw, .put = snd_soc_put_volsw, \
	.private_value = SOC_DOUBLE_R_VALUE(reg_left, reg_right, xshift, \
					    xmax, xinvert) }
#define SOC_DOUBLE_R_RANGE_TLV(xname, reg_left, reg_right, xshift, xmin, \
			       xmax, xinvert, tlv_array)		\
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = (xname),\
	.access = SNDRV_CTL_ELEM_ACCESS_TLV_READ |\
		 SNDRV_CTL_ELEM_ACCESS_READWRITE,\
	.tlv.p = (tlv_array), \
	.info = snd_soc_info_volsw_range, \
	.get = snd_soc_get_volsw_range, .put = snd_soc_put_volsw_range, \
	.private_value = SOC_DOUBLE_R_RANGE_VALUE(reg_left, reg_right, \
					    xshift, xmin, xmax, xinvert) }
#define SOC_DOUBLE_R_SX_TLV(xname, xreg, xrreg, xshift, xmin, xmax, tlv_array) \
{       .iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = (xname), \
	.access = SNDRV_CTL_ELEM_ACCESS_TLV_READ | \
	SNDRV_CTL_ELEM_ACCESS_READWRITE, \
	.tlv.p  = (tlv_array), \
	.info = snd_soc_info_volsw_sx, \
	.get = snd_soc_get_volsw_sx, \
	.put = snd_soc_put_volsw_sx, \
	.private_value = (unsigned long)&(struct soc_mixer_control) \
		{.reg = xreg, .rreg = xrreg, \
		.shift = xshift, .rshift = xshift, \
		.max = xmax, .min = xmin} }
#define SOC_DOUBLE_R_S_TLV(xname, reg_left, reg_right, xshift, xmin, xmax, xsign_bit, xinvert, tlv_array) \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = (xname),\
	.access = SNDRV_CTL_ELEM_ACCESS_TLV_READ |\
		 SNDRV_CTL_ELEM_ACCESS_READWRITE,\
	.tlv.p = (tlv_array), \
	.info = snd_soc_info_volsw, \
	.get = snd_soc_get_volsw, .put = snd_soc_put_volsw, \
	.private_value = SOC_DOUBLE_R_S_VALUE(reg_left, reg_right, xshift, \
					    xmin, xmax, xsign_bit, xinvert) }
#define SOC_DOUBLE_S8_TLV(xname, xreg, xmin, xmax, tlv_array) \
{	.iface  = SNDRV_CTL_ELEM_IFACE_MIXER, .name = (xname), \
	.access = SNDRV_CTL_ELEM_ACCESS_TLV_READ | \
		  SNDRV_CTL_ELEM_ACCESS_READWRITE, \
	.tlv.p  = (tlv_array), \
	.info = snd_soc_info_volsw, .get = snd_soc_get_volsw,\
	.put = snd_soc_put_volsw, \
	.private_value = SOC_DOUBLE_S_VALUE(xreg, 0, 8, xmin, xmax, 7, 0, 0) }
#define SOC_ENUM_DOUBLE(xreg, xshift_l, xshift_r, xitems, xtexts) \
{	.reg = xreg, .shift_l = xshift_l, .shift_r = xshift_r, \
	.items = xitems, .texts = xtexts, \
	.mask = xitems ? roundup_pow_of_two(xitems) - 1 : 0}
#define SOC_ENUM_SINGLE(xreg, xshift, xitems, xtexts) \
	SOC_ENUM_DOUBLE(xreg, xshift, xshift, xitems, xtexts)
#define SOC_ENUM_SINGLE_EXT(xitems, xtexts) \
{	.items = xitems, .texts = xtexts }
#define SOC_VALUE_ENUM_DOUBLE(xreg, xshift_l, xshift_r, xmask, xitems, xtexts, xvalues) \
{	.reg = xreg, .shift_l = xshift_l, .shift_r = xshift_r, \
	.mask = xmask, .items = xitems, .texts = xtexts, .values = xvalues}
#define SOC_VALUE_ENUM_SINGLE(xreg, xshift, xmask, xitems, xtexts, xvalues) \
	SOC_VALUE_ENUM_DOUBLE(xreg, xshift, xshift, xmask, xitems, xtexts, xvalues)
#define SOC_VALUE_ENUM_SINGLE_AUTODISABLE(xreg, xshift, xmask, xitems, xtexts, xvalues) \
{	.reg = xreg, .shift_l = xshift, .shift_r = xshift, \
	.mask = xmask, .items = xitems, .texts = xtexts, \
	.values = xvalues, .autodisable = 1}
#define SOC_ENUM_SINGLE_VIRT(xitems, xtexts) \
	SOC_ENUM_SINGLE(SND_SOC_NOPM, 0, xitems, xtexts)
#define SOC_ENUM(xname, xenum) \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = xname,\
	.info = snd_soc_info_enum_double, \
	.get = snd_soc_get_enum_double, .put = snd_soc_put_enum_double, \
	.private_value = (unsigned long)&xenum }
#define SOC_SINGLE_EXT(xname, xreg, xshift, xmax, xinvert,\
	 xhandler_get, xhandler_put) \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = xname, \
	.info = snd_soc_info_volsw, \
	.get = xhandler_get, .put = xhandler_put, \
	.private_value = SOC_SINGLE_VALUE(xreg, xshift, xmax, xinvert, 0) }
#define SOC_DOUBLE_EXT(xname, reg, shift_left, shift_right, max, invert,\
	 xhandler_get, xhandler_put) \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = (xname),\
	.info = snd_soc_info_volsw, \
	.get = xhandler_get, .put = xhandler_put, \
	.private_value = \
		SOC_DOUBLE_VALUE(reg, shift_left, shift_right, max, invert, 0) }
#define SOC_DOUBLE_R_EXT(xname, reg_left, reg_right, xshift, xmax, xinvert,\
	 xhandler_get, xhandler_put) \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = (xname), \
	.info = snd_soc_info_volsw, \
	.get = xhandler_get, .put = xhandler_put, \
	.private_value = SOC_DOUBLE_R_VALUE(reg_left, reg_right, xshift, \
					    xmax, xinvert) }
#define SOC_SINGLE_EXT_TLV(xname, xreg, xshift, xmax, xinvert,\
	 xhandler_get, xhandler_put, tlv_array) \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = xname, \
	.access = SNDRV_CTL_ELEM_ACCESS_TLV_READ |\
		 SNDRV_CTL_ELEM_ACCESS_READWRITE,\
	.tlv.p = (tlv_array), \
	.info = snd_soc_info_volsw, \
	.get = xhandler_get, .put = xhandler_put, \
	.private_value = SOC_SINGLE_VALUE(xreg, xshift, xmax, xinvert, 0) }
#define SOC_SINGLE_RANGE_EXT_TLV(xname, xreg, xshift, xmin, xmax, xinvert, \
				 xhandler_get, xhandler_put, tlv_array) \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = (xname),\
	.access = SNDRV_CTL_ELEM_ACCESS_TLV_READ |\
		 SNDRV_CTL_ELEM_ACCESS_READWRITE,\
	.tlv.p = (tlv_array), \
	.info = snd_soc_info_volsw_range, \
	.get = xhandler_get, .put = xhandler_put, \
	.private_value = (unsigned long)&(struct soc_mixer_control) \
		{.reg = xreg, .rreg = xreg, .shift = xshift, \
		 .rshift = xshift, .min = xmin, .max = xmax, \
		 .platform_max = xmax, .invert = xinvert} }
#define SOC_DOUBLE_EXT_TLV(xname, xreg, shift_left, shift_right, xmax, xinvert,\
	 xhandler_get, xhandler_put, tlv_array) \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = (xname), \
	.access = SNDRV_CTL_ELEM_ACCESS_TLV_READ | \
		 SNDRV_CTL_ELEM_ACCESS_READWRITE, \
	.tlv.p = (tlv_array), \
	.info = snd_soc_info_volsw, \
	.get = xhandler_get, .put = xhandler_put, \
	.private_value = SOC_DOUBLE_VALUE(xreg, shift_left, shift_right, \
					  xmax, xinvert, 0) }
#define SOC_DOUBLE_R_EXT_TLV(xname, reg_left, reg_right, xshift, xmax, xinvert,\
	 xhandler_get, xhandler_put, tlv_array) \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = (xname), \
	.access = SNDRV_CTL_ELEM_ACCESS_TLV_READ | \
		 SNDRV_CTL_ELEM_ACCESS_READWRITE, \
	.tlv.p = (tlv_array), \
	.info = snd_soc_info_volsw, \
	.get = xhandler_get, .put = xhandler_put, \
	.private_value = SOC_DOUBLE_R_VALUE(reg_left, reg_right, xshift, \
					    xmax, xinvert) }
#define SOC_SINGLE_BOOL_EXT(xname, xdata, xhandler_get, xhandler_put) \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = xname, \
	.info = snd_soc_info_bool_ext, \
	.get = xhandler_get, .put = xhandler_put, \
	.private_value = xdata }
#define SOC_ENUM_EXT(xname, xenum, xhandler_get, xhandler_put) \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = xname, \
	.info = snd_soc_info_enum_double, \
	.get = xhandler_get, .put = xhandler_put, \
	.private_value = (unsigned long)&xenum }
#define SOC_VALUE_ENUM_EXT(xname, xenum, xhandler_get, xhandler_put) \
	SOC_ENUM_EXT(xname, xenum, xhandler_get, xhandler_put)

#define SND_SOC_BYTES(xname, xbase, xregs)		      \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = xname,   \
	.info = snd_soc_bytes_info, .get = snd_soc_bytes_get, \
	.put = snd_soc_bytes_put, .private_value =	      \
		((unsigned long)&(struct soc_bytes)           \
		{.base = xbase, .num_regs = xregs }) }

#define SND_SOC_BYTES_MASK(xname, xbase, xregs, xmask)	      \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = xname,   \
	.info = snd_soc_bytes_info, .get = snd_soc_bytes_get, \
	.put = snd_soc_bytes_put, .private_value =	      \
		((unsigned long)&(struct soc_bytes)           \
		{.base = xbase, .num_regs = xregs,	      \
		 .mask = xmask }) }

#define SND_SOC_BYTES_EXT(xname, xcount, xhandler_get, xhandler_put) \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = xname, \
	.info = snd_soc_bytes_info_ext, \
	.get = xhandler_get, .put = xhandler_put, \
	.private_value = (unsigned long)&(struct soc_bytes_ext) \
		{.max = xcount} }
#define SND_SOC_BYTES_TLV(xname, xcount, xhandler_get, xhandler_put) \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = xname, \
	.access = SNDRV_CTL_ELEM_ACCESS_TLV_READWRITE | \
		  SNDRV_CTL_ELEM_ACCESS_TLV_CALLBACK, \
	.tlv.c = (snd_soc_bytes_tlv_callback), \
	.info = snd_soc_bytes_info_ext, \
	.private_value = (unsigned long)&(struct soc_bytes_ext) \
		{.max = xcount, .get = xhandler_get, .put = xhandler_put, } }
#define SOC_SINGLE_XR_SX(xname, xregbase, xregcount, xnbits, \
		xmin, xmax, xinvert) \
{	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = (xname), \
	.info = snd_soc_info_xr_sx, .get = snd_soc_get_xr_sx, \
	.put = snd_soc_put_xr_sx, \
	.private_value = (unsigned long)&(struct soc_mreg_control) \
		{.regbase = xregbase, .regcount = xregcount, .nbits = xnbits, \
		.invert = xinvert, .min = xmin, .max = xmax} }

#define SOC_SINGLE_STROBE(xname, xreg, xshift, xinvert) \
	SOC_SINGLE_EXT(xname, xreg, xshift, 1, xinvert, \
		snd_soc_get_strobe, snd_soc_put_strobe)

#define SOC_ENUM_DOUBLE_DECL(name, xreg, xshift_l, xshift_r, xtexts) \
	const struct soc_enum name = SOC_ENUM_DOUBLE(xreg, xshift_l, xshift_r, \
						ARRAY_SIZE(xtexts), xtexts)
#define SOC_ENUM_SINGLE_DECL(name, xreg, xshift, xtexts) \
	SOC_ENUM_DOUBLE_DECL(name, xreg, xshift, xshift, xtexts)
#define SOC_ENUM_SINGLE_EXT_DECL(name, xtexts) \
	const struct soc_enum name = SOC_ENUM_SINGLE_EXT(ARRAY_SIZE(xtexts), xtexts)
#define SOC_VALUE_ENUM_DOUBLE_DECL(name, xreg, xshift_l, xshift_r, xmask, xtexts, xvalues) \
	const struct soc_enum name = SOC_VALUE_ENUM_DOUBLE(xreg, xshift_l, xshift_r, xmask, \
							ARRAY_SIZE(xtexts), xtexts, xvalues)
#define SOC_VALUE_ENUM_SINGLE_DECL(name, xreg, xshift, xmask, xtexts, xvalues) \
	SOC_VALUE_ENUM_DOUBLE_DECL(name, xreg, xshift, xshift, xmask, xtexts, xvalues)

#define SOC_VALUE_ENUM_SINGLE_AUTODISABLE_DECL(name, xreg, xshift, xmask, xtexts, xvalues) \
	const struct soc_enum name = SOC_VALUE_ENUM_SINGLE_AUTODISABLE(xreg, \
		xshift, xmask, ARRAY_SIZE(xtexts), xtexts, xvalues)

#define SOC_ENUM_SINGLE_VIRT_DECL(name, xtexts) \
	const struct soc_enum name = SOC_ENUM_SINGLE_VIRT(ARRAY_SIZE(xtexts), xtexts)

#define SND_SOC_COMP_ORDER_FIRST		-2
#define SND_SOC_COMP_ORDER_EARLY		-1
#define SND_SOC_COMP_ORDER_NORMAL		0
#define SND_SOC_COMP_ORDER_LATE		1
#define SND_SOC_COMP_ORDER_LAST		2

enum snd_soc_bias_level {
	SND_SOC_BIAS_OFF = 0,
	SND_SOC_BIAS_STANDBY = 1,
	SND_SOC_BIAS_PREPARE = 2,
	SND_SOC_BIAS_ON = 3,
};

struct device_node;
struct snd_jack;
struct snd_soc_card;
struct snd_soc_pcm_stream;
struct snd_soc_ops;
struct snd_soc_pcm_runtime;
struct snd_soc_dai;
struct snd_soc_dai_driver;
struct snd_soc_platform;
struct snd_soc_dai_link;
struct snd_soc_platform_driver;
struct snd_soc_codec;
struct snd_soc_codec_driver;
struct snd_soc_component;
struct snd_soc_component_driver;
struct soc_enum;
struct snd_soc_jack;
struct snd_soc_jack_zone;
struct snd_soc_jack_pin;
#include <sound/soc-dapm.h>
#include <sound/soc-dpcm.h>

struct snd_soc_jack_gpio;

typedef int (*hw_write_t)(void *,const char* ,int);

enum snd_soc_pcm_subclass {
	SND_SOC_PCM_CLASS_PCM	= 0,
	SND_SOC_PCM_CLASS_BE	= 1,
};

enum snd_soc_card_subclass {
	SND_SOC_CARD_CLASS_INIT		= 0,
	SND_SOC_CARD_CLASS_RUNTIME	= 1,
};

int snd_soc_codec_set_sysclk(struct snd_soc_codec *codec, int clk_id,
			     int source, unsigned int freq, int dir);
int snd_soc_codec_set_pll(struct snd_soc_codec *codec, int pll_id, int source,
			  unsigned int freq_in, unsigned int freq_out);

int snd_soc_register_card(struct snd_soc_card *card);
int snd_soc_unregister_card(struct snd_soc_card *card);
int devm_snd_soc_register_card(struct device *dev, struct snd_soc_card *card);
#ifdef CONFIG_PM_SLEEP
int snd_soc_suspend(struct device *dev);
int snd_soc_resume(struct device *dev);
#else
static inline int snd_soc_suspend(struct device *dev)
{
	return 0;
}

static inline int snd_soc_resume(struct device *dev)
{
	return 0;
}
#endif
int snd_soc_poweroff(struct device *dev);
int snd_soc_register_platform(struct device *dev,
		const struct snd_soc_platform_driver *platform_drv);
int devm_snd_soc_register_platform(struct device *dev,
		const struct snd_soc_platform_driver *platform_drv);
void snd_soc_unregister_platform(struct device *dev);
int snd_soc_add_platform(struct device *dev, struct snd_soc_platform *platform,
		const struct snd_soc_platform_driver *platform_drv);
void snd_soc_remove_platform(struct snd_soc_platform *platform);
struct snd_soc_platform *snd_soc_lookup_platform(struct device *dev);
int snd_soc_register_codec(struct device *dev,
		const struct snd_soc_codec_driver *codec_drv,
		struct snd_soc_dai_driver *dai_drv, int num_dai);
void snd_soc_unregister_codec(struct device *dev);
int snd_soc_register_component(struct device *dev,
			 const struct snd_soc_component_driver *cmpnt_drv,
			 struct snd_soc_dai_driver *dai_drv, int num_dai);
int devm_snd_soc_register_component(struct device *dev,
			 const struct snd_soc_component_driver *cmpnt_drv,
			 struct snd_soc_dai_driver *dai_drv, int num_dai);
void snd_soc_unregister_component(struct device *dev);
int snd_soc_cache_init(struct snd_soc_codec *codec);
int snd_soc_cache_exit(struct snd_soc_codec *codec);

int snd_soc_platform_read(struct snd_soc_platform *platform,
					unsigned int reg);
int snd_soc_platform_write(struct snd_soc_platform *platform,
					unsigned int reg, unsigned int val);
int soc_new_pcm(struct snd_soc_pcm_runtime *rtd, int num);
#ifdef CONFIG_SND_SOC_COMPRESS
int snd_soc_new_compress(struct snd_soc_pcm_runtime *rtd, int num);
#endif

struct snd_pcm_substream *snd_soc_get_dai_substream(struct snd_soc_card *card,
		const char *dai_link, int stream);
struct snd_soc_pcm_runtime *snd_soc_get_pcm_runtime(struct snd_soc_card *card,
		const char *dai_link);

bool snd_soc_runtime_ignore_pmdown_time(struct snd_soc_pcm_runtime *rtd);
void snd_soc_runtime_activate(struct snd_soc_pcm_runtime *rtd, int stream);
void snd_soc_runtime_deactivate(struct snd_soc_pcm_runtime *rtd, int stream);

int snd_soc_runtime_set_dai_fmt(struct snd_soc_pcm_runtime *rtd,
	unsigned int dai_fmt);

int snd_soc_calc_frame_size(int sample_size, int channels, int tdm_slots);
int snd_soc_params_to_frame_size(struct snd_pcm_hw_params *params);
int snd_soc_calc_bclk(int fs, int sample_size, int channels, int tdm_slots);
int snd_soc_params_to_bclk(struct snd_pcm_hw_params *parms);

int snd_soc_set_runtime_hwparams(struct snd_pcm_substream *substream,
	const struct snd_pcm_hardware *hw);

int snd_soc_platform_trigger(struct snd_pcm_substream *substream,
		int cmd, struct snd_soc_platform *platform);

int soc_dai_hw_params(struct snd_pcm_substream *substream,
		      struct snd_pcm_hw_params *params,
		      struct snd_soc_dai *dai);

int snd_soc_card_jack_new(struct snd_soc_card *card, const char *id, int type,
	struct snd_soc_jack *jack, struct snd_soc_jack_pin *pins,
	unsigned int num_pins);

void snd_soc_jack_report(struct snd_soc_jack *jack, int status, int mask);
int snd_soc_jack_add_pins(struct snd_soc_jack *jack, int count,
			  struct snd_soc_jack_pin *pins);
void snd_soc_jack_notifier_register(struct snd_soc_jack *jack,
				    struct notifier_block *nb);
void snd_soc_jack_notifier_unregister(struct snd_soc_jack *jack,
				      struct notifier_block *nb);
int snd_soc_jack_add_zones(struct snd_soc_jack *jack, int count,
			  struct snd_soc_jack_zone *zones);
int snd_soc_jack_get_type(struct snd_soc_jack *jack, int micbias_voltage);
#ifdef CONFIG_GPIOLIB
int snd_soc_jack_add_gpios(struct snd_soc_jack *jack, int count,
			struct snd_soc_jack_gpio *gpios);
int snd_soc_jack_add_gpiods(struct device *gpiod_dev,
			    struct snd_soc_jack *jack,
			    int count, struct snd_soc_jack_gpio *gpios);
void snd_soc_jack_free_gpios(struct snd_soc_jack *jack, int count,
			struct snd_soc_jack_gpio *gpios);
#else
static inline int snd_soc_jack_add_gpios(struct snd_soc_jack *jack, int count,
					 struct snd_soc_jack_gpio *gpios)
{
	return 0;
}

static inline int snd_soc_jack_add_gpiods(struct device *gpiod_dev,
					  struct snd_soc_jack *jack,
					  int count,
					  struct snd_soc_jack_gpio *gpios)
{
	return 0;
}

static inline void snd_soc_jack_free_gpios(struct snd_soc_jack *jack, int count,
					   struct snd_soc_jack_gpio *gpios)
{
}
#endif

int snd_soc_update_bits(struct snd_soc_codec *codec, unsigned int reg,
				unsigned int mask, unsigned int value);
int snd_soc_update_bits_locked(struct snd_soc_codec *codec,
			       unsigned int reg, unsigned int mask,
			       unsigned int value);
int snd_soc_test_bits(struct snd_soc_codec *codec, unsigned int reg,
				unsigned int mask, unsigned int value);

#ifdef CONFIG_SND_SOC_AC97_BUS
struct snd_ac97 *snd_soc_alloc_ac97_codec(struct snd_soc_codec *codec);
struct snd_ac97 *snd_soc_new_ac97_codec(struct snd_soc_codec *codec,
	unsigned int id, unsigned int id_mask);
void snd_soc_free_ac97_codec(struct snd_ac97 *ac97);

int snd_soc_set_ac97_ops(struct snd_ac97_bus_ops *ops);
int snd_soc_set_ac97_ops_of_reset(struct snd_ac97_bus_ops *ops,
		struct platform_device *pdev);

extern struct snd_ac97_bus_ops *soc_ac97_ops;
#else
static inline int snd_soc_set_ac97_ops_of_reset(struct snd_ac97_bus_ops *ops,
	struct platform_device *pdev)
{
	return 0;
}

static inline int snd_soc_set_ac97_ops(struct snd_ac97_bus_ops *ops)
{
	return 0;
}
#endif

struct snd_kcontrol *snd_soc_cnew(const struct snd_kcontrol_new *_template,
				  void *data, const char *long_name,
				  const char *prefix);
struct snd_kcontrol *snd_soc_card_get_kcontrol(struct snd_soc_card *soc_card,
					       const char *name);
int snd_soc_add_component_controls(struct snd_soc_component *component,
	const struct snd_kcontrol_new *controls, unsigned int num_controls);
int snd_soc_add_codec_controls(struct snd_soc_codec *codec,
	const struct snd_kcontrol_new *controls, unsigned int num_controls);
int snd_soc_add_platform_controls(struct snd_soc_platform *platform,
	const struct snd_kcontrol_new *controls, unsigned int num_controls);
int snd_soc_add_card_controls(struct snd_soc_card *soc_card,
	const struct snd_kcontrol_new *controls, int num_controls);
int snd_soc_add_dai_controls(struct snd_soc_dai *dai,
	const struct snd_kcontrol_new *controls, int num_controls);
int snd_soc_info_enum_double(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_info *uinfo);
int snd_soc_get_enum_double(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol);
int snd_soc_put_enum_double(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol);
int snd_soc_info_volsw(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_info *uinfo);
int snd_soc_info_volsw_sx(struct snd_kcontrol *kcontrol,
			  struct snd_ctl_elem_info *uinfo);
#define snd_soc_info_bool_ext		snd_ctl_boolean_mono_info
int snd_soc_get_volsw(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol);
int snd_soc_put_volsw(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol);
#define snd_soc_get_volsw_2r snd_soc_get_volsw
#define snd_soc_put_volsw_2r snd_soc_put_volsw
int snd_soc_get_volsw_sx(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol);
int snd_soc_put_volsw_sx(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol);
int snd_soc_info_volsw_range(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_info *uinfo);
int snd_soc_put_volsw_range(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol);
int snd_soc_get_volsw_range(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol);
int snd_soc_limit_volume(struct snd_soc_card *card,
	const char *name, int max);
int snd_soc_bytes_info(struct snd_kcontrol *kcontrol,
		       struct snd_ctl_elem_info *uinfo);
int snd_soc_bytes_get(struct snd_kcontrol *kcontrol,
		      struct snd_ctl_elem_value *ucontrol);
int snd_soc_bytes_put(struct snd_kcontrol *kcontrol,
		      struct snd_ctl_elem_value *ucontrol);
int snd_soc_bytes_info_ext(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_info *ucontrol);
int snd_soc_bytes_tlv_callback(struct snd_kcontrol *kcontrol, int op_flag,
	unsigned int size, unsigned int __user *tlv);
int snd_soc_info_xr_sx(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_info *uinfo);
int snd_soc_get_xr_sx(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol);
int snd_soc_put_xr_sx(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol);
int snd_soc_get_strobe(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol);
int snd_soc_put_strobe(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol);

struct snd_soc_jack_pin {
	struct list_head list;
	const char *pin;
	int mask;
	bool invert;
};

struct snd_soc_jack_zone {
	unsigned int min_mv;
	unsigned int max_mv;
	unsigned int jack_type;
	unsigned int debounce_time;
	struct list_head list;
};

struct snd_soc_jack_gpio {
	unsigned int gpio;
	unsigned int idx;
	struct device *gpiod_dev;
	const char *name;
	int report;
	int invert;
	int debounce_time;
	bool wake;

	struct snd_soc_jack *jack;
	struct delayed_work work;
	struct gpio_desc *desc;

	void *data;
	 
	int (*jack_status_check)(void *data);
};

struct snd_soc_jack {
	struct mutex mutex;
	struct snd_jack *jack;
	struct snd_soc_card *card;
	struct list_head pins;
	int status;
	struct blocking_notifier_head notifier;
	struct list_head jack_zones;
};

struct snd_soc_pcm_stream {
	const char *stream_name;
	u64 formats;			 
	unsigned int rates;		 
	unsigned int rate_min;		 
	unsigned int rate_max;		 
	unsigned int channels_min;	 
	unsigned int channels_max;	 
	unsigned int sig_bits;		 
};

struct snd_soc_ops {
	int (*startup)(struct snd_pcm_substream *);
	void (*shutdown)(struct snd_pcm_substream *);
	int (*hw_params)(struct snd_pcm_substream *, struct snd_pcm_hw_params *);
	int (*hw_free)(struct snd_pcm_substream *);
	int (*prepare)(struct snd_pcm_substream *);
	int (*trigger)(struct snd_pcm_substream *, int);
};

struct snd_soc_compr_ops {
	int (*startup)(struct snd_compr_stream *);
	void (*shutdown)(struct snd_compr_stream *);
	int (*set_params)(struct snd_compr_stream *);
	int (*trigger)(struct snd_compr_stream *);
};

struct snd_soc_component_driver {
	const char *name;

	const struct snd_kcontrol_new *controls;
	unsigned int num_controls;
	const struct snd_soc_dapm_widget *dapm_widgets;
	unsigned int num_dapm_widgets;
	const struct snd_soc_dapm_route *dapm_routes;
	unsigned int num_dapm_routes;

	int (*probe)(struct snd_soc_component *);
	void (*remove)(struct snd_soc_component *);

	int (*of_xlate_dai_name)(struct snd_soc_component *component,
				 struct of_phandle_args *args,
				 const char **dai_name);
	void (*seq_notifier)(struct snd_soc_component *, enum snd_soc_dapm_type,
		int subseq);
	int (*stream_event)(struct snd_soc_component *, int event);

	int probe_order;
	int remove_order;
};

struct snd_soc_component {
	const char *name;
	int id;
	const char *name_prefix;
	struct device *dev;
	struct snd_soc_card *card;

	unsigned int active;

	unsigned int ignore_pmdown_time:1;  
	unsigned int registered_as_component:1;

	struct list_head list;

	struct snd_soc_dai_driver *dai_drv;
	int num_dai;

	const struct snd_soc_component_driver *driver;

	struct list_head dai_list;

	int (*read)(struct snd_soc_component *, unsigned int, unsigned int *);
	int (*write)(struct snd_soc_component *, unsigned int, unsigned int);

	struct regmap *regmap;
	int val_bytes;

	struct mutex io_mutex;

	struct list_head dobj_list;

#ifdef CONFIG_DEBUG_FS
	struct dentry *debugfs_root;
#endif

	struct snd_soc_dapm_context dapm;

	const struct snd_kcontrol_new *controls;
	unsigned int num_controls;
	const struct snd_soc_dapm_widget *dapm_widgets;
	unsigned int num_dapm_widgets;
	const struct snd_soc_dapm_route *dapm_routes;
	unsigned int num_dapm_routes;
	struct snd_soc_codec *codec;

	int (*probe)(struct snd_soc_component *);
	void (*remove)(struct snd_soc_component *);

#ifdef CONFIG_DEBUG_FS
	void (*init_debugfs)(struct snd_soc_component *component);
	const char *debugfs_prefix;
#endif
};

struct snd_soc_codec {
	struct device *dev;
	const struct snd_soc_codec_driver *driver;

	struct list_head list;
	struct list_head card_list;

	unsigned int cache_bypass:1;  
	unsigned int suspended:1;  
	unsigned int cache_init:1;  

	void *control_data;  
	hw_write_t hw_write;
	void *reg_cache;

	struct snd_soc_component component;

#ifdef CONFIG_DEBUG_FS
	struct dentry *debugfs_reg;
#endif
};

struct snd_soc_codec_driver {

	int (*probe)(struct snd_soc_codec *);
	int (*remove)(struct snd_soc_codec *);
	int (*suspend)(struct snd_soc_codec *);
	int (*resume)(struct snd_soc_codec *);
	struct snd_soc_component_driver component_driver;

	const struct snd_kcontrol_new *controls;
	int num_controls;
	const struct snd_soc_dapm_widget *dapm_widgets;
	int num_dapm_widgets;
	const struct snd_soc_dapm_route *dapm_routes;
	int num_dapm_routes;

	int (*set_sysclk)(struct snd_soc_codec *codec,
			  int clk_id, int source, unsigned int freq, int dir);
	int (*set_pll)(struct snd_soc_codec *codec, int pll_id, int source,
		unsigned int freq_in, unsigned int freq_out);

	struct regmap *(*get_regmap)(struct device *);
	unsigned int (*read)(struct snd_soc_codec *, unsigned int);
	int (*write)(struct snd_soc_codec *, unsigned int, unsigned int);
	unsigned int reg_cache_size;
	short reg_cache_step;
	short reg_word_size;
	const void *reg_cache_default;

	int (*set_bias_level)(struct snd_soc_codec *,
			      enum snd_soc_bias_level level);
	bool idle_bias_off;
	bool suspend_bias_off;

	void (*seq_notifier)(struct snd_soc_dapm_context *,
			     enum snd_soc_dapm_type, int);

	bool ignore_pmdown_time;   
};

struct snd_soc_platform_driver {

	int (*probe)(struct snd_soc_platform *);
	int (*remove)(struct snd_soc_platform *);
	struct snd_soc_component_driver component_driver;

	int (*pcm_new)(struct snd_soc_pcm_runtime *);
	void (*pcm_free)(struct snd_pcm *);

	snd_pcm_sframes_t (*delay)(struct snd_pcm_substream *,
		struct snd_soc_dai *);

	const struct snd_pcm_ops *ops;

	const struct snd_compr_ops *compr_ops;

	int (*bespoke_trigger)(struct snd_pcm_substream *, int);
};

struct snd_soc_dai_link_component {
	const char *name;
	struct device_node *of_node;
	const char *dai_name;
};

struct snd_soc_platform {
	struct device *dev;
	const struct snd_soc_platform_driver *driver;

	struct list_head list;

	struct snd_soc_component component;
};

struct snd_soc_dai_link {
	 
	const char *name;			 
	const char *stream_name;		 
	 
	const char *cpu_name;
	struct device_node *cpu_of_node;
	 
	const char *cpu_dai_name;
	 
	const char *codec_name;
	struct device_node *codec_of_node;
	 
	const char *codec_dai_name;

	struct snd_soc_dai_link_component *codecs;
	unsigned int num_codecs;

	const char *platform_name;
	struct device_node *platform_of_node;
	int be_id;	 

	const struct snd_soc_pcm_stream *params;
	unsigned int num_params;

	unsigned int dai_fmt;            

	enum snd_soc_dpcm_trigger trigger[2];  

	int (*init)(struct snd_soc_pcm_runtime *rtd);

	int (*be_hw_params_fixup)(struct snd_soc_pcm_runtime *rtd,
			struct snd_pcm_hw_params *params);

	const struct snd_soc_ops *ops;
	const struct snd_soc_compr_ops *compr_ops;

	bool playback_only;
	bool capture_only;

	bool nonatomic;

	unsigned int ignore_suspend:1;

	unsigned int symmetric_rates:1;
	unsigned int symmetric_channels:1;
	unsigned int symmetric_samplebits:1;

	unsigned int no_pcm:1;

	unsigned int dynamic:1;

	unsigned int dpcm_capture:1;
	unsigned int dpcm_playback:1;

	unsigned int dpcm_merged_format:1;

	unsigned int ignore_pmdown_time:1;
};

struct snd_soc_codec_conf {
	 
	const char *dev_name;
	struct device_node *of_node;

	const char *name_prefix;
};

struct snd_soc_aux_dev {
	const char *name;		 

	const char *codec_name;
	struct device_node *codec_of_node;

	int (*init)(struct snd_soc_component *component);
};

struct snd_soc_card {
	const char *name;
	const char *long_name;
	const char *driver_name;
	struct device *dev;
	struct snd_card *snd_card;
	struct module *owner;

	struct mutex mutex;
	struct mutex dapm_mutex;

	bool instantiated;

	int (*probe)(struct snd_soc_card *card);
	int (*late_probe)(struct snd_soc_card *card);
	int (*remove)(struct snd_soc_card *card);

	int (*suspend_pre)(struct snd_soc_card *card);
	int (*suspend_post)(struct snd_soc_card *card);
	int (*resume_pre)(struct snd_soc_card *card);
	int (*resume_post)(struct snd_soc_card *card);

	int (*set_bias_level)(struct snd_soc_card *,
			      struct snd_soc_dapm_context *dapm,
			      enum snd_soc_bias_level level);
	int (*set_bias_level_post)(struct snd_soc_card *,
				   struct snd_soc_dapm_context *dapm,
				   enum snd_soc_bias_level level);

	long pmdown_time;

	struct snd_soc_dai_link *dai_link;
	int num_links;
	struct snd_soc_pcm_runtime *rtd;
	int num_rtd;

	struct snd_soc_codec_conf *codec_conf;
	int num_configs;

	struct snd_soc_aux_dev *aux_dev;
	int num_aux_devs;
	struct snd_soc_pcm_runtime *rtd_aux;
	int num_aux_rtd;

	const struct snd_kcontrol_new *controls;
	int num_controls;

	const struct snd_soc_dapm_widget *dapm_widgets;
	int num_dapm_widgets;
	const struct snd_soc_dapm_route *dapm_routes;
	int num_dapm_routes;
	const struct snd_soc_dapm_widget *of_dapm_widgets;
	int num_of_dapm_widgets;
	const struct snd_soc_dapm_route *of_dapm_routes;
	int num_of_dapm_routes;
	bool fully_routed;

	struct work_struct deferred_resume_work;

	struct list_head codec_dev_list;

	struct list_head widgets;
	struct list_head paths;
	struct list_head dapm_list;
	struct list_head dapm_dirty;

	struct list_head dobj_list;

	struct snd_soc_dapm_context dapm;
	struct snd_soc_dapm_stats dapm_stats;
	struct snd_soc_dapm_update *update;

#ifdef CONFIG_DEBUG_FS
	struct dentry *debugfs_card_root;
	struct dentry *debugfs_pop_time;
#endif
	u32 pop_time;

	void *drvdata;
};

struct snd_soc_pcm_runtime {
	struct device *dev;
	struct snd_soc_card *card;
	struct snd_soc_dai_link *dai_link;
	struct mutex pcm_mutex;
	enum snd_soc_pcm_subclass pcm_subclass;
	struct snd_pcm_ops ops;

	unsigned int dev_registered:1;

	struct snd_soc_dpcm_runtime dpcm[2];
	int fe_compr;

	long pmdown_time;
	unsigned char pop_wait:1;

	struct snd_pcm *pcm;
	struct snd_compr *compr;
	struct snd_soc_codec *codec;
	struct snd_soc_platform *platform;
	struct snd_soc_dai *codec_dai;
	struct snd_soc_dai *cpu_dai;
	struct snd_soc_component *component;  

	struct snd_soc_dai **codec_dais;
	unsigned int num_codecs;

	struct delayed_work delayed_work;
#ifdef CONFIG_DEBUG_FS
	struct dentry *debugfs_dpcm_root;
	struct dentry *debugfs_dpcm_state;
#endif
};

struct soc_mixer_control {
	int min, max, platform_max;
	int reg, rreg;
	unsigned int shift, rshift;
	unsigned int sign_bit;
	unsigned int invert:1;
	unsigned int autodisable:1;
	struct snd_soc_dobj dobj;
};

struct soc_bytes {
	int base;
	int num_regs;
	u32 mask;
};

struct soc_bytes_ext {
	int max;
	struct snd_soc_dobj dobj;

	int (*get)(unsigned int __user *bytes, unsigned int size);
	int (*put)(const unsigned int __user *bytes, unsigned int size);
};

struct soc_mreg_control {
	long min, max;
	unsigned int regbase, regcount, nbits, invert;
};

struct soc_enum {
	int reg;
	unsigned char shift_l;
	unsigned char shift_r;
	unsigned int items;
	unsigned int mask;
	const char * const *texts;
	const unsigned int *values;
	unsigned int autodisable:1;
	struct snd_soc_dobj dobj;
};

static inline struct snd_soc_codec *snd_soc_component_to_codec(
	struct snd_soc_component *component)
{
	return container_of(component, struct snd_soc_codec, component);
}

static inline struct snd_soc_platform *snd_soc_component_to_platform(
	struct snd_soc_component *component)
{
	return container_of(component, struct snd_soc_platform, component);
}

static inline struct snd_soc_component *snd_soc_dapm_to_component(
	struct snd_soc_dapm_context *dapm)
{
	return container_of(dapm, struct snd_soc_component, dapm);
}

static inline struct snd_soc_codec *snd_soc_dapm_to_codec(
	struct snd_soc_dapm_context *dapm)
{
	return snd_soc_component_to_codec(snd_soc_dapm_to_component(dapm));
}

static inline struct snd_soc_platform *snd_soc_dapm_to_platform(
	struct snd_soc_dapm_context *dapm)
{
	return snd_soc_component_to_platform(snd_soc_dapm_to_component(dapm));
}

static inline struct snd_soc_dapm_context *snd_soc_component_get_dapm(
	struct snd_soc_component *component)
{
	return &component->dapm;
}

static inline struct snd_soc_dapm_context *snd_soc_codec_get_dapm(
	struct snd_soc_codec *codec)
{
	return snd_soc_component_get_dapm(&codec->component);
}

static inline void snd_soc_codec_init_bias_level(struct snd_soc_codec *codec,
	enum snd_soc_bias_level level)
{
	snd_soc_dapm_init_bias_level(snd_soc_codec_get_dapm(codec), level);
}

static inline enum snd_soc_bias_level snd_soc_codec_get_bias_level(
	struct snd_soc_codec *codec)
{
	return snd_soc_dapm_get_bias_level(snd_soc_codec_get_dapm(codec));
}

static inline int snd_soc_codec_force_bias_level(struct snd_soc_codec *codec,
	enum snd_soc_bias_level level)
{
	return snd_soc_dapm_force_bias_level(snd_soc_codec_get_dapm(codec),
		level);
}

static inline struct snd_soc_codec *snd_soc_dapm_kcontrol_codec(
	struct snd_kcontrol *kcontrol)
{
	return snd_soc_dapm_to_codec(snd_soc_dapm_kcontrol_dapm(kcontrol));
}

unsigned int snd_soc_read(struct snd_soc_codec *codec, unsigned int reg);
int snd_soc_write(struct snd_soc_codec *codec, unsigned int reg,
	unsigned int val);

static inline int snd_soc_cache_sync(struct snd_soc_codec *codec)
{
	return regcache_sync(codec->component.regmap);
}

int snd_soc_component_read(struct snd_soc_component *component,
	unsigned int reg, unsigned int *val);
int snd_soc_component_write(struct snd_soc_component *component,
	unsigned int reg, unsigned int val);
int snd_soc_component_update_bits(struct snd_soc_component *component,
	unsigned int reg, unsigned int mask, unsigned int val);
int snd_soc_component_update_bits_async(struct snd_soc_component *component,
	unsigned int reg, unsigned int mask, unsigned int val);
void snd_soc_component_async_complete(struct snd_soc_component *component);
int snd_soc_component_test_bits(struct snd_soc_component *component,
	unsigned int reg, unsigned int mask, unsigned int value);

#ifdef CONFIG_REGMAP

void snd_soc_component_init_regmap(struct snd_soc_component *component,
	struct regmap *regmap);
void snd_soc_component_exit_regmap(struct snd_soc_component *component);

static inline void snd_soc_codec_init_regmap(struct snd_soc_codec *codec,
	struct regmap *regmap)
{
	snd_soc_component_init_regmap(&codec->component, regmap);
}

static inline void snd_soc_codec_exit_regmap(struct snd_soc_codec *codec)
{
	snd_soc_component_exit_regmap(&codec->component);
}

#endif

static inline void snd_soc_card_set_drvdata(struct snd_soc_card *card,
		void *data)
{
	card->drvdata = data;
}

static inline void *snd_soc_card_get_drvdata(struct snd_soc_card *card)
{
	return card->drvdata;
}

static inline void snd_soc_component_set_drvdata(struct snd_soc_component *c,
		void *data)
{
	dev_set_drvdata(c->dev, data);
}

static inline void *snd_soc_component_get_drvdata(struct snd_soc_component *c)
{
	return dev_get_drvdata(c->dev);
}

static inline void snd_soc_codec_set_drvdata(struct snd_soc_codec *codec,
		void *data)
{
	snd_soc_component_set_drvdata(&codec->component, data);
}

static inline void *snd_soc_codec_get_drvdata(struct snd_soc_codec *codec)
{
	return snd_soc_component_get_drvdata(&codec->component);
}

static inline void snd_soc_platform_set_drvdata(struct snd_soc_platform *platform,
		void *data)
{
	snd_soc_component_set_drvdata(&platform->component, data);
}

static inline void *snd_soc_platform_get_drvdata(struct snd_soc_platform *platform)
{
	return snd_soc_component_get_drvdata(&platform->component);
}

static inline void snd_soc_pcm_set_drvdata(struct snd_soc_pcm_runtime *rtd,
		void *data)
{
	dev_set_drvdata(rtd->dev, data);
}

static inline void *snd_soc_pcm_get_drvdata(struct snd_soc_pcm_runtime *rtd)
{
	return dev_get_drvdata(rtd->dev);
}

static inline void snd_soc_initialize_card_lists(struct snd_soc_card *card)
{
	INIT_LIST_HEAD(&card->codec_dev_list);
	INIT_LIST_HEAD(&card->widgets);
	INIT_LIST_HEAD(&card->paths);
	INIT_LIST_HEAD(&card->dapm_list);
}

static inline bool snd_soc_volsw_is_stereo(struct soc_mixer_control *mc)
{
	if (mc->reg == mc->rreg && mc->shift == mc->rshift)
		return 0;
	 
	return 1;
}

static inline unsigned int snd_soc_enum_val_to_item(struct soc_enum *e,
	unsigned int val)
{
	unsigned int i;

	if (!e->values)
		return val;

	for (i = 0; i < e->items; i++)
		if (val == e->values[i])
			return i;

	return 0;
}

static inline unsigned int snd_soc_enum_item_to_val(struct soc_enum *e,
	unsigned int item)
{
	if (!e->values)
		return item;

	return e->values[item];
}

static inline bool snd_soc_component_is_active(
	struct snd_soc_component *component)
{
	return component->active != 0;
}

static inline bool snd_soc_codec_is_active(struct snd_soc_codec *codec)
{
	return snd_soc_component_is_active(&codec->component);
}

static inline struct snd_soc_component *snd_soc_kcontrol_component(
	struct snd_kcontrol *kcontrol)
{
	return snd_kcontrol_chip(kcontrol);
}

static inline struct snd_soc_codec *snd_soc_kcontrol_codec(
	struct snd_kcontrol *kcontrol)
{
	return snd_soc_component_to_codec(snd_soc_kcontrol_component(kcontrol));
}

static inline struct snd_soc_platform *snd_soc_kcontrol_platform(
	struct snd_kcontrol *kcontrol)
{
	return snd_soc_component_to_platform(snd_soc_kcontrol_component(kcontrol));
}

int snd_soc_util_init(void);
void snd_soc_util_exit(void);

int snd_soc_of_parse_card_name(struct snd_soc_card *card,
			       const char *propname);
int snd_soc_of_parse_audio_simple_widgets(struct snd_soc_card *card,
					  const char *propname);
int snd_soc_of_parse_tdm_slot(struct device_node *np,
			      unsigned int *tx_mask,
			      unsigned int *rx_mask,
			      unsigned int *slots,
			      unsigned int *slot_width);
void snd_soc_of_parse_audio_prefix(struct snd_soc_card *card,
				   struct snd_soc_codec_conf *codec_conf,
				   struct device_node *of_node,
				   const char *propname);
int snd_soc_of_parse_audio_routing(struct snd_soc_card *card,
				   const char *propname);
unsigned int snd_soc_of_parse_daifmt(struct device_node *np,
				     const char *prefix,
				     struct device_node **bitclkmaster,
				     struct device_node **framemaster);
int snd_soc_of_get_dai_name(struct device_node *of_node,
			    const char **dai_name);
int snd_soc_of_get_dai_link_codecs(struct device *dev,
				   struct device_node *of_node,
				   struct snd_soc_dai_link *dai_link);

#include <sound/soc-dai.h>

#ifdef CONFIG_DEBUG_FS
extern struct dentry *snd_soc_debugfs_root;
#endif

extern const struct dev_pm_ops snd_soc_pm_ops;

static inline void snd_soc_dapm_mutex_lock(struct snd_soc_dapm_context *dapm)
{
	mutex_lock_nested(&dapm->card->dapm_mutex, SND_SOC_DAPM_CLASS_RUNTIME);
}

static inline void snd_soc_dapm_mutex_unlock(struct snd_soc_dapm_context *dapm)
{
	mutex_unlock(&dapm->card->dapm_mutex);
}

#endif
