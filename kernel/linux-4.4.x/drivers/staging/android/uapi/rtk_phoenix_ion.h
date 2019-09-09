/*
 * include/linux/rtk_phoenix_ion.h
 *
 * Copyright (C) 2011 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef _LINUX_RTK_PHOENIX_ION_H
#define _LINUX_RTK_PHOENIX_ION_H

#include <linux/types.h>
#include <linux/cma.h>

//#include "ion.h"
//#include "../ion/ion.h"
/**
 * struct rtk_phoenix_ion_tiler_alloc_data - metadata passed from userspace for allocations
 * @w:		width of the allocation
 * @h:		height of the allocation
 * @fmt:	format of the data (8, 16, 32bit or page)
 * @flags:	flags passed to heap
 * @stride:	stride of the allocation, returned to caller from kernel
 * @handle:	pointer that will be populated with a cookie to use to refer
 *		to this allocation
 *
 * Provided by userspace as an argument to the ioctl
 */
struct rtk_phoenix_ion_tiler_alloc_data {
	size_t w;
	size_t h;
	int fmt;
	unsigned int flags;
	struct ion_handle *handle;
	size_t stride;
	size_t offset;
	unsigned int size;
};

#ifdef __KERNEL__
int rtk_phoenix_ion_tiler_alloc(struct ion_client *client,
			 struct rtk_phoenix_ion_tiler_alloc_data *data);
int rtk_phoenix_ion_nonsecure_tiler_alloc(struct ion_client *client,
			 struct rtk_phoenix_ion_tiler_alloc_data *data);
/* given a handle in the tiler, return a list of tiler pages that back it */
#if 1 //fix this later
int rtk_phoenix_tiler_pages(struct ion_client *client, struct ion_handle *handle, int *n, u32 ** tiler_pages);
#endif
#if 0 /* legacy */
struct ion_heap *rtk_phoenix_tiler_heap_create(struct ion_platform_heap *data);
struct ion_heap *rtk_phoenix_media_heap_create(struct ion_platform_heap *data);
struct ion_heap *rtk_phoenix_audio_heap_create(struct ion_platform_heap *data);
#endif
long rtk_phoenix_ion_ioctl(struct ion_client *client, unsigned int cmd, unsigned long arg);
void rtk_phoenix_set_tiler_heap(struct ion_heap **hPtr);
void rtk_phoenix_ion_update_last_alloc_addr(unsigned int addr, unsigned int size);
#endif /* __KERNEL__ */

/* additional heaps used only on rtk_phoenix */
enum {
	RTK_PHOENIX_ION_HEAP_TYPE_TILER = ION_HEAP_TYPE_CUSTOM + 1,
	RTK_PHOENIX_ION_HEAP_TYPE_MEDIA,
	RTK_PHOENIX_ION_HEAP_TYPE_AUDIO,
	RTK_PHOENIX_ION_HEAP_TYPE_SECURE,
};

#define RTK_PHOENIX_ION_HEAP_TILER_MASK (1 << RTK_PHOENIX_ION_HEAP_TYPE_TILER)
#define RTK_PHOENIX_ION_HEAP_MEDIA_MASK (1 << RTK_PHOENIX_ION_HEAP_TYPE_MEDIA)
#define RTK_PHOENIX_ION_HEAP_AUDIO_MASK (1 << RTK_PHOENIX_ION_HEAP_TYPE_AUDIO)
#define RTK_PHOENIX_ION_HEAP_SECURE_MASK (1 << RTK_PHOENIX_ION_HEAP_TYPE_SECURE)

enum {
	RTK_PHOENIX_ION_TILER_ALLOC,
	RTK_PHOENIX_ION_GET_LAST_ALLOC_ADDR,
	RTK_ION_IOC_INVALIDATE  = 0x10,
	RTK_ION_IOC_FLUSH,
};

/**
 * These should match the defines in the tiler driver
 */
enum {
	TILER_PIXEL_FMT_MIN   = 0,
	TILER_PIXEL_FMT_8BIT  = 0,
	TILER_PIXEL_FMT_16BIT = 1,
	TILER_PIXEL_FMT_32BIT = 2,
	TILER_PIXEL_FMT_PAGE  = 3,
	TILER_PIXEL_FMT_MAX   = 3
};

/**
 * List of heaps in the system
 */
enum {
	RTK_PHOENIX_ION_HEAP_LARGE_SURFACES,
	RTK_PHOENIX_ION_HEAP_TILER,
	RTK_PHOENIX_ION_HEAP_SECURE_INPUT,
	RTK_PHOENIX_ION_HEAP_NONSECURE_TILER,
};

enum ion_rtk_carveout_pool_type {
    RTK_CARVEOUT_GEN_POOL_TYPE = 0,
    RTK_CARVEOUT_CMA_POOL_TYPE,
};

struct ion_rtk_priv_pool {
    enum ion_rtk_carveout_pool_type type;
    ion_phys_addr_t base;
    struct cma * cma_pool;
    size_t size;
    unsigned long flags;
    struct list_head list;
};

#endif /* _LINUX_RTK_PHOENIX_ION_H */
