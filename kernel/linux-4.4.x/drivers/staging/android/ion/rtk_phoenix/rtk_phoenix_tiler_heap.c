/*
 * drivers/gpu/ion/rtk_phoenix/rtk_phoenix_tiler_heap.c
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
#include <linux/spinlock.h>

#include <linux/err.h>
#include <linux/genalloc.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <asm/page.h>
#include "../ion.h"
#include "../ion_priv.h"
#include "../../uapi/rtk_phoenix_ion.h"

#define ALIGNTO   32U
#define ION_ALIGN(len) ( ((len)+ALIGNTO-1) & ~(ALIGNTO-1) )
#define	__phys_to_pfn(paddr)	((unsigned long)((paddr) >> PAGE_SHIFT))

extern void rtk_phoenix_ion_update_last_alloc_addr(unsigned int addr, unsigned int size);

#if 0 /* legacy */
struct ion_heap *rtk_phoenix_tiler_heap_create(struct ion_platform_heap *data)
{
    struct ion_heap *heap;

    heap = ion_rtk_carveout_heap_create(data);
    if (!heap)
        return ERR_PTR(-ENOMEM);
    heap->type = RTK_PHOENIX_ION_HEAP_TYPE_TILER;
    heap->name = data->name;
    heap->id = data->id;
    return heap;
}
#endif
