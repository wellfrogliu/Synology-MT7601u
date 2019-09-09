/*
 * drivers/gpu/rtk_phoenix/rtk_phoenix_ion.c
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

#include <linux/err.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "../ion.h"
#include "../ion_priv.h"
#include "../../uapi/rtk_phoenix_ion.h"
#include "rtk_phoenix_ion_priv.h"
#include <linux/dma-buf.h>

#define ALIGNTO   32U
#define ION_ALIGN(len) ( ((len)+ALIGNTO-1) & ~(ALIGNTO-1) )

struct ion_heap *tiler_heap;
static unsigned int rtk_phoenix_last_alloc_addr = 0;
static unsigned int rtk_phoenix_last_size = 0;

void rtk_phoenix_set_tiler_heap(struct ion_heap **hPtr)
{
    tiler_heap = *hPtr;
}

#if 0 /* legacy */
struct ion_heap *rtk_phoenix_media_heap_create(struct ion_platform_heap *data)
{
    struct ion_heap *heap;

    heap = ion_rtk_carveout_heap_create(data);
    if (!heap)
        return ERR_PTR(-ENOMEM);
    heap->type = RTK_PHOENIX_ION_HEAP_TYPE_MEDIA;
    heap->name = data->name;
    heap->id = data->id;
    return heap;
}

struct ion_heap *rtk_phoenix_audio_heap_create(struct ion_platform_heap *data)
{
    struct ion_heap *heap;

    heap = ion_rtk_carveout_heap_create(data);
    if (!heap)
        return ERR_PTR(-ENOMEM);
    heap->type = RTK_PHOENIX_ION_HEAP_TYPE_AUDIO;
    heap->name = data->name;
    heap->id = data->id;
    return heap;
}
#endif

void rtk_phoenix_ion_update_last_alloc_addr(unsigned int addr, unsigned int size)
{
    rtk_phoenix_last_alloc_addr = addr;
    rtk_phoenix_last_size = size;
}

static int rtk_ion_sync_for_device(struct ion_client *client, int fd, int cmd)
{
	struct dma_buf *dmabuf;
	struct ion_buffer *buffer;
    enum dma_data_direction dir = (cmd == RTK_ION_IOC_INVALIDATE) ? DMA_FROM_DEVICE : DMA_TO_DEVICE;

    switch (cmd) {
        case RTK_ION_IOC_INVALIDATE:
        case RTK_ION_IOC_FLUSH:
            break;
        default:
            return -EINVAL;
    }

	dmabuf = dma_buf_get(fd);
	if (IS_ERR(dmabuf))
		return PTR_ERR(dmabuf);

	buffer = dmabuf->priv;

	dma_sync_sg_for_device(NULL, buffer->sg_table->sgl,
			       buffer->sg_table->nents, dir);
	dma_buf_put(dmabuf);
	return 0;
}

long rtk_phoenix_ion_ioctl(struct ion_client *client, unsigned int cmd,
                           unsigned long arg)
{
    switch (cmd) {

    case RTK_PHOENIX_ION_GET_LAST_ALLOC_ADDR:
    {
        u32 buf[2];
//		u32 new_addr = rtk_phoenix_last_alloc_addr;
        buf[0] = rtk_phoenix_last_alloc_addr;
        buf[1] = (u32)rtk_phoenix_last_size;

        if (copy_to_user((void __user *)arg, &buf[0],
                         sizeof(buf)))
            return -EFAULT;
        break;
    }

	case RTK_ION_IOC_INVALIDATE:
	case RTK_ION_IOC_FLUSH:
	{
        int fd = (int) arg& -1U;
		if (rtk_ion_sync_for_device(client, fd, cmd) != 0) {
            pr_err("%s: rtk_ion_sync_for_device failed! (cmd:%d fd:%d)\n", __func__, cmd, fd);
            return -EFAULT;
        }
		break;
	}

    default:
        pr_err("%s: Unknown custom ioctl\n", __func__);
        return -ENOTTY;
    }
    return 0;
}
