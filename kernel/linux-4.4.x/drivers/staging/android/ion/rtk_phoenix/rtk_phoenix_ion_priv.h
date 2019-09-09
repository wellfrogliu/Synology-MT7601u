/*
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

#ifndef _LINUX_RTK_PHOENIX_ION_PRIV_H
#define _LINUX_RTK_PHOENIX_ION_PRIV_H

#include <linux/types.h>
#include "../ion.h"
int rtk_phoenix_tiler_alloc(struct ion_heap *heap,
		     struct ion_client *client,
		     struct rtk_phoenix_ion_tiler_alloc_data *data);
struct ion_heap *rtk_phoenix_tiler_heap_create(struct ion_platform_heap *heap_data);
void rtk_phoenix_tiler_heap_destroy(struct ion_heap *heap);

#endif /* _LINUX_RTK_PHOENIX_ION_PRIV_H */
