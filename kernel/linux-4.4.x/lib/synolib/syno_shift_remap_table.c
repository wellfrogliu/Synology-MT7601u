#include <linux/synolib.h>
#include <linux/pci.h>
#include <linux/libata.h>

void syno_insert_sata_index_remap(unsigned int idx, unsigned int num, unsigned int id_start)
{
	int i = 0;

	if ((idx < 0) || (num < 0) || (id_start < 0)) {
		printk("Bad parameter, idx:%d, num:%d, id_start:%d\n", idx, num, id_start);
		return;
	}

	/* Shift g_syno_sata_remap  */
	for (i = (SATA_REMAP_MAX - 1); i >= (idx + num); i--) {
		g_syno_sata_remap[i] = g_syno_sata_remap[i - num];
	}

	for (i = 0; i < num; i++) {
		g_syno_sata_remap[idx + i] = id_start + i;
	}

	return;
}

EXPORT_SYMBOL(syno_insert_sata_index_remap);
