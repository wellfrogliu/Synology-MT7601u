#include <linux/synolib.h>

int syno_get_remap_idx(int origin_idx)
{
	if ((SATA_REMAP_NOT_INIT == g_syno_sata_remap[0]) ||
	    (SATA_REMAP_MAX <= origin_idx)) {
		return origin_idx;
	} else {
		return g_syno_sata_remap[origin_idx];
	}
}
EXPORT_SYMBOL(syno_get_remap_idx);

int syno_get_mv_14xx_remap_idx(int origin_idx)
{
	if ((g_use_mv14xx_remap) && (origin_idx < SATA_REMAP_MAX)) {
		return g_syno_mv14xx_remap[origin_idx];
	} else {
		return origin_idx;
	}
}
EXPORT_SYMBOL(syno_get_mv_14xx_remap_idx);
