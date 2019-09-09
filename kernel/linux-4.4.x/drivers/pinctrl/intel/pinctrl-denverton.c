/*
 * Intel Denverton SoC pinctrl/GPIO driver
 *
 * Copyright (C) 2016, Synology Corporation
 * Author: Jason Li <jasonli@synology.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/acpi.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/pm.h>
#include <linux/pinctrl/pinctrl.h>

#include "pinctrl-intel.h"

#define HVL_PAD_OWN	0x020
#define HVL_HOSTSW_OWN	0x0C0
#define HVL_PADCFGLOCK	0x090
#define HVL_GPI_IE	0x120

#define HVL_COMMUNITY(s, e)				\
	{						\
		.padown_offset = HVL_PAD_OWN,		\
		.padcfglock_offset = HVL_PADCFGLOCK,	\
		.hostown_offset = HVL_HOSTSW_OWN,	\
		.ie_offset = HVL_GPI_IE,		\
		.gpp_size = 32,                         \
		.pin_base = (s),			\
		.npins = ((e) - (s) + 1),		\
	}

/* DNV */
static const struct pinctrl_pin_desc dnv_north_pins[] = {
	PINCTRL_PIN(0, "GBE0_SDP0"),
	PINCTRL_PIN(1, "GBE1_SDP0"),
	PINCTRL_PIN(2, "GBE0_SDP1"),
	PINCTRL_PIN(3, "GBE1_SDP1"),
	PINCTRL_PIN(4, "GBE0_SDP2"),
	PINCTRL_PIN(5, "GBE1_SDP2"),
	PINCTRL_PIN(6, "GBE0_SDP3"),
	PINCTRL_PIN(7, "GBE1_SDP3"),
	PINCTRL_PIN(8, "GBE2_LED0"),
	PINCTRL_PIN(9, "GBE2_LED1"),
	PINCTRL_PIN(10, "GBE0_I2C_CLK"),
	PINCTRL_PIN(11, "GBE0_I2C_DATA"),
	PINCTRL_PIN(12, "GBE1_I2C_CLK"),
	PINCTRL_PIN(13, "GBE1_I2C_DATA"),
	PINCTRL_PIN(14, "NCSI_RXD0"),
	PINCTRL_PIN(15, "NCSI_CLK_IN"),
	PINCTRL_PIN(16, "NCSI_RXD1"),
	PINCTRL_PIN(17, "NCSI_CRS_DV"),
	PINCTRL_PIN(18, "NCSI_ARB_IN"),
	PINCTRL_PIN(19, "NCSI_TX_EN"),
	PINCTRL_PIN(20, "NCSI_TXD0"),
	PINCTRL_PIN(21, "NCSI_TXD1"),
	PINCTRL_PIN(22, "NCSI_ARB_OUT"),
	PINCTRL_PIN(23, "GBE0_LED0"),
	PINCTRL_PIN(24, "GBE0_LED1"),
	PINCTRL_PIN(25, "GBE1_LED0"),
	PINCTRL_PIN(26, "GBE1_LED1"),
	PINCTRL_PIN(27, "GPIO_0"),
	PINCTRL_PIN(28, "PCIE_CLKREQ0_N"),
	PINCTRL_PIN(29, "PCIE_CLKREQ1_N"),
	PINCTRL_PIN(30, "PCIE_CLKREQ2_N"),
	PINCTRL_PIN(31, "PCIE_CLKREQ3_N"),
	PINCTRL_PIN(32, "PCIE_CLKREQ4_N"),
	PINCTRL_PIN(33, "GPIO_1"),
	PINCTRL_PIN(34, "GPIO_2"),
	PINCTRL_PIN(35, "SVID_ALERT_N"),
	PINCTRL_PIN(36, "SVID_DATA"),
	PINCTRL_PIN(37, "SVID_CLK"),
	PINCTRL_PIN(38, "THERMTRIP_N"),
	PINCTRL_PIN(39, "PROCHOT_N"),
	PINCTRL_PIN(40, "MEMHOT_N"),
};

static const struct intel_community dnv_north_communities[] = {
	HVL_COMMUNITY(0, 40),
};

static const struct intel_pinctrl_soc_data dnv_north_soc_data = {
	.uid = "1",
	.pins = dnv_north_pins,
	.npins = ARRAY_SIZE(dnv_north_pins),
	.communities = dnv_north_communities,
	.ncommunities = ARRAY_SIZE(dnv_north_communities),
};

static const struct pinctrl_pin_desc dnv_south_pins[] = {
	PINCTRL_PIN(0, "DFX_PORT_CLK0"),
	PINCTRL_PIN(1, "DFX_PORT_CLK1"),
	PINCTRL_PIN(2, "DFX_PORT0"),
	PINCTRL_PIN(3, "DFX_PORT1"),
	PINCTRL_PIN(4, "DFX_PORT2"),
	PINCTRL_PIN(5, "DFX_PORT3"),
	PINCTRL_PIN(6, "DFX_PORT4"),
	PINCTRL_PIN(7, "DFX_PORT5"),
	PINCTRL_PIN(8, "DFX_PORT6"),
	PINCTRL_PIN(9, "DFX_PORT7"),
	PINCTRL_PIN(10, "DFX_PORT8"),
	PINCTRL_PIN(11, "DFX_PORT9"),
	PINCTRL_PIN(12, "DFX_PORT10"),
	PINCTRL_PIN(13, "DFX_PORT11"),
	PINCTRL_PIN(14, "DFX_PORT12"),
	PINCTRL_PIN(15, "DFX_PORT13"),
	PINCTRL_PIN(16, "DFX_PORT14"),
	PINCTRL_PIN(17, "DFX_PORT15"),
	PINCTRL_PIN(18, "GPIO_12"),
	PINCTRL_PIN(19, "SMB5_GBE_ALRT_N"),
	PINCTRL_PIN(20, "PCIE_CLKREQ5_N"),
	PINCTRL_PIN(21, "PCIE_CLKREQ6_N"),
	PINCTRL_PIN(22, "PCIE_CLKREQ7_N"),
	PINCTRL_PIN(23, "UART0_RXD"),
	PINCTRL_PIN(24, "UART0_TXD"),
	PINCTRL_PIN(25, "SMB5_GBE_CLK"),
	PINCTRL_PIN(26, "SMB5_GBE_DATA"),
	PINCTRL_PIN(27, "ERROR2_N"),
	PINCTRL_PIN(28, "ERROR1_N"),
	PINCTRL_PIN(29, "ERROR0_N"),
	PINCTRL_PIN(30, "IERR_N"),
	PINCTRL_PIN(31, "MCERR_N"),
	PINCTRL_PIN(32, "SMB0_LEG_CLK"),
	PINCTRL_PIN(33, "SMB0_LEG_DATA"),
	PINCTRL_PIN(34, "SMB0_LEG_ALRT_N"),
	PINCTRL_PIN(35, "SMB1_HOST_DATA"),
	PINCTRL_PIN(36, "SMB1_HOST_CLK"),
	PINCTRL_PIN(37, "SMB2_PECI_DATA"),
	PINCTRL_PIN(38, "SMB2_PECI_CLK"),
	PINCTRL_PIN(39, "SMB4_CSME0_DATA"),
	PINCTRL_PIN(40, "SMB4_CSME0_CLK"),
	PINCTRL_PIN(41, "SMB4_CSME0_ALRT_N"),
	PINCTRL_PIN(42, "USB_OC0_N"),
	PINCTRL_PIN(43, "FLEX_CLK_SE0"),
	PINCTRL_PIN(44, "FLEX_CLK_SE1"),
	PINCTRL_PIN(45, "GPIO_4"),
	PINCTRL_PIN(46, "GPIO_5"),
	PINCTRL_PIN(47, "GPIO_6"),
	PINCTRL_PIN(48, "GPIO_7"),
	PINCTRL_PIN(49, "SATA0_LED_N"),
	PINCTRL_PIN(50, "SATA1_LED_N"),
	PINCTRL_PIN(51, "SATA_PDETECT0"),
	PINCTRL_PIN(52, "SATA_PDETECT1"),
	PINCTRL_PIN(53, "SATA0_SDOUT"),
	PINCTRL_PIN(54, "SATA1_SDOUT"),
	PINCTRL_PIN(55, "UART1_RXD"),
	PINCTRL_PIN(56, "UART1_TXD"),
	PINCTRL_PIN(57, "GPIO_8"),
	PINCTRL_PIN(58, "GPIO_9"),
	PINCTRL_PIN(59, "TCK"),
	PINCTRL_PIN(60, "TRST_N"),
	PINCTRL_PIN(61, "TMS"),
	PINCTRL_PIN(62, "TDI"),
	PINCTRL_PIN(63, "TDO"),
	PINCTRL_PIN(64, "CX_PRDY_N"),
	PINCTRL_PIN(65, "CX_PREQ_N"),
	PINCTRL_PIN(66, "CTBTRIGINOUT"),
	PINCTRL_PIN(67, "CTBTRIGOUT"),
	PINCTRL_PIN(68, "DFX_SPARE2"),
	PINCTRL_PIN(69, "DFX_SPARE3"),
	PINCTRL_PIN(70, "DFX_SPARE4"),
	PINCTRL_PIN(71, "SUSPWRDNACK"),
	PINCTRL_PIN(72, "PMU_SUSCLK"),
	PINCTRL_PIN(73, "ADR_TRIGGER"),
	PINCTRL_PIN(74, "PMU_SLP_S45_N"),
	PINCTRL_PIN(75, "PMU_SLP_S3_N"),
	PINCTRL_PIN(76, "PMU_WAKE_N"),
	PINCTRL_PIN(77, "PMU_PWRBTN_N"),
	PINCTRL_PIN(78, "PMU_RESETBUTTON_N"),
	PINCTRL_PIN(79, "PMU_PLTRST_N"),
	PINCTRL_PIN(80, "SUS_STAT_N"),
	PINCTRL_PIN(81, "SLP_S0IX_N"),
	PINCTRL_PIN(82, "SPI_CS0_N"),
	PINCTRL_PIN(83, "SPI_CS1_N"),
	PINCTRL_PIN(84, "SPI_MOSI_IO0"),
	PINCTRL_PIN(85, "SPI_MOSI_IO1"),
	PINCTRL_PIN(86, "SPI_IO2"),
	PINCTRL_PIN(87, "SPI_IO3"),
	PINCTRL_PIN(88, "SPI_CLK"),
	PINCTRL_PIN(89, "SPI_CLK_LOOPBK"),
	PINCTRL_PIN(90, "ESPI_IO0"),
	PINCTRL_PIN(91, "ESPI_IO1"),
	PINCTRL_PIN(92, "ESPI_IO2"),
	PINCTRL_PIN(93, "ESPI_IO3"),
	PINCTRL_PIN(94, "ESPI_CS0_N"),
	PINCTRL_PIN(95, "ESPI_CLK"),
	PINCTRL_PIN(96, "ESPI_RST_N"),
	PINCTRL_PIN(97, "ESPI_ALRT0_N"),
	PINCTRL_PIN(98, "GPIO_10"),
	PINCTRL_PIN(99, "GPIO_11"),
	PINCTRL_PIN(100, "ESPI_CLK_LOOPBK"),
	PINCTRL_PIN(101, "EMMC_CMD"),
	PINCTRL_PIN(102, "EMMC_STROBE"),
	PINCTRL_PIN(103, "EMMC_CLK"),
	PINCTRL_PIN(104, "EMMC_D0"),
	PINCTRL_PIN(105, "EMMC_D1"),
	PINCTRL_PIN(106, "EMMC_D2"),
	PINCTRL_PIN(107, "EMMC_D3"),
	PINCTRL_PIN(108, "EMMC_D4"),
	PINCTRL_PIN(109, "EMMC_D5"),
	PINCTRL_PIN(110, "EMMC_D6"),
	PINCTRL_PIN(111, "EMMC_D7"),
	PINCTRL_PIN(112, "GPIO_3"),
};

static const struct intel_community dnv_south_communities[] = {
	HVL_COMMUNITY(0, 112),
};

static const struct intel_pinctrl_soc_data dnv_south_soc_data = {
	.uid = "2",
	.pins = dnv_south_pins,
	.npins = ARRAY_SIZE(dnv_south_pins),
	.communities = dnv_south_communities,
	.ncommunities = ARRAY_SIZE(dnv_south_communities),
};

static const struct intel_pinctrl_soc_data *dnv_pinctrl_soc_data[] = {
	&dnv_north_soc_data,
	&dnv_south_soc_data,
	NULL,
};

static const struct acpi_device_id hvl_pinctrl_acpi_match[] = {
	{ "INT5566", (kernel_ulong_t)dnv_pinctrl_soc_data },
	{ }
};
MODULE_DEVICE_TABLE(acpi, hvl_pinctrl_acpi_match);

static int hvl_pinctrl_probe(struct platform_device *pdev)
{
	const struct intel_pinctrl_soc_data *soc_data = NULL;
	const struct intel_pinctrl_soc_data **soc_table;
	const struct acpi_device_id *id;
	struct acpi_device *adev;
	int i;

	adev = ACPI_COMPANION(&pdev->dev);
	if (!adev)
		return -ENODEV;

	id = acpi_match_device(hvl_pinctrl_acpi_match, &pdev->dev);
	if (!id)
		return -ENODEV;

	soc_table = (const struct intel_pinctrl_soc_data **)id->driver_data;

	for (i = 0; soc_table[i]; i++) {
		if (!strcmp(adev->pnp.unique_id, soc_table[i]->uid)) {
			soc_data = soc_table[i];
			break;
		}
	}

	if (!soc_data) {
		return -ENODEV;
	}

	return intel_pinctrl_probe(pdev, soc_data);
}

static const struct dev_pm_ops hvl_pinctrl_pm_ops = {
	SET_LATE_SYSTEM_SLEEP_PM_OPS(intel_pinctrl_suspend,
				     intel_pinctrl_resume)
};

static struct platform_driver hvl_pinctrl_driver = {
	.probe = hvl_pinctrl_probe,
	.remove = intel_pinctrl_remove,
	.driver = {
		.name = "denverton-pinctrl",
		.acpi_match_table = hvl_pinctrl_acpi_match,
		.pm = &hvl_pinctrl_pm_ops,
	},
};

static int __init hvl_pinctrl_init(void)
{
	return platform_driver_register(&hvl_pinctrl_driver);
}
subsys_initcall(hvl_pinctrl_init);

static void __exit hvl_pinctrl_exit(void)
{
	platform_driver_unregister(&hvl_pinctrl_driver);
}
module_exit(hvl_pinctrl_exit);

MODULE_AUTHOR("Jason Li <jasonli@synology.com>");
MODULE_DESCRIPTION("Intel Denverton SoC pinctrl/GPIO driver");
MODULE_LICENSE("GPL v2");
