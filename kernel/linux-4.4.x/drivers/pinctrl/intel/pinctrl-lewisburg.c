/*
 * Intel Lewisburg PCH pinctrl/GPIO driver
 *
 * Copyright (C) 2016, Synology Corporation
 * Authors: Ricky Chang <rickychang@synology.com>
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

#define LWB_PAD_OWN	0x020
#define LWB_PADCFGLOCK	0x060
#define LWB_HOSTSW_OWN	0x080
#define LWB_GPI_IE	0x100

#define LWB_COMMUNITY(s, e)				\
	{						\
		.padown_offset = LWB_PAD_OWN,		\
		.padcfglock_offset = LWB_PADCFGLOCK,	\
		.hostown_offset = LWB_HOSTSW_OWN,	\
		.ie_offset = LWB_GPI_IE,		\
		.gpp_size = 24,				\
		.pin_base = (s),			\
		.npins = ((e) - (s) + 1),		\
	}

/* Lewisburg */
static const struct pinctrl_pin_desc lwb_cm0_pins[] = {
	/*Community 0 Registers are for GPP_A, GPP_B and GPP_F groups, refer to lewisburg EDS*/
	/* GPP_A */
	PINCTRL_PIN(0, "RCINB"),
	PINCTRL_PIN(1, "LAD_0"),
	PINCTRL_PIN(2, "LAD_1"),
	PINCTRL_PIN(3, "LAD_2"),
	PINCTRL_PIN(4, "LAD_3"),
	PINCTRL_PIN(5, "LFRAMEB"),
	PINCTRL_PIN(6, "SERIQ"),
	PINCTRL_PIN(7, "PIRQAB"),
	PINCTRL_PIN(8, "CLKRUNB"),
	PINCTRL_PIN(9, "CLKOUT_LPC_0"),
	PINCTRL_PIN(10, "CLKOUT_LPC_1"),
	PINCTRL_PIN(11, "PMEB"),
	PINCTRL_PIN(12, "BM_BUSYB"),
	PINCTRL_PIN(13, "SUSWARNB_SUS_PWRDNACK"),
	PINCTRL_PIN(14, "SUS_STATB"),
	PINCTRL_PIN(15, "SUSACKB"),
	PINCTRL_PIN(16, "CLKOUT_LPC2"),
	PINCTRL_PIN(17, "PU_UPI_SLOW_MODE_N"),
	PINCTRL_PIN(18, "PD_BIOS_ADV_FUNCTIONS"),
	PINCTRL_PIN(19, "FM_ME_RCVR_N"),
	PINCTRL_PIN(20, "GPP_A20"),
	PINCTRL_PIN(21, "GPP_A21"),
	PINCTRL_PIN(22, "GPP_A22"),
	PINCTRL_PIN(23, "GPP_A23"),
	/* GPP_B */
	PINCTRL_PIN(24, "CORE_VID_0"),
	PINCTRL_PIN(25, "CORE_VID_1"),
	PINCTRL_PIN(26, "PU_QAT_ENABLE_N"),
	PINCTRL_PIN(27, "GPP_B3"),
	PINCTRL_PIN(28, "GPP_B4"),
	PINCTRL_PIN(29, "GPP_B5"),
	PINCTRL_PIN(30, "GPP_B6"),
	PINCTRL_PIN(31, "GPP_B7"),
	PINCTRL_PIN(32, "GPP_B8"),
	PINCTRL_PIN(33, "uP_PWR_BTN_N"),
	PINCTRL_PIN(34, "FP_RST_BTN_N"),
	PINCTRL_PIN(35, "FAN_BMC_R_PWM0"),
	PINCTRL_PIN(36, "TP_SLP_S0_N"),
	PINCTRL_PIN(37, "PLTRSTB"),
	PINCTRL_PIN(38, "FM_PCH_BIOS_RCVR_SPKR"),
	PINCTRL_PIN(39, "FM_PERST_SEL_BIT0"),
	PINCTRL_PIN(40, "FM_PERST_SEL_BIT1"),
	PINCTRL_PIN(41, "FM_PERST_SEL_BIT2"),
	PINCTRL_PIN(42, "PU_NO_REBOOT"),
	PINCTRL_PIN(43, "FM_PERST_SEL_BIT3"),
	PINCTRL_PIN(44, "FM_BIOS_POST_CMPLT_N"),
	PINCTRL_PIN(45, "FM_BIOS_SPI_BMC_CTRL"),
	PINCTRL_PIN(46, "PD_PCH_BOOT_BIOS_DEVICE"),
	PINCTRL_PIN(47, "FM_PCH_BMC_THERMTRIP_EXI_STRAP_N"),
	/* GPP_F */
	PINCTRL_PIN(109, "GPP_F0"),
	PINCTRL_PIN(110, "GPP_F1"),
	PINCTRL_PIN(111, "GPP_F2"),
	PINCTRL_PIN(112, "GPP_F3"),
	PINCTRL_PIN(113, "GPP_F4"),
	PINCTRL_PIN(114, "FM_SYS_THROTTLE_LVC3"),
	PINCTRL_PIN(115, "JTAG_PCH_PLD_TCK_R"),
	PINCTRL_PIN(116, "JTAG_PCH_PLD_TDI"),
	PINCTRL_PIN(117, "JTAG_PCH_PLD_TMS"),
	PINCTRL_PIN(118, "JTAG_PCH_PLD_TDO"),
	PINCTRL_PIN(119, "GPP_F10"),
	PINCTRL_PIN(120, "GPP_F11"),
	PINCTRL_PIN(121, "GPP_F12"),
	PINCTRL_PIN(122, "GPP_F13"),
	PINCTRL_PIN(123, "GPP_F14"),
	PINCTRL_PIN(124, "FM_FORCE_ADR_N"),
	PINCTRL_PIN(125, "FM_IE_DISABLE_N"),
	PINCTRL_PIN(126, "GPP_F17"),
	PINCTRL_PIN(127, "FM_MEM_THERM_EVENT_PCH_N"),
	PINCTRL_PIN(128, "GPP_F19"),
	PINCTRL_PIN(129, "GPP_F20"),
	PINCTRL_PIN(130, "GPP_F21"),
	PINCTRL_PIN(131, "GPP_F22"),
	PINCTRL_PIN(132, "GPP_F23"),
};
static const struct intel_community lwb_cm0_communities[] = {
	LWB_COMMUNITY(0, 71),
};

static const struct intel_pinctrl_soc_data lwb_cm0_soc_data = {
	.uid = "1",
	.pins = lwb_cm0_pins,
	.npins = ARRAY_SIZE(lwb_cm0_pins),
	.communities = lwb_cm0_communities,
	.ncommunities = ARRAY_SIZE(lwb_cm0_communities),
};

static const struct pinctrl_pin_desc lwb_cm1_pins[] = {
	/*Community 1 Registers are for GPP_C, GPP_D, and GPP_E groups.*/	
	/* GPP_C */
	PINCTRL_PIN(48, "SMBCLK"),
	PINCTRL_PIN(49, "SMBDATA"),
	PINCTRL_PIN(50, "PU_PCH_TLS_ENABLE_STRAP"),
	PINCTRL_PIN(51, "SML0CLK"),
	PINCTRL_PIN(52, "SML0DATA"),
	PINCTRL_PIN(53, "SML0ALERTB"),
	PINCTRL_PIN(54, "SMB_PMBUS_BMC_STBY_LVC3_CLK_R2"),
	PINCTRL_PIN(55, "SMB_PMBUS_BMC_STBY_LVC3_DATA_R2"),
	PINCTRL_PIN(56, "FM_PASSWORD_CLEAR_N"),
	PINCTRL_PIN(57, "FM_MFG_MODE"),
	PINCTRL_PIN(58, "FM_PCH_SATA_RAID_KEY"),
	PINCTRL_PIN(59, "PU_GPP_C_11_UART0_CTSB"),
	PINCTRL_PIN(60, "FM_BOARD_REV_ID0"),
	PINCTRL_PIN(61, "FM_BOARD_REV_ID1"),
	PINCTRL_PIN(62, "IRQ_BMC_PCH_SCI_LPC_N"),
	PINCTRL_PIN(63, "GPP_C15"),
	PINCTRL_PIN(64, "GPP_C16"),
	PINCTRL_PIN(65, "GPP_C17"),
	PINCTRL_PIN(66, "GPP_C18"),
	PINCTRL_PIN(67, "GPP_C19"),
	PINCTRL_PIN(68, "FM_THROTTLE_N"),
	PINCTRL_PIN(69, "RST_PCH_MIC_MUX_R_N"),
	PINCTRL_PIN(70, "IRQ_BMC_PCH_SMI_LPC_N"),
	PINCTRL_PIN(71, "FM_CPU_CATERR_DLY_LVT3_N"),
	/* GPP_D */
	PINCTRL_PIN(72, "IRQ_BMC_PCH_NMI"),
	PINCTRL_PIN(73, "FP_PWR_LED_N"),
	PINCTRL_PIN(74, "TP_PCH_GPP_D_2"),
	PINCTRL_PIN(75, "FP_LD_DEFAULT_RST_BTN_PCH_N"),
	PINCTRL_PIN(76, "FM_PLD_PCH_DATA"),
	PINCTRL_PIN(77, "SPI_BMC_BOOT_CS0_N"),
	PINCTRL_PIN(78, "GPP_D6"),
	PINCTRL_PIN(79, "FM_BMC_CPLD_GPO"),
	PINCTRL_PIN(80, "GPP_D8"),
	PINCTRL_PIN(81, "PU_GPP_D_9_ISH_SPI_CSB"),
	PINCTRL_PIN(82, "PU_GPP_D_10_ISH_SPI_CLK"),
	PINCTRL_PIN(83, "PU_GPP_D_11_ISH_SPI_MISO"),
	PINCTRL_PIN(84, "TP_SGPIO_SSATA_DATAOUT1"),
	PINCTRL_PIN(85, "SML0BCLK"),
	PINCTRL_PIN(86, "SML0BDATA"),
	PINCTRL_PIN(87, "GPP_D15"),
	PINCTRL_PIN(88, "GPP_D16"),
	PINCTRL_PIN(89, "BUZZER_MUTE_BOT_PCH_GPO"),
	PINCTRL_PIN(90, "BUZZER_MUTE_BOT_PCH_GPI"),
	PINCTRL_PIN(91, "FM_PS_PWROK_DLY_SEL"),
	PINCTRL_PIN(92, "LED_BMC_HB_LED_N"),
	PINCTRL_PIN(93, "SP2_BMC_CM_UART_RX"),
	PINCTRL_PIN(94, "SP2_BMC_CM_UART_TX"),
	PINCTRL_PIN(95, "GPP_D23"),
	/* GPP_E */
	PINCTRL_PIN(96, "GPP_E0"),
	PINCTRL_PIN(97, "GPP_E1"),
	PINCTRL_PIN(98, "GPP_E2"),
	PINCTRL_PIN(99, "FM_ADR_TRIGGER_N"),
	PINCTRL_PIN(100, "FM_CPU_ERR2_LVT3_N"),
	PINCTRL_PIN(101, "FM_CPU_MSMI_LVT3_N"),
	PINCTRL_PIN(102, "GPP_E6"),
	PINCTRL_PIN(103, "FM_ADR_SMI_GPIO_N"),
	PINCTRL_PIN(104, "RST_PCH_SYSRST_BTN_OUT_N"),
	PINCTRL_PIN(105, "FM_USB_OC0_REAR_N"),
	PINCTRL_PIN(106, "FM_USB_OC1_BRDG_N"),
	PINCTRL_PIN(107, "FM_PCH_PWRBTN_OUT_N"),
	PINCTRL_PIN(108, "GPP_E12"),
};

static const struct intel_community lwb_cm1_communities[] = {
	LWB_COMMUNITY(0, 60),
};

static const struct intel_pinctrl_soc_data lwb_cm1_soc_data = {
	.uid = "2",
	.pins = lwb_cm1_pins,
	.npins = ARRAY_SIZE(lwb_cm1_pins),
	.communities = lwb_cm1_communities,
	.ncommunities = ARRAY_SIZE(lwb_cm1_communities),
};

static const struct pinctrl_pin_desc lwb_cm2_pins[] = {
	/*Community 2 Registers are for GPP_DSW group.*/
	/* GPD */
	PINCTRL_PIN(245, "FM_PCH_HOOK2_N"),
	PINCTRL_PIN(246, "PU_ACPRESENT"),
	PINCTRL_PIN(247, "PU_LAN_WAKE_N"),
	PINCTRL_PIN(248, "FM_SLPS3_N"),
	PINCTRL_PIN(249, "FM_SLPS3_N"),
	PINCTRL_PIN(250, "FM_SLPS4_N"),
	PINCTRL_PIN(251, "TP_SLPA_N"),
	PINCTRL_PIN(252, "TP_GPD_7"),
	PINCTRL_PIN(253, "TP_PCH_GPD_8"),
	PINCTRL_PIN(254, "TP_SLP_WLAN"),
	PINCTRL_PIN(255, "TP_SLPS5_N"),
	PINCTRL_PIN(256, "TP_GPD_11_GBEPHY"),
};
static const struct intel_community lwb_cm2_communities[] = {
	LWB_COMMUNITY(0, 11),
};

static const struct intel_pinctrl_soc_data lwb_cm2_soc_data = {
	.uid = "3",
	.pins = lwb_cm2_pins,
	.npins = ARRAY_SIZE(lwb_cm2_pins),
	.communities = lwb_cm2_communities,
	.ncommunities = ARRAY_SIZE(lwb_cm2_communities),
};

static const struct pinctrl_pin_desc lwb_cm3_pins[] = {
	/*Community 3 Registers are for GPP_I group.*/
	/* GPP_I */
	PINCTRL_PIN(181, "PU_GPP_I_0_DDSP_HPD_0"),
	PINCTRL_PIN(182, "PD_GPP_I_1_DDSP_HPD_1"),
	PINCTRL_PIN(183, "GPP_I2"),
	PINCTRL_PIN(184, "GPP_I3"),
	PINCTRL_PIN(185, "IRQ_DIMM_SAVE_LVT3_N"),
	PINCTRL_PIN(186, "GPP_I5"),
	PINCTRL_PIN(187, "GPP_I6"),
	PINCTRL_PIN(188, "IRQ_DIMM_SAVE_LVT3_N"),
	PINCTRL_PIN(189, "GPP_I8"),
	PINCTRL_PIN(190, "GPP_I9"),
	PINCTRL_PIN(191, "REAR_USB3_PWR_EN"),
};
static const struct intel_community lwb_cm3_communities[] = {
	LWB_COMMUNITY(0, 10),
};

static const struct intel_pinctrl_soc_data lwb_cm3_soc_data = {
	.uid = "4",
	.pins = lwb_cm3_pins,
	.npins = ARRAY_SIZE(lwb_cm3_pins),
	.communities = lwb_cm3_communities,
	.ncommunities = ARRAY_SIZE(lwb_cm3_communities),
};

static const struct pinctrl_pin_desc lwb_cm4_pins[] = {
	/*Community 4 Registers are for GPP_J,and GPP_K groups.*/
	/* GPP_J */
	PINCTRL_PIN(192, "GPP_J0"),
	PINCTRL_PIN(193, "GPP_J1"),
	PINCTRL_PIN(194, "GPP_J2"),
	PINCTRL_PIN(195, "GPP_J3"),
	PINCTRL_PIN(196, "GPP_J4"),
	PINCTRL_PIN(197, "GPP_J5"),
	PINCTRL_PIN(198, "GPP_J6"),
	PINCTRL_PIN(199, "GPP_J7"),
	PINCTRL_PIN(200, "PU_PCH_GPP_J_8"),
	PINCTRL_PIN(201, "PU_PCH_GPP_J_9"),
	PINCTRL_PIN(202, "PU_PCH_GPP_J_10"),
	PINCTRL_PIN(203, "PU_PCH_GPP_J_11"),
	PINCTRL_PIN(204, "PU_PCH_GPP_J_12"),
	PINCTRL_PIN(205, "PU_PCH_GPP_J_13"),
	PINCTRL_PIN(206, "PU_PCH_GPP_J_14"),
	PINCTRL_PIN(207, "PU_PCH_GPP_J_15"),
	PINCTRL_PIN(208, "FM_CPU_ERR0_LVT3_N"),
	PINCTRL_PIN(209, "FM_CPU_ERR1_LVT3_N"),
	PINCTRL_PIN(210, "FM_CPU1_THERMTRIP_LATCH_LVT3_N"),
	PINCTRL_PIN(211, "FM_CPU0_THERMTRIP_LATCH_LVT3_N"),
	PINCTRL_PIN(212, "FM_CPU_CATERR_PLD_LVT3_N"),
	PINCTRL_PIN(213, "GPP_J21"),
	PINCTRL_PIN(214, "GPP_J22"),
	PINCTRL_PIN(215, "GPP_J23"),
	/* GPP_K */
	PINCTRL_PIN(216, "PD_CLK_50M_CKMNG_PCH"),
	PINCTRL_PIN(217, "IRQ_CPU0_PROCHOT_R_N"),
	PINCTRL_PIN(218, "IRQ_CPU1_PROCHOT_R_N"),
	PINCTRL_PIN(219, "IRQ_PVDDQ_CPU1_DEF_VRHOT_LVC3_N"),
	PINCTRL_PIN(220, "IRQ_PVDDQ_CPU1_ABC_VRHOT_LVC3_N"),
	PINCTRL_PIN(221, "IRQ_PVDDQ_CPU0_DEF_VRHOT_LVC3_N"),
	PINCTRL_PIN(222, "IRQ_PVDDQ_CPU0_ABC_VRHOT_LVC3_N"),
	PINCTRL_PIN(223, "PD_RMII_PCH_BMC_RX_ER"),
	PINCTRL_PIN(224, "PD_RMII_PCH_ARB_IN"),
	PINCTRL_PIN(225, "PU_RMII_PCH_ARB_OUT"),
	PINCTRL_PIN(226, "RST_PCIE_PCH_PERST_N"),
};
static const struct intel_community lwb_cm4_communities[] = {
	LWB_COMMUNITY(0, 34),
};

static const struct intel_pinctrl_soc_data lwb_cm4_soc_data = {
	.uid = "5",
	.pins = lwb_cm4_pins,
	.npins = ARRAY_SIZE(lwb_cm4_pins),
	.communities = lwb_cm4_communities,
	.ncommunities = ARRAY_SIZE(lwb_cm4_communities),
};

static const struct pinctrl_pin_desc lwb_cm5_pins[] = {
	/*Community 5 Registers are for GPP_G, GPP_H and GPP_L groups.*/
	/* GPP_G */
	PINCTRL_PIN(133, "FAN_BMC_TACH0"),
	PINCTRL_PIN(134, "FAN_BMC_TACH1"),
	PINCTRL_PIN(135, "FAN_BMC_TACH2"),
	PINCTRL_PIN(136, "FAN_BMC_TACH3"),
	PINCTRL_PIN(137, "IRQ_PVCCIN_CPU0_VRHOT_LVC3_N"),
	PINCTRL_PIN(138, "IRQ_PVCCIN_CPU1_VRHOT_LVC3_N"),
	PINCTRL_PIN(139, "FM_CPU0_FIVR_FAULT_LVT3_N"),
	PINCTRL_PIN(140, "FM_CPU1_FIVR_FAULT_LVT3_N"),
	PINCTRL_PIN(141, "FAN_BMC_R_PWM0"),
	PINCTRL_PIN(142, "FAN_BMC_R_PWM1"),
	PINCTRL_PIN(143, "FAN_BMC_R_PWM2"),
	PINCTRL_PIN(144, "FAN_BMC_R_PWM3"),
	PINCTRL_PIN(145, "FM_BOARD_SKU_ID0"),
	PINCTRL_PIN(146, "FM_BOARD_SKU_ID1"),
	PINCTRL_PIN(147, "FM_BOARD_SKU_ID2"),
	PINCTRL_PIN(148, "FM_BOARD_SKU_ID3"),
	PINCTRL_PIN(149, "FM_BOARD_SKU_ID4"),
	PINCTRL_PIN(150, "FM_ADR_COMPLETE"),
	PINCTRL_PIN(151, "IRQ_NMI_EVENT_N"),
	PINCTRL_PIN(152, "IRQ_SMI_ACTIVE_N"),
	PINCTRL_PIN(153, "IRQ_SML1_PMBUS_ALERT_N"),
	PINCTRL_PIN(154, "PCH_SYNO_SASCARD_CTRL"),
	PINCTRL_PIN(155, "GPP_G22"),
	PINCTRL_PIN(156, "PCH_PHY_RST_RTL8211E_N"),
	/* GPP_H */
	PINCTRL_PIN(157, "FM_BACKUP_BIOS_SEL_N"),
	PINCTRL_PIN(158, "CPLD_LED_CTRL_N"),
	PINCTRL_PIN(159, "LED_CONTROL_0"),
	PINCTRL_PIN(160, "LED_CONTROL_1"),
	PINCTRL_PIN(161, "LED_CONTROL_2"),
	PINCTRL_PIN(162, "LED_CONTROL_3"),
	PINCTRL_PIN(163, "LED_CONTROL_4"),
	PINCTRL_PIN(164, "LED_CONTROL_5"),
	PINCTRL_PIN(165, "LED_CONTROL_6"),
	PINCTRL_PIN(166, "LED_CONTROL_7"),
	PINCTRL_PIN(167, "SMB_SML2_VR_CLK"),
	PINCTRL_PIN(168, "SMB_SML2_VR_DIA"),
	PINCTRL_PIN(169, "PU_ESPI_FLASH_MODE"),
	PINCTRL_PIN(170, "SMB_SENSOR_STBY_LVC3_SCL_R1"),
	PINCTRL_PIN(171, "SMB_SENSOR_STBY_LVC3_SDA_R1"),
	PINCTRL_PIN(172, "PU_ADR_TIMER_HOLD_OFF_N"),
	PINCTRL_PIN(173, "SMB_SMLINK4_STBY_LVC3_SCL_R1"),
	PINCTRL_PIN(174, "SMB_SMLINK4_STBY_LVC3_SDA_R1"),
	PINCTRL_PIN(175, "IRQ_SML4_ALERT_R_N"),
	PINCTRL_PIN(176, "FM_PCH_BMC_THERMTRIP_N"),
	PINCTRL_PIN(177, "FM_PCH_LAN0_DISABLE_N"),
	PINCTRL_PIN(178, "FM_PCH_LAN1_DISABLE_N"),
	PINCTRL_PIN(179, "LAN2_DEV_OFF_L"),
	PINCTRL_PIN(180, "LAN1_DEV_OFF_L"),
	/* GPP_L */
	PINCTRL_PIN(227, "XDP_VISA_2CH0_D0"),
	PINCTRL_PIN(228, "XDP_VISA_2CH0_D1"),
	PINCTRL_PIN(229, "XDP_VISA_2CH0_D2"),
	PINCTRL_PIN(230, "XDP_VISA_2CH0_D3"),
	PINCTRL_PIN(231, "XDP_VISA_2CH0_D4"),
	PINCTRL_PIN(232, "XDP_VISA_2CH0_D5"),
	PINCTRL_PIN(233, "XDP_VISA_2CH0_D6"),
	PINCTRL_PIN(234, "XDP_VISA_2CH0_D7"),
	PINCTRL_PIN(235, "XDP_VISA_2CH0_CLK"),
	PINCTRL_PIN(236, "XDP_VISA_2CH1_D0"),
	PINCTRL_PIN(237, "XDP_VISA_2CH1_D1"),
	PINCTRL_PIN(238, "XDP_VISA_2CH1_D2"),
	PINCTRL_PIN(239, "XDP_VISA_2CH1_D3"),
	PINCTRL_PIN(240, "XDP_VISA_2CH1_D4"),
	PINCTRL_PIN(241, "XDP_VISA_2CH1_D5"),
	PINCTRL_PIN(242, "XDP_VISA_2CH1_D6"),
	PINCTRL_PIN(243, "XDP_VISA_2CH1_D7"),
	PINCTRL_PIN(244, "XDP_VISA_2CH1_CLK"),
};
static const struct intel_community lwb_cm5_communities[] = {
	LWB_COMMUNITY(0, 65),
};

static const struct intel_pinctrl_soc_data lwb_cm5_soc_data = {
	.uid = "6",
	.pins = lwb_cm5_pins,
	.npins = ARRAY_SIZE(lwb_cm5_pins),
	.communities = lwb_cm5_communities,
	.ncommunities = ARRAY_SIZE(lwb_cm5_communities),
};

static const struct intel_pinctrl_soc_data *lwb_soc_data[] = {
	&lwb_cm0_soc_data,
	&lwb_cm1_soc_data,
	&lwb_cm2_soc_data,
	&lwb_cm3_soc_data,
	&lwb_cm4_soc_data,
	&lwb_cm5_soc_data,
	NULL,
};

static const struct acpi_device_id lwb_pinctrl_acpi_match[] = {
	{ "INT5566", (kernel_ulong_t)lwb_soc_data },
	{ }
};
MODULE_DEVICE_TABLE(acpi, lwb_pinctrl_acpi_match);

static int lwb_pinctrl_probe(struct platform_device *pdev)
{
	const struct intel_pinctrl_soc_data *soc_data = NULL;
	const struct intel_pinctrl_soc_data **soc_table = NULL;
	const struct acpi_device_id *id;
	struct acpi_device *adev;
	int i;

	adev = ACPI_COMPANION(&pdev->dev);
	if (!adev)
		return -ENODEV;

	id = acpi_match_device(lwb_pinctrl_acpi_match, &pdev->dev);
	if (!id || !id->driver_data)
		return -ENODEV;
	
	soc_table = (const struct intel_pinctrl_soc_data **)id->driver_data;
	
	for (i = 0; soc_table[i]; i++) {
		if (!strcmp(adev->pnp.unique_id, soc_table[i]->uid)) {
			soc_data = soc_table[i];
			break;
		}
	}

	return intel_pinctrl_probe(pdev, soc_data);
}

static const struct dev_pm_ops lwb_pinctrl_pm_ops = {
	SET_LATE_SYSTEM_SLEEP_PM_OPS(intel_pinctrl_suspend,
				     intel_pinctrl_resume)
};

static struct platform_driver lwb_pinctrl_driver = {
	.probe = lwb_pinctrl_probe,
	.remove = intel_pinctrl_remove,
	.driver = {
		.name = "lewisburg-pinctrl",
		.acpi_match_table = lwb_pinctrl_acpi_match,
		.pm = &lwb_pinctrl_pm_ops,
	},
};

static int __init lwb_pinctrl_init(void)
{
	return platform_driver_register(&lwb_pinctrl_driver);
}
subsys_initcall(lwb_pinctrl_init);

static void __exit lwb_pinctrl_exit(void)
{
	platform_driver_unregister(&lwb_pinctrl_driver);
}
module_exit(lwb_pinctrl_exit);

MODULE_AUTHOR("Ricky Chang <rickychang@synology.com>");
MODULE_DESCRIPTION("Intel Rewisurg PCH pinctrl/GPIO driver");
MODULE_LICENSE("GPL v2");
