# Berlin SoC Family
dtb-$(CONFIG_ARCH_BERLIN) += berlin4ct-dmp.dtb
dtb-$(CONFIG_ARCH_BERLIN) += berlin4ct-stb.dtb

ifeq ($(CONFIG_SYNO_LSP_ARMADA_16_12), y)
# Mvebu SoC Family
dtb-$(CONFIG_ARCH_MVEBU) += armada-3720-db.dtb
ifeq ($(CONFIG_SYNO_LSP_ARMADA_17_06_01), y)
dtb-$(CONFIG_ARCH_MVEBU) += armada-3720-db-B.dtb
dtb-$(CONFIG_ARCH_MVEBU) += armada-3720-db-C.dtb
else # CONFIG_SYNO_LSP_ARMADA_17_06_01
dtb-$(CONFIG_ARCH_MVEBU) += armada-3720-db-sgmii1.dtb
dtb-$(CONFIG_ARCH_MVEBU) += armada-3720-db-sfp.dtb
endif # CONFIG_SYNO_LSP_ARMADA_17_06_01
dtb-$(CONFIG_ARCH_MVEBU) += armada-3720-community.dtb
dtb-$(CONFIG_ARCH_MVEBU) += armada-37x0-customer.dtb
ifeq ($(CONFIG_SYNO_LSP_ARMADA_17_02_02), y)
dtb-$(CONFIG_ARCH_MVEBU) += armada-7040-db-A.dtb
dtb-$(CONFIG_ARCH_MVEBU) += armada-7040-db-B.dtb
ifeq ($(CONFIG_SYNO_LSP_ARMADA_17_04_02), y)
dtb-$(CONFIG_ARCH_MVEBU) += armada-7040-db-C.dtb
ifeq ($(CONFIG_SYNO_LSP_ARMADA_17_06_01), y)
dtb-$(CONFIG_ARCH_MVEBU) += armada-7040-db-D.dtb
endif # CONFIG_SYNO_LSP_ARMADA_17_06_01
dtb-$(CONFIG_ARCH_MVEBU) += armada-7040-db-E.dtb
endif # CONFIG_SYNO_LSP_ARMADA_17_04_02
else  # CONFIG_SYNO_LSP_ARMADA_17_02_02
dtb-$(CONFIG_ARCH_MVEBU) += armada-7040-db-router.dtb
endif # CONFIG_SYNO_LSP_ARMADA_17_02_02
dtb-$(CONFIG_ARCH_MVEBU) += armada-7040-db-nand.dtb
dtb-$(CONFIG_ARCH_MVEBU) += armada-7040-db-all-pcie.dtb
dtb-$(CONFIG_ARCH_MVEBU) += armada-70x0-customer.dtb
ifeq ($(CONFIG_SYNO_LSP_ARMADA_17_04_02), y)
dtb-$(CONFIG_ARCH_MVEBU) += armada-7040-pcac.dtb
endif # CONFIG_SYNO_LSP_ARMADA_17_04_02
dtb-$(CONFIG_ARCH_MVEBU_PD) += armada-7040-pd.dtb
dtb-$(CONFIG_ARCH_MVEBU) += armada-8040-db-A.dtb
ifeq ($(CONFIG_SYNO_LSP_ARMADA_17_02_02), y)
dtb-$(CONFIG_ARCH_MVEBU) += armada-8040-db-B.dtb
dtb-$(CONFIG_ARCH_MVEBU) += armada-8040-db-C.dtb
dtb-$(CONFIG_ARCH_MVEBU) += armada-8040-db-D.dtb
dtb-$(CONFIG_ARCH_MVEBU) += armada-8040-db-E.dtb
ifeq ($(CONFIG_SYNO_LSP_ARMADA_17_04_02), y)
# do nothing
else  # CONFIG_SYNO_LSP_ARMADA_17_04_02
dtb-$(CONFIG_ARCH_MVEBU) += armada-8040-db-A0.dtb
endif # CONFIG_SYNO_LSP_ARMADA_17_04_02
else  # CONFIG_SYNO_LSP_ARMADA_17_02_02
dtb-$(CONFIG_ARCH_MVEBU) += armada-8040-db-router.dtb
endif # CONFIG_SYNO_LSP_ARMADA_17_02_02
dtb-$(CONFIG_ARCH_MVEBU) += armada-8040-mcbin.dtb
dtb-$(CONFIG_ARCH_MVEBU) += armada-80x0-customer.dtb
endif

always		:= $(dtb-y)
subdir-y	:= $(dts-dirs)
clean-files	:= *.dtb
