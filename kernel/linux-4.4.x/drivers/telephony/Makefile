#
# linux/drivers/telephony/Makefile
#

ifeq ($(CONFIG_SYNO_LSP_ARMADA_16_12), y)
ifeq ($(CONFIG_SYNO_LSP_ARMADA_17_02_02), y)
obj-$(CONFIG_MVEBU_PHONE)		+= mvebu_phone/
else  # CONFIG_SYNO_LSP_ARMADA_17_02_02
obj-$(CONFIG_MV_INCLUDE_TDM)		+= mvebu_phone/
endif # CONFIG_SYNO_LSP_ARMADA_17_02_02
endif
