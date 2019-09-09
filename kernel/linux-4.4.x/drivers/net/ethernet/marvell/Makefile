#
# Makefile for the Marvell device drivers.
#

obj-$(CONFIG_MVMDIO) += mvmdio.o
obj-$(CONFIG_MV643XX_ETH) += mv643xx_eth.o
ifeq ($(CONFIG_SYNO_LSP_ARMADA_17_04_02), y)
obj-$(CONFIG_MVNETA_BM) += mvneta_bm.o
endif # CONFIG_SYNO_LSP_ARMADA_17_04_02
obj-$(CONFIG_MVNETA) += mvneta.o
obj-$(CONFIG_MVPP2) += mvpp2.o
obj-$(CONFIG_PXA168_ETH) += pxa168_eth.o
obj-$(CONFIG_SKGE) += skge.o
obj-$(CONFIG_SKY2) += sky2.o
ifeq ($(CONFIG_SYNO_LSP_ARMADA_16_12), y)
obj-$(CONFIG_MVXMDIO) += mvxmdio.o
obj-$(CONFIG_MVPP2X) += mvpp2x/
obj-$(CONFIG_MVNET_COMPLEX) += net_complex/mv_net_complex_a39x.o
obj-$(CONFIG_MVPP3) += pp3/
endif
