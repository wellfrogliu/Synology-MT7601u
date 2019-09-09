# the core
obj-$(CONFIG_NET_DSA) += dsa_core.o
ifeq ($(CONFIG_SYNO_LSP_ARMADA_16_12), y)
dsa_core-y += dsa.o slave.o dsa2.o
else
dsa_core-y += dsa.o slave.o
endif

# tagging formats
dsa_core-$(CONFIG_NET_DSA_TAG_BRCM) += tag_brcm.o
dsa_core-$(CONFIG_NET_DSA_TAG_DSA) += tag_dsa.o
dsa_core-$(CONFIG_NET_DSA_TAG_EDSA) += tag_edsa.o
dsa_core-$(CONFIG_NET_DSA_TAG_TRAILER) += tag_trailer.o
