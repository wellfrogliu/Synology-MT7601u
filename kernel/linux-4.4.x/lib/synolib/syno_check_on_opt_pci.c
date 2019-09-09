#include <linux/synolib.h>
#include <linux/pci.h>

/*
 * Return if the pci_dev on optional PCIe slot.
 *
 * @param pdev [IN] PCI device strct
 *
 * Return 1: pci_dev match
 *        0: pci_dev mismatch
 *       -1: something error
 */
int syno_check_on_option_pci_slot(struct pci_dev *pdev)
{
	int i = 0;
	int iRet = -1;
	char szPciAddress[PCI_ADDR_LEN_MAX + 1];
	struct pci_dev *pdev_cur = NULL;

	if (NULL == pdev) {
		printk("Bad parameter!\n");
		goto END;
	}

	pdev_cur = pdev;

	while (NULL != pdev_cur) {
		snprintf(szPciAddress, sizeof(szPciAddress),"%04x%02x%02x%x",
				pci_domain_nr(pdev_cur->bus), pdev_cur->bus->number,
				PCI_SLOT(pdev_cur->devfn), PCI_FUNC(pdev_cur->devfn));

		for (i = 0; i < gPciAddrNum; i++) {
			if (0 == strncmp(szPciAddress, gszPciAddrList[i], PCI_ADDR_LEN_MAX)) {
				iRet = 1;
				goto END;
			}
		}
		pdev_cur = pdev_cur->bus->self;
	}
	iRet = 0;
END:
	return iRet;
}
