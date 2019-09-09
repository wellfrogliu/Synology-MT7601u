#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#include <linux/export.h>
#include <linux/init.h>

	__INITRODATA

	.align 8
	.globl VMLINUX_SYMBOL(system_certificate_list)
VMLINUX_SYMBOL(system_certificate_list):
__cert_list_start:
#ifdef CONFIG_MODULE_SIG
	.incbin "certs/signing_key.x509"
#endif
	.incbin "certs/x509_certificate_list"
__cert_list_end:

	.align 8
	.globl VMLINUX_SYMBOL(system_certificate_list_size)
VMLINUX_SYMBOL(system_certificate_list_size):
#ifdef CONFIG_64BIT
	.quad __cert_list_end - __cert_list_start
#else
	.long __cert_list_end - __cert_list_start
#endif

#ifdef MY_ABC_HERE
	.align 8
	.globl VMLINUX_SYMBOL(system_certificate_list_untrusted)
VMLINUX_SYMBOL(system_certificate_list_untrusted):
__cert_list_untrusted_start:
	.incbin "certs/x509_certificate_list_untrusted"
__cert_list_untrusted_end:

	.align 8
	.globl VMLINUX_SYMBOL(system_certificate_list_untrusted_size)
VMLINUX_SYMBOL(system_certificate_list_untrusted_size):
#ifdef CONFIG_64BIT
	.quad __cert_list_untrusted_end - __cert_list_untrusted_start
#else
	.long __cert_list_untrusted_end - __cert_list_untrusted_start
#endif
#endif
