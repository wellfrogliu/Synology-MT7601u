/* Copyright (c) 2016 Synology Inc. All rights reserved. */

#include <asm/io.h>
#include <linux/serial_reg.h>
#include "rtd129x_syno_uart1.h"

void syno_uart1_write(u32 cmd)
{
    u32 data = 0;
    void __iomem * rstn_ur1 = ioremap(RTK_RSTN_UR1_ADDR, 4);
    void __iomem * clk_en_ur1 = ioremap(RTK_CLK_EN_UR1_ADDR, 4);
    void __iomem * base_addr = ioremap(RTK_UR1_BASE_ADDR, 0x100);

    data = __raw_readl(rstn_ur1);
    data |= (1 << 28);
    __raw_writel(data, rstn_ur1);

    data = __raw_readl(clk_en_ur1);
    data |= (1 << 28);
    __raw_writel(data, clk_en_ur1);

    __raw_writeb(SET8N1 & 0xff, base_addr + (UART_LCR << 2));
    __raw_writeb(cmd & 0xff, base_addr + (UART_TX << 2));
}
