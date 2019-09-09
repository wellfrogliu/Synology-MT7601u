#ifndef __IR_INPUT_H
#define __IR_INPUT_H

#include <linux/input.h>
#include <linux/slab.h>
#include <linux/types.h>

int venus_ir_input_init(void);
void venus_ir_input_cleanup(void);
void venus_ir_input_report_key(uint32_t keycode);
void venus_ir_input_report_end(void);

#endif
