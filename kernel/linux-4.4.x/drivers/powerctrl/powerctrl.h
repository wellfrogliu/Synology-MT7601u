#ifndef _POWER_CTRL_H_
#define _POWER_CTRL_H_

enum {PC_NONE = 0, PC_ON, PC_OFF };

struct power_control_priv {
    int count_on;
    int count_off;
    int count_x;
    int last_call;
};

extern struct mutex power_control_list_mutex;

extern struct list_head power_control_list;

#define to_power_control(_p) container_of((_p), struct power_control, list)

#endif
