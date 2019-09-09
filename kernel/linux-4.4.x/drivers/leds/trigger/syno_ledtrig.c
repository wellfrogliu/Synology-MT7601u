#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/leds.h>
#include <linux/delay.h>
#include <linux/timer.h>

#ifdef MY_ABC_HERE

typedef struct _tag_SYNO_LED_TRIGGER_TIMER {
	struct timer_list Timer;
	int DiskActivity;
	int DiskLastActivity;
	int DiskFaulty;
} SYNO_LED_TRIGGER_TIMER;

static SYNO_LED_TRIGGER_TIMER syno_led_trigger_timer[16];
static struct led_trigger syno_led_ledtrig[16];

int *gpGreenLedMap, *gpOrangeLedMap = NULL;  
EXPORT_SYMBOL(gpGreenLedMap);
EXPORT_SYMBOL(gpOrangeLedMap);

void syno_ledtrig_set(int iLedNum, enum led_brightness brightness)
{
	if(0 > iLedNum || 16 <= iLedNum){
		return;
	}

	led_trigger_event(&syno_led_ledtrig[iLedNum], brightness);
}
EXPORT_SYMBOL(syno_ledtrig_set);

void syno_ledtrig_active_set(int iLedNum)
{
	SYNO_LED_TRIGGER_TIMER *pTriggerTimer = NULL;

	if(0 > iLedNum){
		goto END;
	}

	pTriggerTimer = &syno_led_trigger_timer[iLedNum];
	if (1 == pTriggerTimer->DiskFaulty){
		goto END;
	}

	pTriggerTimer->DiskActivity++;
	if (!timer_pending(&pTriggerTimer->Timer)){
		mod_timer(&pTriggerTimer->Timer, jiffies + msecs_to_jiffies(100));
	}

END:
	return;

}
EXPORT_SYMBOL(syno_ledtrig_active_set);

void syno_ledtrig_faulty_set(int iLedNum, int iFaulty)
{
	SYNO_LED_TRIGGER_TIMER *pTriggerTimer = NULL;

	if(0 > iLedNum || 0> iFaulty) {
		return;
	}

	pTriggerTimer = &syno_led_trigger_timer[iLedNum];
	pTriggerTimer->DiskFaulty = iFaulty;
}
EXPORT_SYMBOL(syno_ledtrig_faulty_set);

static void syno_active_ledtrig_timerfunc(unsigned long iLedNum)
{
	SYNO_LED_TRIGGER_TIMER *pTriggerTimer = &syno_led_trigger_timer[iLedNum];

	if (pTriggerTimer->DiskLastActivity != pTriggerTimer->DiskActivity) {
		pTriggerTimer->DiskLastActivity = pTriggerTimer->DiskActivity;
		led_trigger_event(&syno_led_ledtrig[iLedNum], LED_HALF);
		mod_timer(&pTriggerTimer->Timer, jiffies + msecs_to_jiffies(150));
	}else if( 1 == pTriggerTimer->DiskFaulty){
		led_trigger_event(&syno_led_ledtrig[iLedNum], LED_OFF);
	}else{
		led_trigger_event(&syno_led_ledtrig[iLedNum], LED_FULL);
	}
}

static int __init syno_ledtrig_init(void)
{
	int iTriggerNum = 0;
	int err = 0;
	SYNO_LED_TRIGGER_TIMER *pTriggerTimer = NULL;

	syno_led_ledtrig[0].name = "syno_led0_ledtrig";
	syno_led_ledtrig[1].name = "syno_led1_ledtrig";
	syno_led_ledtrig[2].name = "syno_led2_ledtrig";
	syno_led_ledtrig[3].name = "syno_led3_ledtrig";
	syno_led_ledtrig[4].name = "syno_led4_ledtrig";
	syno_led_ledtrig[5].name = "syno_led5_ledtrig";
	syno_led_ledtrig[6].name = "syno_led6_ledtrig";
	syno_led_ledtrig[7].name = "syno_led7_ledtrig";
	syno_led_ledtrig[8].name = "syno_led8_ledtrig";
	syno_led_ledtrig[9].name = "syno_led9_ledtrig";
	syno_led_ledtrig[10].name = "syno_led10_ledtrig";
	syno_led_ledtrig[11].name = "syno_led11_ledtrig";
	syno_led_ledtrig[12].name = "syno_led12_ledtrig";
	syno_led_ledtrig[13].name = "syno_led13_ledtrig";
	syno_led_ledtrig[14].name = "syno_led14_ledtrig";
	syno_led_ledtrig[15].name = "syno_led15_ledtrig";

	for(iTriggerNum = 0 ; iTriggerNum < 16 ; iTriggerNum++){
		err = led_trigger_register(&syno_led_ledtrig[iTriggerNum]);
		if (0 != err ){
			printk("fail to regist tirgger Num %d \n", iTriggerNum);
			break;
		}
		pTriggerTimer = &syno_led_trigger_timer[iTriggerNum];
		pTriggerTimer->DiskFaulty = 0;
		setup_timer(&pTriggerTimer->Timer, syno_active_ledtrig_timerfunc, (unsigned long)iTriggerNum);
	}

	return err;
}
module_init(syno_ledtrig_init);

static void __exit syno_ledtrig_exit(void)
{
	int iTriggerNum = 0;
	 
	for(iTriggerNum = 0 ; iTriggerNum < 16 ; iTriggerNum++){
		led_trigger_unregister_simple(&syno_led_ledtrig[iTriggerNum]);
	}
}
module_exit(syno_ledtrig_exit);

#endif  
