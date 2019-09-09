#!/bin/sh
ACTION=$1
KERNEL_MINOR_NUM=`uname -a | cut -d' ' -f3 | cut -d'.' -f2`
buildnumber=`cat /etc.defaults/VERSION | grep buildnumber | cut -d'"' -f2`
dual_head=`/bin/get_key_value /etc.defaults/synoinfo.conf support_dual_head`
DVB_HANDLER="/lib/udev/script/usb-dvb-util.sh"

if [ "${dual_head}" == "yes" ]; then
	return
fi

SYS_USB_DEV_PATH="/sys/bus/usb/devices"
ALL_USB="`ls -l ${SYS_USB_DEV_PATH} | awk -F"->" '{print $1}' | grep -v "usb"`"

for EACH_USB in ${ALL_USB};
do
	if [ "`echo $EACH_USB | grep "-"`" != "" ]; then
		VID=""
		PID=""
		[ -e "${SYS_USB_DEV_PATH}/$EACH_USB/idVendor" ] && VID="`cat ${SYS_USB_DEV_PATH}/$EACH_USB/idVendor`"
		[ -e "${SYS_USB_DEV_PATH}/$EACH_USB/idProduct" ] && PID="`cat ${SYS_USB_DEV_PATH}/$EACH_USB/idProduct`"
		if [ -n "${VID}" -a -n "${PID}" ]; then
			case ${ACTION} in
				[Aa][Dd][Dd])
					[ -e ${DVB_HANDLER} ] && ${DVB_HANDLER} "add" "0x${VID}" "0x${PID}" "0" "0"
					;;
				[Rr][Ee][Mm][Oo][Vv][Ee])
					[ -e ${DVB_HANDLER} ] && ${DVB_HANDLER} "remove" "0x${VID}" "0x${PID}" "0" "0"
					;;
				*)
					;;
			esac
		fi
	fi
done
