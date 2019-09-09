ACTION="$1"

DVB_HANDLER_FOLDER="/lib/udev/script"
DVB_HANDLER="usb-dvb-util.sh"


if [ "${ACTION}" = "start" ]; then
	echo "yes" > ${DVB_HANDLER_FOLDER}/DTV_enabled
	[ -e "${DVB_HANDLER_FOLDER}/manual_gen_hotplug.sh" ] && ${DVB_HANDLER_FOLDER}/manual_gen_hotplug.sh "add"
else
	echo "no" > ${DVB_HANDLER_FOLDER}/DTV_enabled
	[ -e "${DVB_HANDLER_FOLDER}/manual_gen_hotplug.sh" ] && ${DVB_HANDLER_FOLDER}/manual_gen_hotplug.sh "remove"
fi
