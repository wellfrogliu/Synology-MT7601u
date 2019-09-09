#!/bin/sh
# Copyright (c) 2000-2015 Synology Inc. All rights reserved.
# Since this script is called by udev, it should be completed within 30 seconds.
# Otherwise it will be terminated by udev before completing its jobs!

. /etc.defaults/rc.subr

ACTION=$1
ID_VENDOR=$2
ID_PRODUCT=$3
MAJOR_NUM=$4
MINOR_NUM=$5
TABLE_DIR="/lib/udev/devicetable"
DVB_DEP_TABLE="${TABLE_DIR}/usb.DVB.dep.table"
DVB_VIDPID_TABLE="${TABLE_DIR}/usb.DVB.VIDPID.table"
DVB_DRIVER=""
SYS_NODE_PATH="/sys/class/dvb"
DEV_NODE_PATH="/dev/dvb"
KernelVersion=""
DTVDAEMON_PID="/var/run/synodtvd.pid"
DTV_ENABLED_KEY="/lib/udev/script/DTV_enabled"
LIBMODULES="compat soundcore snd-page-alloc snd snd-pcm snd-timer"

if [ -f ${DTV_ENABLED_KEY} -a "yes" = "`cat ${DTV_ENABLED_KEY}`" ] || [ "${ACTION}" = "remove" ]; then
	true
else
	exit
fi

if [ "4" = "`uname -r | cut -d'.' -f1`" ]; then
	if [ "4" = "`uname -r | cut -d'.' -f2`" ]; then
		KernelVersion="4.4.x"
	else
		KernelVersion="3.x"
	fi
else
	echo "Not supported kernel ... exit now" >> /tmp/usbdebug
	exit
fi

NotifyDaemon() {
	sleep 2s #for Qoriq multiple dongle timing issue
	PID=`cat ${DTVDAEMON_PID}`
	if [ ! -z "${PID}" ] && [ "${PID}" -gt "0" ]; then
		kill -s USR1 ${PID}
	fi
}

MakeNodes () {
	[ -d "${DEV_NODE_PATH}" ] || mkdir -p ${DEV_NODE_PATH}

	if [ ! -d "${SYS_NODE_PATH}" ]; then
		echo "No sys dvb folders" >> /tmp/usbdebug;
		return;
	fi

	sleep 3s

	for NodePath in `find ${SYS_NODE_PATH} -name "*dvb*" | grep "dvb[0-9]"`;
	do
		[ -n "${NodePath}" ] || continue;
		Node=`echo ${NodePath} | cut -d'.' -f2`
		Num=`echo ${NodePath} | cut -d'/' -f5 | cut -d'.' -f1 | cut -d'b' -f2`
		Major=`cat ${NodePath}/dev | cut -d':' -f1`
		Minor=`cat ${NodePath}/dev | cut -d':' -f2`

		mkdir -p ${DEV_NODE_PATH}/adapter${Num}/
		mknod ${DEV_NODE_PATH}/adapter${Num}/${Node} -m 777 c ${Major} ${Minor}
	done
}

RemoveNodes () {
	rm -rf ${DEV_NODE_PATH}
}

PlugInUSB () {
	SYNOLoadModules ${DVB_DRIVER}

	RemoveNodes
	MakeNodes
}

PlugOutUSB () {
	SYNOUnloadModules ${DVB_DRIVER}

	RemoveNodes
	MakeNodes
}

BlockSpecificModule () {
	local ModuleName="$1"
	local BlockModuleList="smsdvb smsusb"
	local BlockPlatformList="ppc853x qoriq"
	for BlockPlatform in ${BlockPlatformList} ; do
		local Platform=`uname -a |grep ${BlockPlatform}`
		if [ -z ${Platform} ] ; then
			continue
		fi
		for BlockModule in ${BlockModuleList} ; do
			if [ "${BlockModule}" = "${ModuleName}" ] ; then
				return 1
			fi
		done
	done
	return 0
}
GetDVBDriver () {
	# idVendor and idProduct show be regular hex format
	echo "${ID_VENDOR}" | egrep "\b0[xX][0-9a-fA-F]+\b" > /dev/null
	if [ $? != 0 ]; then
		return;
	fi

	echo "${ID_PRODUCT}" | egrep "\b0[xX][0-9a-fA-F]+\b" > /dev/null
	if [ $? != 0 ]; then
		return;
	fi

	[ -e "${DVB_DEP_TABLE}" ] || return;
	[ -e "${DVB_VIDPID_TABLE}" ] || return;
	[ -n "${KernelVersion}" ] || return;

	local IDStartLine=`grep -n "#Kernel ${KernelVersion} - VIDPID - start" ${DVB_VIDPID_TABLE} | cut -d':' -f1`
	local IDEndLine=`grep -n "#Kernel ${KernelVersion} - VIDPID - end" ${DVB_VIDPID_TABLE} | cut -d':' -f1`

	#Get the modules that this Vendor ID & Product ID uses
	for GetModule in `awk 'NR > '"${IDStartLine}"' && NR < '"${IDEndLine}"' {print $0}' ${DVB_VIDPID_TABLE} | grep -i "${ID_VENDOR}:" | grep -i "${ID_PRODUCT}," | cut -d',' -f2 | cut -d')' -f1`;
	do
		[ -n "${GetModule}" ] || continue;
		local DepStartLine=`grep -n "#Kernel ${KernelVersion} - ModuleDep - start" ${DVB_DEP_TABLE} | cut -d':' -f1`
		local DepEndLine=`grep -n "#Kernel ${KernelVersion} - ModuleDep - end" ${DVB_DEP_TABLE} | cut -d':' -f1`

		#Get the module list that this module depends
		GetModuleList="`awk 'NR > '"${DepStartLine}"' && NR < '"${DepEndLine}"' {print $0}' ${DVB_DEP_TABLE} | grep "${GetModule}:" | cut -d':' -f2`"
		[ -n "${GetModuleList}" ] || continue;

		BlockSpecificModule "${GetModule}"

		if [ "$?" != 0 ] ; then
			continue
		fi

		#For multi dongle purpose
		local file="`ls "/tmp" | grep "^${GetModule}\\.[1-9][0-9]*$"`"
		local name="`echo ${file} | cut -d'.' -f1`"
		local count="`echo ${file} | cut -d'.' -f2`"
		case ${ACTION} in
			[Aa][Dd][Dd])
				#If this module hasn't used before , touch a module.1 to record (means the first time using this module)
				if [ "${file}" = "" ]; then
					touch /tmp/${GetModule}.1
				#If this module has used before , just let module.x = module.(x+1) , and continue to skip adding it into the list
				else
					rm -f /tmp/${file}
					count=$((${count}+1))
					touch /tmp/${name}.${count}
					continue
				fi
				;;
			[Rr][Ee][Mm][Oo][Vv][Ee])
				rm -f /tmp/${file}
				#If someone is using the same module (count > 1) , don't put it in the remove list , just let module.x = module.(x-1) and continue
				if [ "${count}" -gt "1" ]; then
					count=$((${count}-1))
					touch /tmp/${name}.${count}
					continue
				fi
				;;
			*)
				;;
		esac

		if [ -n "${DVB_DRIVER}" ]; then
			DVB_DRIVER="${GetModuleList} ${DVB_DRIVER}"
			DVB_DRIVER=`echo ${DVB_DRIVER} | awk '!arr[$1]++' RS=" "`  # remove duplicated drivers
		else
			DVB_DRIVER="${GetModuleList}"
		fi
	done

	[ -n "${DVB_DRIVER}" ] && echo "It's DVB USB adapter , VendorID = ${ID_VENDOR} , ProductID = ${ID_PRODUCT} , Driver List = ${DVB_DRIVER}" >> /tmp/usbdebug;
}

#Since the Vendor ID or Product ID might be any format of 0x1 , 0x12 , 0x123 , or 0x1234 etc.
#So we need to transform it to 0x0001 , 0x0012 , 0x0123.
FormatVIDPID () {
	local TempVID="`echo ${ID_VENDOR} | awk -F"0x" {'print $2'}`"
	local TempPID="`echo ${ID_PRODUCT} | awk -F"0x" {'print $2'}`"
	local LenTempVID="${#TempVID}"
	local LenTempPID="${#TempPID}"
	local Loop=0

	while [ "${Loop}" != "$((4-${LenTempVID}))" ];
	do
		TempVID="0${TempVID}"
		Loop=$((${Loop}+1))
	done

	Loop=0

	while [ "${Loop}" != "$((4-${LenTempPID}))" ];
	do
		TempPID="0${TempPID}"
		Loop=$((${Loop}+1))
	done

	ID_VENDOR="0x${TempVID}"
	ID_PRODUCT="0x${TempPID}"
}

#Main
(
flock -x 200
if [ "${MAJOR_NUM}" == "" -o "${MINOR_NUM}" == "" ]; then
	exit
fi

FormatVIDPID

GetDVBDriver

if [ -n "${DVB_DRIVER}" ]; then
	case ${ACTION} in
		[Aa][Dd][Dd])
			PlugInUSB
			;;
		[Rr][Ee][Mm][Oo][Vv][Ee])
			PlugOutUSB
			;;
		*)
			;;
	esac
fi
NotifyDaemon
) 200>/tmp/dvbpluglock
