#!/bin/bash

USB_USBMODEM_MAP="./usb.usbmodem.table"
USB_USBMODEM_ERROR_FILE="./usb.usbmodem.error"
USBMODEM_DRIVER_LIST="option qmi_wwan cdc-acm sierra"
USBMODEM_OPTION_DIR="drivers/usb/serial/option.c"
USBMODEM_CDC_ACM_DIR="drivers/usb/class/cdc-acm.c"
USBMODEM_SIERRA_DIR="drivers/usb/serial/sierra.c"

DEVICE_KEY="USB_DEVICE("
VENDOR_INTERFACE_INFO_KEY="USB_VENDOR_AND_INTERFACE_INFO("
DEVICE_INTERFACE_INFO_KEY="USB_DEVICE_AND_INTERFACE_INFO("
DEVICE_INTERFACE_CLASS_KEY="USB_DEVICE_INTERFACE_CLASS("

Find_String=""

find_string_define() {
	local string=$1
	local find=`echo ${string} | grep -c '0x[0-9a-fA-F]\{3,4\}'`
	if [ $find -lt 1 ]; then
		#In RTL8187_DIR, vendor is assigned to USB_VENDER_ID_REALTEK, in this case, the definition must be returned
		local string_define=`grep -wr ${string} ${2} | awk '/define/{print $3}'`
		find=`echo ${string_define} | grep -c '0x[0-9a-fA-F]\{3,4\}'`
		if [ $find -lt 1 ]; then
			Find_String=""
		else
			Find_String=${string_define}
		fi
	else
		Find_String=${string}
	fi
}

generate_device_interface_class_table() { #$1 table-name, $2 map-file-name, $3 error-file-name
	local record=""
	# ex. line is like {USB_DEVICE_INTERFACE_CLASS(BANDRICH_VENDOR_ID, BANDRICH_PRODUCT_C100_1, 0xff) },

	for line in `grep -r ${DEVICE_INTERFACE_CLASS_KEY} $1 | cut -d'(' -f2 | cut -d')' -f1 | sed 's/ //g'`; do
		local vendor=`echo ${line} | cut -d',' -f1`
		local product=`echo ${line} | cut -d',' -f2`
		find_string_define ${vendor} $1
		if [ ${#Find_String} -eq 0 ]; then
			record=$3
		else
			vendor=${Find_String}
			find_string_define ${product} $1
			if [ ${#Find_String} -eq 0 ]; then
				record=$3
			else
				product=${Find_String}
				record=$2
			fi
		fi

		echo "(${vendor}:${product},${driver})" >> ${record}
	done
}

generate_vendor_interface_info_table() {
	local record=""
	# ex. line is like { USB_VENDOR_AND_INTERFACE_INFO(0x05ac, 0xff, 0x01, 0x01) },

	for line in `grep -r ${VENDOR_INTERFACE_INFO_KEY} $1 | cut -d'(' -f2 | cut -d')' -f1 | sed 's/ //g'`; do
		local vendor=`echo ${line} | cut -d',' -f1`
		find_string_define ${vendor} $1
		if [ ${#Find_String} -eq 0 ]; then
			record=$3
		else
			vendor=${Find_String}
			record=$2
		fi

		local checkrepeat=`grep "VENDOR(${vendor},${driver})" ${record}`
		if [ "${checkrepeat}" == "" ]; then
			echo "VENDOR(${vendor},${driver})" >> ${record}
		fi
	done
}

generate_device_interface_info_table() {
	local record=""
	# ex. line is like { USB_DEVICE_AND_INTERFACE_INFO(0x2001, 0x7d01, 0xff, 0x02, 0x01) },

	for line in `grep -r ${DEVICE_INTERFACE_INFO_KEY} $1 | cut -d'(' -f2 | cut -d')' -f1 | sed 's/ //g'`; do
		local vendor=`echo ${line} | cut -d',' -f1`
		local product=`echo ${line} | cut -d',' -f2`
		find_string_define ${vendor} $1
		if [ ${#Find_String} -eq 0 ]; then
			record=$3
		else
			vendor=${Find_String}
			record=$2
		fi

		find_string_define ${product} $1
		if [ ${#Find_String} -eq 0 ]; then
			record=$3
		else
			product=${Find_String}
			record=$2
		fi

		echo "(${vendor}:${product},${driver})" >> ${record}
	done
}

generate_entry_table() { #$1 table-name, $2 map-file-name, $3 error-file-name
	local record=""
	# ex. line is like { USB_DEVICE(0x07d1, 0x3c13) },

	for line in `grep -r ${DEVICE_KEY} $1 | cut -d'(' -f2 | cut -d')' -f1 | sed 's/ //g'`; do
		local vendor=`echo ${line} | cut -d',' -f1`
		local product=`echo ${line} | cut -d',' -f2`
		find_string_define ${vendor} $1
		if [ ${#Find_String} -eq 0 ]; then
			record=$3
		else
			vendor=${Find_String}
			find_string_define ${product} $1
			if [ ${#Find_String} -eq 0 ]; then
				record=$3
			else
				product=${Find_String}
				record=$2
			fi
		fi

		echo "(${vendor}:${product},${driver})" >> ${record}
	done
}

create_driver_entry() { #$1: driver-name
	local TABLE_SEARCH=""
	local driver=$1

	case $1 in
		option)
			TABLE_SEARCH=${USBMODEM_OPTION_DIR}
			;;
		cdc-acm)
			TABLE_SEARCH=${USBMODEM_CDC_ACM_DIR}
			;;
		sierra)
			TABLE_SEARCH=${USBMODEM_SIERRA_DIR}
			;;
		*)
			;;
	esac

	generate_entry_table ${TABLE_SEARCH} ${USB_USBMODEM_MAP} ${USB_USBMODEM_ERROR_FILE}
	generate_vendor_interface_info_table ${TABLE_SEARCH} ${USB_USBMODEM_MAP} ${USB_USBMODEM_ERROR_FILE}
	generate_device_interface_info_table ${TABLE_SEARCH} ${USB_USBMODEM_MAP} ${USB_USBMODEM_ERROR_FILE}
	generate_device_interface_class_table ${TABLE_SEARCH} ${USB_USBMODEM_MAP} ${USB_USBMODEM_ERROR_FILE}
}

create_usb_usbmodem_table() { #$1: driver list
	local driver_list=$1
	if [ -f ${USB_USBMODEM_MAP} ]; then
		rm ${USB_USBMODEM_MAP}
	fi

	if [ -f ${USB_USBMODEM_ERROR_FILE} ]; then
		rm ${USB_USBMODEM_ERROR_FILE}
	fi

	driver_list=${USBMODEM_DRIVER_LIST}

	for driver in ${driver_list}; do
		create_driver_entry "${driver}"
	done

	# some device has to match vid pid sub proto class
	# but we only care about vid pid
	# thus the grep will cause duplicate lines
	uniq ${USB_USBMODEM_MAP} > ${USB_USBMODEM_MAP}.tmp
	mv ${USB_USBMODEM_MAP}.tmp ${USB_USBMODEM_MAP}
}

case $1 in
	create-table)
		shift;
		create_usb_usbmodem_table "all"
		;;
	*)
		;;
esac
