#!/bin/bash
insmod /lib/modules/wireless/lib80211.ko
insmod /lib/modules/wireless/lib80211_crypt_ccmp.ko
insmod /lib/modules/wireless/lib80211_crypt_tkip.ko
insmod /lib/modules/wireless/lib80211_crypt_wep.ko
insmod /lib/modules/wireless/rfkill.ko
insmod /lib/modules/ctr.ko
insmod /lib/modules/ccm.ko
insmod /lib/modules/cfg80211.ko
insmod /lib/modules/mac80211.ko
insmod /lib/modules/mt7601u.ko
sleep 2
ifconfig wlan0 up
wpa_supplicant -i wlan0 -c /etc/wpa_supplicant/wpa_supplicant.conf&
