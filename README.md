# Synology-MT7601u
### please give a star, if it is usefull! thank you!
this is mt7601u wifi for Synology DS918+, DSM 6.2.1, linux kernel 4.4.59+.

# using
I have compiled so lib in output folder. 
you can copy  wireless folder into /lib/modules. 
```shell
$ unzip Synology-MT7601u-master.zip
$ cd Synology-MT7601u-master/output
$ cp ./wireless /lib/modules
$ sudo mkdir /etc/wpa_supplicant/
$ sudo wpa_passphrase SSID passphrase > /etc/wpa_supplicant/wpa_supplicant.conf
$ sudo ./mt7601u_start.sh
$ ifconfig
```
then the wlan0 will get ip

# build
## if you want compile other so, you need compile kernel, I use Ubuntu 14.04
```shell
$ sudo export CC=/your_path/x86_64-pc-linux-gnu/bin/x86_64-pc-linux-gnu-gcc
$ sudo export RANLIB=/your_path/x86_64-pc-linux-gnu/bin/x86_64-pc-linux-gnu-ranlib
$ sudo export LD=/your_path/x86_64-pc-linux-gnu/bin/x86_64-pc-linux-gnu-ld
$ sudo export LDFLAGS=-L/your_path/x86_64-pc-linux-gnu/x86_64-pc-linux-gnu/sys-root/lib
$ sudo export CFLAGS=-I/your_path/x86_64-pc-linux-gnu/x86_64-pc-linux-gnu/sys-root/usr/include
$ sudo export PATH=$PATH:/your_path/x86_64-pc-linux-gnu/bin/
$ sudo cd Synology-MT7601u-master/kernel/linux-4.4.x
$ sudo cp SynoBuildConf/apollolake .config
$ sudo make menuconfig
$ sudo make modules
$ sudo mkdir modules
$ make modules_install INSTALL_MOD_PATH=./modules
```
you can find so in modules folder.

## if your Synology device was not DS918+ 
you need download your kernel and toolchain, then compile like above.
