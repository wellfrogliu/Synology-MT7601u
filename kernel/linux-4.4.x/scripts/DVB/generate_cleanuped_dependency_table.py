#!/usr/bin/env python2
'''
Filter dependency table, keep only final driver dependency chains
appeared in VIDPID table
'''
import codecs
import os

DEPENDENCY_TABLE_PATH = './usb.DVB.dep.table'
VIDPID_TABLE_PATH = './usb.DVB.VIDPID.table'
kernel_version = '4.4.x'
def parse_vidpid_drivers():
    if not os.path.exists(VIDPID_TABLE_PATH):
        print('ERROR: VIDPID table file {} not found!'.format(VIDPID_TABLE_PATH))
        sys.exit(1)

    drivers = set()
    with codecs.open(VIDPID_TABLE_PATH,'r', 'utf-8') as f:
        for line in f:
            if line.startswith('#'):
                continue
            drivers.add(line.strip()[:-1].split(',')[1])
    return drivers
print('Filtering kernel {} dvb dependency table...'.format(kernel_version))
drivers = parse_vidpid_drivers()

interested_lines = []
with codecs.open(DEPENDENCY_TABLE_PATH, 'r', 'utf-8') as f:
    for line in f:
        if line.startswith('#'):
            interested_lines.append(line)
            continue
        driver = line.split(':')[0]
        if driver in drivers:
            interested_lines.append(line)

with codecs.open(DEPENDENCY_TABLE_PATH, 'w', 'utf-8') as f:
    f.writelines(interested_lines)
