#!/usr/bin/env python2
'''
This script is for generating DVB driver modules' dependency table.
Prepare folder architecture like this and run me:

---- 2.6.32 --- a8293.ko    <- untar kernel 2.6.32 DVB drivers here
 |          |-- adv7170.ko
 |          |-- adv7175.ko
 |          |-- ...
 |
 |-- 3.x ------ a8293.ko    <- untar kernel 3.x DVB drivers here
 |          |-- adv7170.ko
 |          |-- adv7175.ko
 |          |-- ...
 |
 |-- generate_dependency_table.py    <- put me here and run me
 |-- usb.DVB.dep.table               <- this will be generated
 |-- debug.log.2.6.32                <- generated debug log
 |-- debug.log.3.x                   <- generated debug log

'''
import codecs
import collections
import glob
import os
import string
import subprocess
import sys

DEBUG = True
MY_PATH = '.'
DEPENDENCY_TABLE_PATH = os.path.join(MY_PATH, 'usb.DVB.dep.table')
DEBUG_LOG_PATH = os.path.join(MY_PATH, 'debug.log')

driver_deps = collections.defaultdict(list)  # driver -> [driver1, driver2, ...]
symbol_source = {}  # symbol -> driver mapping, will be expanded later


def run(cmd):
    subprocess.call([cmd], shell=True)


def dprint(s):
    if DEBUG:
        with codecs.open(DEBUG_LOG_PATH, 'a', 'utf-8') as f:
            f.write(s + '\n')


def drivername(filepath):
    '''
    Convert './*.ko' to *
    '''
    assert(filepath.startswith('./'))
    assert(filepath.endswith('.ko'))
    return filepath[2:-3]


def strings(filepath, min_length=4):
    '''
    Emulate linux command 'strings' but produce more output lines, which is
    critical for completing dependency generation.
    '''
    with open(filepath) as f:
        result = ''
        for c in f.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= min_length:
                yield result
            result = ''


def process_symbol_source(filepath):
    '''
    For example, if we can see '__ksymtab_tda829x_attach' in ./tda8290.ko,
    we know that it's the source of this symbol.
    '''
    global symbol_source
    driver = drivername(filepath)

    for s in strings(filepath):
        if s.startswith('__ksymtab_'):
            # example: '__ksymtab_tda829x_attach'
            symbol = s[len('__ksymtab_'):]
            symbol_source[symbol] = driver
            dprint('Found symbol {} from {}'.format(symbol, driver))


def process_modinfo_dependencies(filepath):
    '''
    Find module dependencies from modinfo.
    The list may be incomplete yet, causing unknown symbol when inserting.
    '''
    global driver_deps
    driver = drivername(filepath)

    depends = subprocess.check_output('modinfo {} | grep "depends:"'.format(filepath), shell=True, universal_newlines=True)
    # example: 'depends:        videobuf-core,videodev,dvb-core,snd,videobuf-vmalloc,usbcore,v4l2-common\n'
    depends = depends.strip()
    if depends == 'depends:':
        # No dependencies. We will add itself as the only dependency later
        return
    dep_list = depends.split()[-1].split(',')

    builtin_drivers = ['usbcore', 'usb-common']  # do not care about DSM's built-in drivers
    dep_list = [dep for dep in dep_list if dep not in builtin_drivers]
    driver_deps[driver].extend(dep_list)
    dprint('{} += {} (modinfo)'.format(driver, dep_list))


def process_strings_dependencies(filepath):
    '''
    The dependency list gathered from modinfo may not be complete...
    1. The module may only complain when inserting it, causing unknown symbol.
       Here we find additional module dependencies from the string
       'Unable to find symbol ...'.
    2. More horribly, some modules just silently insert without any warning,
       then the missing dependency makes DVB dongle unusable!!!!!!!!!!!!!!!!!!
    '''
    global driver_deps
    driver = drivername(filepath)

    for s in strings(filepath):
        if 'Unable to find symbol' in s:
            # example: '<3>DVB: Unable to find symbol tda18271_attach()\n'
            symbol = s.strip().split()[-1][:-2]

            if symbol not in symbol_source:
                possible_driver = symbol.rsplit('_', 1)[0]
                if os.path.exists('./{}.ko'.format(possible_driver)):
                    symbol_source[symbol] = possible_driver
                    dprint('Guess symbol {} is from {}'.format(symbol, possible_driver))
                else:
                    print('ERROR: cannot find source of symbol: {} ({} requires it)'.format(symbol, driver))
                    sys.exit(1)

            source_driver = symbol_source[symbol]
            driver_deps[driver].append(source_driver)
            dprint('{} += {} (Unable to find symbol {})'.format(driver, source_driver, symbol))

        if driver not in s:  # prevent cases like "em28xx" depends on "em28xx-alsa"
            if (driver, s) == ('smsmdtv', 'smsdvb'):  # special cases, they have resursive dependency
                continue
            if (driver, s) == ('v4l2-common', 'tuner'):
                continue
            if (driver, s) == ('videodev', 'tuner'):
                continue
            if os.path.exists('./{}.ko'.format(s)):
                if s not in driver_deps[driver]:
                    driver_deps[driver].append(s)
                    dprint('Guess {} requires {} (strings)'.format(driver, s))


def patch_missing_dependency():
    '''
    Workaround for some modules not depend on other required modules
    '''
    global driver_deps
    driver_missing_deps = {
        'smsdvb': ['smsusb'],
        'poseidon': ['soundcore', 'snd-page-alloc', 'snd', 'snd-timer', 'snd-pcm']
    }
    for driver in driver_deps:
        for patching_driver, missing_deps in driver_missing_deps.items():
            if driver == patching_driver:
                for dep in missing_deps:
                    if dep in driver_deps[driver]:
                        driver_deps[driver].remove(dep)
                for dep in missing_deps:
                    driver_deps[driver].append(dep)


def append_self(filepath):
    '''
    Append self as dependency if not exists yet. For example:
    "A:B C D" becomes "A:B C D A"
    '''
    global driver_deps
    driver = drivername(filepath)

    if driver not in driver_deps or driver not in driver_deps[driver]:
        driver_deps[driver].append(driver)
        dprint('{} += {} (append self)'.format(driver, driver))


def expand_dependency_list():
    '''
    If "A depends on C, B, A" and "B depends on E, C, D, B", it should be
    expanded to: "A depends on C, E, D, B, A"
    '''
    def unique(seq):
        '''
        Keep unique items in seq with original order
        '''
        seen = set()
        return [x for x in seq if not (x in seen or seen.add(x))]

    def expand(driver, processed=None):
        '''
        DFS expand dependency chain
        '''
        if processed is None:
            processed = set()
        drivers = []
        processed.add(driver)
        for dep in driver_deps[driver]:
            if dep not in processed:
                drivers.extend(expand(dep, processed))
        return unique(drivers + [driver])

    global driver_deps

    for driver in sorted(driver_deps.keys()):
        dep_list = expand(driver)
        driver_deps[driver] = dep_list
        dprint('{} = {} (expanded and unique)'.format(driver, driver_deps[driver]))


def write_line(line):
    with codecs.open(DEPENDENCY_TABLE_PATH, 'a', 'utf-8') as f:
        f.write(line + '\n')


def write_dependency_table():
    uninterested = ('usb-common', 'usbcore', 'led-class', 'snd', 'snd-pcm','lirc_dev')
    with codecs.open(DEPENDENCY_TABLE_PATH, 'a', 'utf-8') as f:
        for driver in sorted(driver_deps.keys()):
            # don't list DSM default drivers
            if driver in uninterested:
                continue
            # ignore ir-* modules
            if driver.startswith('ir-'):
                continue
            # ignore *-alsa modules
            if driver.endswith('-alsa'):
                continue
            deps = driver_deps[driver]
            if driver == 'poseidon':
                pass
            else:
                deps = [drivername for drivername in deps if (drivername not in uninterested and not drivername.startswith('ir-'))]
            driver_list = ' '.join(deps)
            f.write('{}:{}\n'.format(driver, driver_list))


def main():
    global driver_deps, symbol_source

    run('rm -f {} {}.*'.format(DEPENDENCY_TABLE_PATH, DEBUG_LOG_PATH))

    #for kernel_version in ('2.6.32', '3.x', '3.10.x'):
    for kernel_version in ('4.4.x',):
        folder = './' + kernel_version
        if not os.path.isdir(folder):
            print('ERROR: folder {} not exists!'.format(folder))
            sys.exit(1)

        print('Generating kernel {} dvb dependency table...'.format(kernel_version))
        driver_deps = collections.defaultdict(list)  # reinitialize
        symbol_source = {}  # reinitialize

        write_line('#Kernel {} - ModuleDep - start'.format(kernel_version))
        os.chdir(folder)
        filelist = glob.glob('./*.ko')

        for filepath in filelist:
            process_symbol_source(filepath)
            process_modinfo_dependencies(filepath)

        for filepath in filelist:
            process_strings_dependencies(filepath)

        patch_missing_dependency()

        for filepath in filelist:
            append_self(filepath)

        expand_dependency_list()
        os.chdir('..')

        write_dependency_table()
        write_line('#Kernel {} - ModuleDep - end'.format(kernel_version))
        if DEBUG:
            run('mv {version}/{log} {log}.{version}'.format(version=kernel_version, log=DEBUG_LOG_PATH))

    print('Dependency table generated as: ' + DEPENDENCY_TABLE_PATH)


if __name__ == '__main__':
    main()
