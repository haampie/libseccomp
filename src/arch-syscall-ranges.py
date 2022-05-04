#!/usr/bin/env python3

C_HEADER_FILE = 'ranges.h'

C_HEADER_START = '''#ifndef _SECCOMP_RANGES_H
#define _SECCOMP_RANGES_H

#ifdef __cplusplus
extern "C" {
#endif
'''

C_HEADER_END = '''#ifdef __cplusplus
}
#endif

#endif
'''

KERNEL_DICT = {
        'KV_UNDEF': -1,
        'KV_UNKNOWN': -2,

        'SCMP_KV_3_5': 100,
        'SCMP_KV_3_6': 101,
        'SCMP_KV_3_7': 102,
        'SCMP_KV_3_8': 103,
        'SCMP_KV_3_9': 104,
        'SCMP_KV_3_10': 105,
        'SCMP_KV_3_11': 106,
        'SCMP_KV_3_12': 107,
        'SCMP_KV_3_13': 108,
        'SCMP_KV_3_14': 109,
        'SCMP_KV_3_15': 110,
        'SCMP_KV_3_16': 111,
        'SCMP_KV_3_17': 112,
        'SCMP_KV_3_18': 113,
        'SCMP_KV_3_19': 114,

        'SCMP_KV_4_0': 115,
        'SCMP_KV_4_1': 116,
        'SCMP_KV_4_2': 117,
        'SCMP_KV_4_3': 118,
        'SCMP_KV_4_4': 119,
        'SCMP_KV_4_5': 120,
        'SCMP_KV_4_6': 121,
        'SCMP_KV_4_7': 122,
        'SCMP_KV_4_8': 123,
        'SCMP_KV_4_9': 124,
        'SCMP_KV_4_10': 125,
        'SCMP_KV_4_11': 126,
        'SCMP_KV_4_12': 127,
        'SCMP_KV_4_13': 128,
        'SCMP_KV_4_14': 129,
        'SCMP_KV_4_15': 130,
        'SCMP_KV_4_16': 131,
        'SCMP_KV_4_17': 132,
        'SCMP_KV_4_18': 133,
        'SCMP_KV_4_19': 134,
        'SCMP_KV_4_20': 135,

        'SCMP_KV_5_0': 136,
        'SCMP_KV_5_1': 137,
        'SCMP_KV_5_2': 138,
        'SCMP_KV_5_3': 139,
        'SCMP_KV_5_4': 140,
        'SCMP_KV_5_5': 141,
        'SCMP_KV_5_6': 142,
        'SCMP_KV_5_7': 143,
        'SCMP_KV_5_8': 144,
        'SCMP_KV_5_9': 145,
        'SCMP_KV_5_10': 146,
        'SCMP_KV_5_11': 147,
        'SCMP_KV_5_12': 148,
        'SCMP_KV_5_13': 149,
        'SCMP_KV_5_14': 150,
        'SCMP_KV_5_15': 151,
        'SCMP_KV_5_16': 152,
        'SCMP_KV_5_17': 153,
        'SCMP_KV_5_18': 154,
}

class Arch(object):
    def __init__(self, name):
        self.name = name

        # A list of each syscall number for this architecture
        self.syscall_nums = list()
        # A list of when the syscall number was introduced.  Must be kept in
        # sync with self.syscall_nums
        self.introduced_version = list()
        self.ranges = dict()
        self.valid = True

    def __str__(self):
        out_str = 'Architecture {}\n'.format(self.name)
        out_str += '\tSyscall # (Introduced):'
        for idx, num in enumerate(self.syscall_nums):
            out_str += '\n\t{} ({})'.format(num, self.introduced_version[idx])

        return out_str


class Settings(object):
    def __init__(self, kernel_version, arch_cnt, date=None):
        self.kernel_version = kernel_version
        self.date = date
        self.arch_cnt = arch_cnt
        self.arch = arch_cnt * [None]

        # keep track of the first column of syscall names to ensure that
        # rows don't get accidentally out of sync
        self.syscall_names = list()

    def __str__(self):
        out_str = "Settings:\n"
        out_str += "\tKernel Version: {}".format(self.kernel_version)


def parse_syscalls_header(line):
    cols = line.split(',')
    for idx, col in enumerate(cols):
        if idx == 0:
            arch_cnt = int((len(cols) - 1) / 2)
            kernel_version = col.split(' ')[1][1:]
            date = col.split(' ')[2][:-1]
            settings = Settings(kernel_version, arch_cnt, date)
        elif col.find('kver') == -1:
            settings.arch[int((idx - 1) / 2)] = Arch(col.strip())
        else:
            # ignore the <arch>_kver column
            pass

    return settings


def parse_syscalls_data(settings, line):
    cols = line.split(',')
    if len(cols) - 1 != settings.arch_cnt * 2:
        raise IndexError(
                '{} architectures were specified in the header, but '
                'syscall {} has only {} architectures specified'.format(
                settings.arch_cnt, cols[0], len(cols) - 1))

    for idx, col in enumerate(cols):
        col = col.strip()

        if idx == 0:
            settings.syscall_names.append(col)
        # TODO - We should probably make this search smarter rather than
        # depending upon 'KV_' being in the kernel version column
        elif col.find('KV_') == -1:
            settings.arch[int((idx - 1) / 2)].syscall_nums.append(col)
        else:
            kernel_enum = KERNEL_DICT[col]
            settings.arch[int((idx - 2) / 2)].introduced_version.append(
                    kernel_enum)


def convert_list_to_ranges(arch, sorted_syscall_nums):
    start = None
    end = None
    ranges = list()

    for idx, syscall_num in enumerate(sorted_syscall_nums):
        if start is None:
            start = syscall_num
            continue

        if syscall_num <= start:
            raise ArithmeticError(
                    'Unexpected syscall number.  start is {}, but the next'
                    ' number in the list, {}, is <= start'.format(
                    start, syscall_num))

        if syscall_num > sorted_syscall_nums[idx - 1] + 1:
            # We have jumped at least two syscall numbers
            ranges.append([start, sorted_syscall_nums[idx - 1]])
            start = syscall_num

    # The last range was never ended in the for loop.  Append it now
    ranges.append([start, sorted_syscall_nums[-1]])

    return ranges

def build_ranges(arch):
    if not arch.valid:
        return

    #### HACK
    if arch.name != 'x86_64':
        return

    for key in KERNEL_DICT:
        valid_syscall_nums = list()

        for idx, syscall_num in enumerate(arch.syscall_nums):
            if arch.introduced_version[idx] >= 0 and \
               arch.introduced_version[idx] <= KERNEL_DICT[key]:
                valid_syscall_nums.append(int(syscall_num))

        if len(valid_syscall_nums) > 0:
            valid_syscall_nums.sort()
            arch.ranges[key] = convert_list_to_ranges(arch, valid_syscall_nums)

def print_range(hf, arch_name, key, ranges):
    hf.write('struct range ranges_{}_{}[] = {{\n'.format(arch_name, key))
    for rng in ranges:
        hf.write('\t{{{}, {}}},\n'.format(rng[0], rng[1]))
    hf.write('};\n\n')

def print_arch_ranges(hf, arch):
    if not arch.valid:
        return

    for key in arch.ranges.keys():
        print_range(hf, arch.name, key, arch.ranges[key])

def build_tables(settings):
    ranges_tbl = ''
    sizes_tbl = ''

    ranges_tbl += 'struct range *range_table[{}][{}] = {{\n'.format(
                      len(settings.arch), len(KERNEL_DICT.keys()))
    sizes_tbl += 'uint32_t sizes_table[{}][{}] = {{\n'.format(
                     len(settings.arch), len(KERNEL_DICT.keys()))

    for arch in settings.arch:
        ranges_tbl += '\t{'
        sizes_tbl += '\t{'

        for key in KERNEL_DICT.keys():
            if key == 'SCMP_KV_UNDEF' or key == 'SCMP_KV_UNKNOWN':
                continue

            try:
                # do an arbitrary read to see if this range was populated.
                tmp = arch.ranges[key]
                ranges_tbl += 'ranges_{}_{},'.format(arch.name, key)
                sizes_tbl += '{},'.format(len(arch.ranges[key]))
            except KeyError:
                ranges_tbl += 'NULL,'
                sizes_tbl += '0,'

        # strip off the trailing ','
        ranges_tbl = ranges_tbl[:-1]
        sizes_tbl = sizes_tbl[:-1]

        ranges_tbl += '},\n'
        sizes_tbl += '},\n'

    # strip off the trailing ',\n'
    ranges_tbl = ranges_tbl[:-2]
    sizes_tbl = sizes_tbl[:-2]

    ranges_tbl += '\n};\n'
    sizes_tbl += '\n};\n'

    return ranges_tbl, sizes_tbl

def print_tables(hf, settings):
    ranges_tbl, sizes_tbl = build_tables(settings)

    hf.write(ranges_tbl)
    hf.write('\n')
    hf.write(sizes_tbl)
    hf.write('\n')

def print_header_file(settings):
    with open(C_HEADER_FILE, 'w') as hf:
        hf.write(C_HEADER_START)

        for arch in settings.arch:
            print_arch_ranges(hf, arch)

        print_tables(hf, settings)

        hf.write(C_HEADER_END)

if __name__ == '__main__':
    with open('syscalls.csv', 'r') as f:
        for idx, line in enumerate(f):
            if idx == 0:
                settings = parse_syscalls_header(line)
            else:
                parse_syscalls_data(settings, line)

    for arch in settings.arch:
        build_ranges(arch)

    print_header_file(settings)
