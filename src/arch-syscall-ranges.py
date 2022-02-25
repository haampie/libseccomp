#!/usr/bin/env python3

KERNEL_DICT = {
        "KV_PRE_5_17": 0,
        "KV_5_17": 1,
        "KV_5_18": 2,

        "KV_UNDEF": -1,
        "KV_UNKNOWN": -2,
}


class Arch(object):
    def __init__(self, name):
        self.name = name
        self.syscall_nums = list()
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
            arch_cnt = len(cols) - 1
            kernel_version = col.split(' ')[1][1:]
            date = col.split(' ')[2][:-1]
            settings = Settings(kernel_version, arch_cnt, date)
        else:
            settings.arch[idx - 1] = Arch(col.strip())

    return settings


def parse_syscalls_data(settings, line):
    cols = line.split(',')
    if len(cols) - 1 != settings.arch_cnt:
        raise IndexError(
                '{} architectures were specified in the header, but '
                'syscall {} has only {} architectures specified'.format(
                settings.arch_cnt, cols[0], len(cols) - 1))

    for idx, col in enumerate(cols):
        col = col.strip()

        if idx == 0:
            settings.syscall_names.append(col)
        else:
            settings.arch[idx - 1].syscall_nums.append(col)


def parse_introduced_header(settings, line):
    cols = line.split(',')
    for idx, col in enumerate(cols):
        col = col.strip()

        if idx == 0:
            arch_cnt = len(cols) - 1
            if arch_cnt != settings.arch_cnt:
                raise IndexError(
                        'syscalls.csv has {} architectures, but '
                        'introduced.csv has {} architectures'.format(
                        settings.arch_cnt, arch_cnt))

            kernel_version = col.split(' ')[1][1:]
            if kernel_version != settings.kernel_version:
                raise IndexError(
                        'syscalls.csv is based on kernel {}, but '
                        'introduced.csv is based on kernel {}'.format(
                        settings.kernel_version, kernel_version))
        else:
            # verify the architectures are in the same order in both files
            if settings.arch[idx - 1].name != col:
                raise IndexError(
                        'syscalls.csv has architecture {} in column {}, but '
                        'introduced.csv has architecture {} in column {}'.format(
                        settings.arch[idx - 1].name, idx, col, idx))

    return settings


def parse_introduced_data(settings, line, line_num):
    cols = line.split(',')
    if len(cols) - 1 != settings.arch_cnt:
        raise IndexError(
                '{} architectures were specified in the header, but '
                'syscall {} has only {} architectures specified'.format(
                settings.arch_cnt, cols[0], len(cols) - 1))

    for idx, col in enumerate(cols):
        col = col.strip()

        if idx == 0:
            if settings.syscall_names[line_num - 1] != col:
                raise IndexError(
                    'syscalls.csv has syscall {} in row {}, but '
                    'introduced.csv has syscalll {} in row {}'.format(
                    settings.syscall_names[line_num - 1], line_num, col,
                    line_num))

        else:
            kernel_enum = KERNEL_DICT[col]
            settings.arch[idx - 1].introduced_version.append(kernel_enum)

            if kernel_enum == KERNEL_DICT['KV_UNKNOWN']:
                # The date this syscall for this architecture was introduced
                # into the kernel is unknown.  Invalidate the entire arch
                settings.arch[idx - 1].valid = False

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
            print(arch.ranges[key])


if __name__ == '__main__':
    with open('syscalls.csv', 'r') as f:
        for idx, line in enumerate(f):
            if idx == 0:
                settings = parse_syscalls_header(line)
            else:
                parse_syscalls_data(settings, line)

    with open('introduced.csv', 'r') as f:
        for idx, line in enumerate(f):
            if idx == 0:
                parse_introduced_header(settings, line)
            else:
                parse_introduced_data(settings, line, idx)

    for arch in settings.arch:
        build_ranges(arch)
