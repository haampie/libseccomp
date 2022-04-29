#!/usr/bin/env python3
import abc
import argparse
import os
import subprocess
import sys

# The 'v' has been intentionally omitted to allow for mathematical comparisons
FIRST_KNOWN_KERNEL = 3.5
FIRST_KNOWN_KERNEL_ENUM = 'SCMP_KV_3_5'

KERNEL_DICT = {
        'v3.5': 'SCMP_KV_3_5',
        'v3.6': 'SCMP_KV_3_6',
        'v3.7': 'SCMP_KV_3_7',
        'v3.8': 'SCMP_KV_3_8',
        'v3.9': 'SCMP_KV_3_9',
        'v3.10': 'SCMP_KV_3_10',
        'v3.11': 'SCMP_KV_3_11',
        'v3.12': 'SCMP_KV_3_12',
        'v3.13': 'SCMP_KV_3_13',
        'v3.14': 'SCMP_KV_3_14',
        'v3.15': 'SCMP_KV_3_15',
        'v3.16': 'SCMP_KV_3_16',
        'v3.17': 'SCMP_KV_3_17',
        'v3.18': 'SCMP_KV_3_18',
        'v3.19': 'SCMP_KV_3_19',

        'v4.0': 'SCMP_KV_4_0',
        'v4.1': 'SCMP_KV_4_1',
        'v4.2': 'SCMP_KV_4_2',
        'v4.3': 'SCMP_KV_4_3',
        'v4.4': 'SCMP_KV_4_4',
        'v4.5': 'SCMP_KV_4_5',
        'v4.6': 'SCMP_KV_4_6',
        'v4.7': 'SCMP_KV_4_7',
        'v4.8': 'SCMP_KV_4_8',
        'v4.9': 'SCMP_KV_4_9',
        'v4.10': 'SCMP_KV_4_10',
        'v4.11': 'SCMP_KV_4_11',
        'v4.12': 'SCMP_KV_4_12',
        'v4.13': 'SCMP_KV_4_13',
        'v4.14': 'SCMP_KV_4_14',
        'v4.15': 'SCMP_KV_4_15',
        'v4.16': 'SCMP_KV_4_16',
        'v4.17': 'SCMP_KV_4_17',
        'v4.18': 'SCMP_KV_4_18',
        'v4.19': 'SCMP_KV_4_19',
        'v4.20': 'SCMP_KV_4_20',

        'v5.0': 'SCMP_KV_5_0',
        'v5.1': 'SCMP_KV_5_1',
        'v5.2': 'SCMP_KV_5_2',
        'v5.3': 'SCMP_KV_5_3',
        'v5.4': 'SCMP_KV_5_4',
        'v5.5': 'SCMP_KV_5_5',
        'v5.6': 'SCMP_KV_5_6',
        'v5.7': 'SCMP_KV_5_7',
        'v5.8': 'SCMP_KV_5_8',
        'v5.9': 'SCMP_KV_5_9',
        'v5.10': 'SCMP_KV_5_10',
        'v5.11': 'SCMP_KV_5_11',
        'v5.12': 'SCMP_KV_5_12',
        'v5.13': 'SCMP_KV_5_13',
        'v5.14': 'SCMP_KV_5_14',
        'v5.15': 'SCMP_KV_5_15',
        'v5.16': 'SCMP_KV_5_16',
        'v5.17': 'SCMP_KV_5_17',
}

HELP_TEXT = '''Validate when syscalls were added to the kernel\n
*********************************************************************
* WARNING - this script will checkout git tags in the kernel source *
* directory.  Use a clean directory                                 *
*********************************************************************
'''

def parse_args():
    parser = argparse.ArgumentParser(HELP_TEXT)

    parser.add_argument(
                        '-k', '--kernelpath',
                        help='path to the Linux kernel source',
                        required=True,
                        type=str,
                        default=None
                       )
    parser.add_argument(
                        '-v', '--verbose',
                        help='verbose logging to stdout',
                        required=False,
                        action='store_true'
                       )

    return parser.parse_args()

def run(command, shell=True):
    if shell:
        if isinstance(command, str):
            # nothing to do.  command is already formatted as a string
            pass
        elif isinstance(command, list):
            command = ' '.join(command)
        else:
            raise ValueError('Unsupported command type')

    subproc = subprocess.Popen(command, shell=shell,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    out, err = subproc.communicate()
    ret = subproc.returncode

    out = out.strip().decode('UTF-8')
    err = err.strip().decode('UTF-8')

    if ret != 0:
        raise OSError("Command '{}' failed with ret = {} and stderr = {}".format(
            ''.join(command), ret, err))

    return out


class Arch(object):
    def __init__(self):
        self._kernel_path = None
        self.syscall_file = None
        self.arch_name = None

        # a dictionary of syscalls and the line number they appear on
        # e.g. self.syscall_dict['utime'] = 143
        self.syscall_dict = dict()

        # column number in the syscalls.csv file
        self.column = None

    @property
    def kernel_path(self):
        return self._kernel_path

    @kernel_path.setter
    def kernel_path(self, path):
        self._kernel_path = path

    @abc.abstractmethod
    def build_syscall_dict(self):
        raise NotImplementedError


class Arch_x86_64(Arch):
    def __init__(self):
        super().__init__()
        self.syscall_file = 'arch/x86/entry/syscalls/syscall_64.tbl'
        self.arch_name = 'x86_64'

    def build_syscall_dict(self, kernel_version):
        major, minor = kernel_version[1:].split('.')
        major = int(major)
        minor = int(minor)
        if major < 4 or \
           major == 4 and minor <= 1:
            tbl_path = '{}/arch/x86/syscalls/syscall_64.tbl'.format(
                    self.kernel_path)
        else:
            tbl_path = '{}/arch/x86/entry/syscalls/syscall_64.tbl'.format(
                    self.kernel_path)

        cmd = "cat {}" \
              " | grep -v \"^#\"" \
              " | sed 's/:/ /g'" \
              " | awk '{{ print $2,$3,$1 }}'" \
              " | sed '/^x32/d'" \
              " | awk '{{ print $2 }}'" \
              " | sort ".format(tbl_path)
        
        res = run(cmd)

        for syscall in res.splitlines():
            if self.syscall_dict.get(syscall) == None:
                self.syscall_dict[syscall] = KERNEL_DICT[kernel_version]

version_populators = {
        'x86_64_kver': Arch_x86_64(),
        }

def parse_syscalls_csv_header(args, line):
    cols = line.split(',')

    populator_list = [None] * len(cols)

    for idx, col in enumerate(cols):
        try:
            if version_populators[col] is not None:
                version_populators[col].kernel_path = args.kernelpath
                version_populators[col].column = idx

                populator_list[idx] = version_populators[col]
        except KeyError:
            # This column does not have a populator class.  Move on
            continue

    for tag in KERNEL_DICT.keys():
        if args.verbose:
            print('Processing syscalls added in {}'.format(tag))

        run('pushd {};git clean -qdfx;git reset --hard;popd'.format(
            args.kernelpath))
        run('pushd {};git checkout {};popd'.format(args.kernelpath, tag))

        for idx, col in enumerate(cols):
            if populator_list[idx] is not None:
                populator_list[idx].build_syscall_dict(tag)

    return populator_list


def parse_syscalls_csv_data(line, row_num, populators):
    cols = line.split(',')
    updated_line = ''
    error_cnt = 0

    if len(line) == 0:
        return line, 0

    if len(cols) != len(populators):
        raise IndexError(
                '{} columns were specified in the CSV, but '
                'populators[] expects {} columns'.format(
                len(cols), len(populators)))

    for idx, col in enumerate(cols):
        col = col.strip()

        if idx == 0:
            syscall_name = col
            updated_line += col
            updated_line += ','
        else:
            if populators[idx] is not None:
                try:
                    kv_enum = populators[idx].syscall_dict[syscall_name]
                    updated_line += kv_enum
                    updated_line += ','
                except KeyError:
                    error_cnt += 1
                    updated_line += col
                    updated_line += ','
            else:
                updated_line += col
                updated_line += ','

    # remove the trailing comma
    updated_line = updated_line[:-1]
    updated_line += '\n'

    return updated_line, error_cnt


if __name__ == '__main__':
    error_cnt = 0

    args = parse_args()

    updated_syscalls_csv = ''

    with open('syscalls.csv', 'r') as f:
        for idx, line in enumerate(f):
            if idx == 0:
                populators = parse_syscalls_csv_header(args, line)
                updated_syscalls_csv += line
            else:
                updated_line, tmp_error_cnt = parse_syscalls_csv_data(line,
                                                idx, populators)
                updated_syscalls_csv += updated_line
                error_cnt += tmp_error_cnt

    # remove the last newline character
    updated_syscalls_csv = updated_syscalls_csv[:-1]

    with open('syscalls.csv', 'w') as f:
        f.write(updated_syscalls_csv)

    sys.exit(error_cnt)
