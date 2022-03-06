#!/usr/bin/env python3
import abc
import os
import subprocess

KERNEL_DICT = {
        "KV_PRE_5_17": 0,
        "KV_5_17": "v5.17",
        "KV_5_18": "v5.18",

        "KV_UNDEF": -1,
        "KV_UNKNOWN": -2,
}

def run(command, shell=False):
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
        #self.kernel_path = None
        # HACK
        self.kernel_path = '/home/thromatka/git/clean/upstream-torvalds'
        self.syscall_file = None

        # a dictionary of syscalls and the line number they appear on
        # e.g. self.syscall_dict['utime'] = 143
        self.syscall_dict = dict()

    @abc.abstractmethod
    def build_syscall_dict(self):
        raise NotImplementedError

    def get_commit_tag(self, syscall_name):
        syscall_dir = os.path.dirname(self.syscall_file)
        syscall_file = os.path.basename(self.syscall_file)
        cmd = 'pushd {} > /dev/null 2>&1;' \
              'git blame {};' \
              'popd'.format(syscall_dir, syscall_file)

        res = run(cmd, shell=True)

        for line in res.splitlines():
            line_num_str = '{})'.format(self.syscall_dict[syscall_name])
            if line.find(line_num_str) != -1 and \
               line.find(syscall_name) != -1:
                   return line.split()[0]

    def validate(self, syscall_name, tag_enum):
        if tag_enum == 'KV_UNDEF':
            # This syscall doesn't exist on this architecture
            return

        commit_tag = self.get_commit_tag(syscall_name)
        print('syscall {} was added in commit {}'.format(syscall_name, commit_tag))


class Arch_x86_64(Arch):
    def __init__(self):
        super().__init__()
        self.syscall_file = os.path.join(self.kernel_path,
                'arch/x86/entry/syscalls/syscall_64.tbl')

    def build_syscall_dict(self):
        cmd = "cat {}/arch/x86/entry/syscalls/syscall_64.tbl" \
              " | grep -nv \"^#\"" \
              " | sed 's/:/ /g'" \
              " | awk '{{ print $3,$1,$4 }}'" \
              " | sed '/^x32/d'" \
              " | awk '{{ print $3,$2 }}'" \
              " | sort ".format(self.kernel_path)
        
        res = run(cmd, shell=True)

        for line in res.splitlines():
            syscall,line_num = line.split()
            self.syscall_dict[syscall] = line_num
        print(self.syscall_dict)


validators = [
        None,           # column 0
        None,           # column 1, x86
        Arch_x86_64(),  # column 2, x86_64
        None,           # column 3
        None,           # column 4
        None,           # column 5
        None,           # column 6
        None,           # column 7
        None,           # column 8
        None,           # column 9
        None,           # column 10
        None,           # column 11
        None,           # column 12
        None,           # column 13
        None,           # column 14
        None,           # column 15
        None,           # column 16
]

def parse_introduced_header(line):
    cols = line.split(',')
    for idx, col in enumerate(cols):
        if validators[idx] is not None:
            validators[idx].build_syscall_dict()


def parse_introduced_data(line, line_num):
    cols = line.split(',')
    if len(cols) != len(validators):
        raise IndexError(
                '{} architectures were specified in the CSV, but '
                'Validators[] has {} architectures specified'.format(
                len(cols), len(validators)))

    for idx, col in enumerate(cols):
        col = col.strip()

        if idx == 0:
            syscall_name = col
        else:
            if validators[idx] is not None:
                validators[idx].validate(syscall_name, col)


if __name__ == '__main__':
    with open('introduced.csv', 'r') as f:
        for idx, line in enumerate(f):
            if idx == 0:
                parse_introduced_header(line)
            else:
                parse_introduced_data(line, idx)
