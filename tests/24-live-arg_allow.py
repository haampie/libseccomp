#!/usr/bin/env python

#
# Seccomp Library test program
#
# Copyright (c) 2013 Red Hat <pmoore@redhat.com>
# Author: Paul Moore <paul@paul-moore.com>
#

#
# This library is free software; you can redistribute it and/or modify it
# under the terms of version 2.1 of the GNU Lesser General Public License as
# published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library; if not, see <http://www.gnu.org/licenses>.
#

import argparse
import os
import sys

import util

from seccomp import *

def test():
    action = util.parse_action(sys.argv[1])
    if not action == ALLOW:
        quit(1)
    util.install_trap()

    fd = os.open("/dev/null", os.O_WRONLY|os.O_CREAT)

    #print("1")
    f = SyscallFilter(TRAP)
    # NOTE: additional syscalls required for python
    #f.add_rule(ALLOW, "write", Arg(0, EQ, fd))
    f.add_rule(ALLOW, "write", Arg(0, EQ, 0))
    #f.add_rule(ALLOW, "write", Arg(0, EQ, sys.stdout.fileno()))
    #f.add_rule(ALLOW, "write", Arg(0, EQ, sys.stderr.fileno()))
    #f.add_rule(ALLOW, "write", Arg(0, EQ, sys.stdin.fileno()))
    #f.add_rule(ALLOW, "write")
    f.add_rule(ALLOW, "close")
    f.add_rule(ALLOW, "rt_sigaction")
    f.add_rule(ALLOW, "rt_sigreturn")
    #print("2")
    f.add_rule(ALLOW, "sigaltstack")
    f.add_rule(ALLOW, "exit_group")
    f.add_rule(ALLOW, "brk")
    f.load()
    #print("3")

    try:
        if not os.write(fd, b"testing") == len("testing"):
            #print("write failed")
            raise IOError("failed to write the full test string")
        #print("write len did equal")
        quit(160)
    except OSError as ex:
        #print("oserror argh")
        quit(ex.errno)
    os.close(fd)

test()

# kate: syntax python;
# kate: indent-mode python; space-indent on; indent-width 4; mixedindent off;
