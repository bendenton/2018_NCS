#!/usr/bin/env python2

# Author: Ben Denton (ben@bendenton.com)
# Solves "crackme" from https://github.com/holbertonschool/dont_hate_the_hacker_hate_the_code

# run ./crackme "$(<crackme_solution)" after executing this script to  verify
# Hurray!

import angr
import claripy

def main():
    proj = angr.Project('./crackme2')

    input_size = 0x15;

    env1 = {"Passw0rd=": claripy.BVS('password', input_size * 8)}

    initial_state = proj.factory.entry_state(env=env1)

    for byte in env1.get("Passw0rd=").chop(8):
        initial_state.add_constraints(byte >= '0') # \x30
        initial_state.add_constraints(byte <= 'z') # \x7A
        initial_state.add_constraints(byte != '\x5C') # \
        initial_state.add_constraints(byte != '\x60') # `

    sm = proj.factory.simulation_manager(initial_state)

    avoid_addr=[0x400a36, 0x40094e, 0x4008e4]
    sm.explore(find=0x400a25, avoid=avoid_addr)

    solution = sm.found[0].solver.eval(argv1, cast_to=str)

    return solution

if __name__ == '__main__':
    print(repr(main()))
