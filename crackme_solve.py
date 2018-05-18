#!/usr/bin/env python2

# Author: Ben Denton (ben@bendenton.com)
# Solves "crackme" from https://github.com/holbertonschool/dont_hate_the_hacker_hate_the_code

# run ./crackme "$(<crackme_solution)" after executing this script to  verify
# Hurray!

import angr
import claripy

def main():
    proj = angr.Project('./crackme')
    # pick a max length for input.
    # 0x20 is the minimum length. i've no idea why.
    input_size = 0x35;

    # declare argv[1], as a symbolic bit vector.
    # this is the password input from the user.
    argv1 = claripy.BVS('argv1', input_size * 8)

    initial_state = proj.factory.entry_state(args=['./crackme', argv1])

    # constrain 'password' to terminal friendly, printable character
    for byte in argv1.chop(8):
        initial_state.add_constraints(byte >= '0') # \x30
        initial_state.add_constraints(byte <= 'z') # \x7A
        initial_state.add_constraints(byte != '\x5C') # \
        initial_state.add_constraints(byte != '\x60') # `
        # initial_state.add_constraints(byte != '@')
        # initial_state.add_constraints(byte != ';')
        # initial_state.add_constraints(byte != ':')
        # initial_state.add_constraints(byte != '<')
        # initial_state.add_constraints(byte != '=')
        # initial_state.add_constraints(byte != '>')
        # initial_state.add_constraints(byte != '[')
        # initial_state.add_constraints(byte != ']')
        # initial_state.add_constraints(byte != '^')
        # initial_state.add_constraints(byte != '_')
        # initial_state.add_constraints(byte != '?')

    # Initialize a Sim with the constrained entry_state
    sm = proj.factory.simulation_manager(initial_state)

    # run the Sim looking for a successful path to the find= block
    # ignore any paths that include the avoid= blocks
                  # 0x40061b = success message
    sm.explore(find=0x40061b, avoid=0x40060a)
                                  # 0x40060a = password failure

    # Concretize the symbolic solution, save to a file, and return result
    solution = sm.found[0].solver.eval(argv1, cast_to=str)

    return solution

if __name__ == '__main__':
    print(repr(main()))
