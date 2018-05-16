#!/usr/bin/env python2

# Author: Ben Denton (ben@bendenton.com) | 17 April 2018
# Solves "crackme" from https://github.com/holbertonschool/dont_hate_the_hacker_hate_the_code

# run ./crackme "$(<crackme_solution)" after executing this script to  verify
# Hurray!

import angr

import claripy

def main():
    proj = angr.Project('./crackme')

    input_size = 0x20; # Pick a max length for input, 0x20 is the minimum length

    argv1 = claripy.BVS("argv1", input_size * 8) # declare argv[1], as a symbolic bit vector.  This is the password input from the user.

    initial_state = proj.factory.entry_state(args=["./crackme", argv1])
    
    # For some reason if you constrain too few bytes, the solution isn't found. To be safe, I'm constraining them all.
    for byte in argv1.chop(8):
        initial_state.add_constraints(byte != '\x00') # null
        initial_state.add_constraints(byte != '\x60') # `
        initial_state.add_constraints(byte != '\x5C') # \
        initial_state.add_constraints(byte >= 'A') # \x30
        initial_state.add_constraints(byte <= 'z') # \x7A
        # Source: https://www.juniper.net/documentation/en_US/idp5.1/topics/reference/general/intrusion-detection-prevention-custom-attack-object-extended-ascii.html
        # Constrain to printable characters

    sm = proj.factory.simulation_manager(initial_state)

                  # 0x40061b = success message
    sm.explore(find=0x40061b, avoid=0x40060a)
                                  # 0x40060a = password failure

    found = sm.found[0] # In our case, there's only one printable solution.

    solution = found.solver.eval(argv1, cast_to=str)

    f=open("crackme_solution","wb")
    f.write(solution)
    f.close()
    return solution

if __name__ == '__main__':
    print(repr(main()))