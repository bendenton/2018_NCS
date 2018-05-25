#!/usr/bin/env python2

# Author: Ben Denton (ben@bendenton.com)
# Solves "crackme" from https://github.com/holbertonschool/dont_hate_the_hacker_hate_the_code

# run ./crackme "$(<crackme_solution)" after executing this script to  verify
# Hurray!
import sys
if sys.version_info[0] == 2:  # the tkinter library changed it's name from Python 2 to 3.
    import Tkinter
    tkinter = Tkinter #I decided to use a library reference to avoid potential naming conflicts with people's programs.
else:
    import tkinter
from PIL import Image, ImageTk


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
    if sm.found:
        solution = sm.found[0].solver.eval(env1.get("Passw0rd="), cast_to=str)

# This is a joke. angr can't symolicly execute MD5, it creates a path explosion.
# Comment out the next two lines to remove popup.
    pilImage = Image.open("18NCS_Denton.png")
    showPIL(pilImage)

    return solution

def showPIL(pilImage):
    root = tkinter.Tk()
    w, h = root.winfo_screenwidth(), root.winfo_screenheight()
    root.overrideredirect(1)
    root.geometry("%dx%d+0+0" % (w, h))
    root.focus_set()
    root.bind("<Escape>", lambda e: (e.widget.withdraw(), e.widget.quit()))
    canvas = tkinter.Canvas(root,width=w,height=h)
    canvas.pack()
    canvas.configure(background="#207DAE")
    imgWidth, imgHeight = pilImage.size
    if imgWidth > w or imgHeight > h:
        ratio = min(w/imgWidth, h/imgHeight)
        imgWidth = int(imgWidth*ratio)
        imgHeight = int(imgHeight*ratio)
        pilImage = pilImage.resize((imgWidth,imgHeight), Image.ANTIALIAS)
    image = ImageTk.PhotoImage(pilImage)
    imagesprite = canvas.create_image(w/2,h/2,image=image)
    root.mainloop()


if __name__ == '__main__':
    print(repr(main()))
