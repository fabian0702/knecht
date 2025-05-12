#!/usr/bin/env python3

from pwn import *
from knecht import *

{bindings}

context.binary = exe


def conn():
    if args.LOCAL:
        r = exe.process()
    elif args.DOCKER:
        r = docker("localhost", 1337)
    elif args.QILING:
        r = qiling([exe.path])
    else:
        r = remote("localhost", 1337)

    if args.GDB:
        gdb.attach(r)

    script(r)


def script(r:remote|process|docker|qiling):
    
	{interactions}

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    r = conn()
    script(r)