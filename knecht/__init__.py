import functools

from pwnlib import gdb

from knecht.docker_debug import docker
from knecht.qiling_debug import qiling


def hook():
    """add a custom handler for the gdb.attach"""

    original_function = getattr(gdb, 'attach')

    @functools.wraps(original_function)
    def attach(target, gdbscript = '', exe = None, gdb_args = None, ssh = None, sysroot = None, api = False):
        if isinstance(target, docker):
            exe = exe or target.exe
            target = target.proxy.remote

        if isinstance(target, qiling):
            exe = target.ql.argv[0]
            target = target.start_debugger()
            
        return original_function(target, gdbscript, exe, gdb_args, ssh, sysroot, api)
    
    setattr(gdb, 'attach', attach)

hook()

if __name__ == '__main__':
    q = qiling(['rootfs/TerminalMate'])

    gdb.attach(q)

    q.interactive()