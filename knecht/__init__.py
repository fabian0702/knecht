import functools
import time
import os

from pwnlib import gdb, tubes
from pwnlib.util import proc
from pwnlib.timeout import Timeout
from pwnlib.log import getLogger

from knecht.docker_debug import docker
from knecht.qiling_debug import qiling

from knecht.transmit.file import File

log = getLogger(__file__)

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

        elif isinstance(target, tubes.sock.sock):
            pids = proc.pidof(target)
            if not pids:
                log.error('Could not find remote process (%s:%d) on this machine' %
                        target.sock.getpeername())
            pid = pids[0]

            # Specifically check for socat, since it has an intermediary process
            # if you do not specify "nofork" to the EXEC: argument
            # python(2640)───socat(2642)───socat(2643)───bash(2644)
            t = Timeout()
            with t.countdown(2):
                while proc.exe(pid).endswith('/socat') and proc.children(pid):
                    time.sleep(0.1)
                    pid = proc.children(pid)[0]

            # We may attach to the remote process after the fork but before it performs an exec.  
            # If an exe is provided, wait until the process is actually running the expected exe
            # before we attach the debugger.
            t = Timeout()
            with t.countdown(2):
                while exe and os.path.realpath(proc.exe(pid)) != os.path.realpath(exe) and t.timeout:
                    time.sleep(0.1)

            target = pid
            
        return original_function(target, gdbscript, exe, gdb_args, ssh, sysroot, api)
    
    setattr(gdb, 'attach', attach)

hook()

if __name__ == '__main__':
    q = qiling(['rootfs/TerminalMate'])

    gdb.attach(q)

    q.interactive()