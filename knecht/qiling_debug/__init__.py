import os
import socket

from threading import Thread
from io import BytesIO
from tarfile import TarFile
from typing import Callable

import docker
import tqdm

from qiling import Qiling
from qiling.debugger.gdb.gdb import QlGdb
from qiling.core import QL_VERBOSE
from qiling.extensions import pipe

from pwnlib.tubes.tube import tube
from pwnlib.log import getLogger
from pwnlib.timeout import Timeout

from docker.models.images import Image
from docker.models.containers import Container


log = getLogger(__file__)

class qiling(tube):
    timeout:int = -1
    _stop:bool = False
    def __init__(self, argv:list[str], env:dict[str, str] = None, docker_image:str|Image=None, rootfs:str=None, run:bool = True, verbose=QL_VERBOSE.DISABLED, *args, **kwargs):
        rootfs = rootfs or self.get_rootfs_from_image(docker_image)
        self.ql = Qiling(*args, argv=argv, rootfs=rootfs, env=env or os.environ, verbose=verbose, **kwargs)
        super(qiling, self).__init__()
        self._timeout = self._get_timeout_seconds(Timeout.default)
        self.ql.os.stdin = pipe.SimpleStringBuffer()
        self.ql.os.stdout = pipe.SimpleStringBuffer()
        if run:
            self.fire_and_forget(self.ql.run)

    def fire_and_forget(self, function:Callable, *args, **kwargs):
        t = Thread(target=function, args=args, kwargs=kwargs, daemon=True)
        t.start()

    def get_rootfs_from_image(self, image:str|Image=None):
        client = docker.from_env()

        if os.path.exists('rootfs'):
            return 'rootfs'

        if isinstance(image, str):
            image = client.images.get(image)

        total_size = sum(layer['Size'] for layer in image.history())

        container:Container = client.containers.create(image=image, command=['/bin/false'])
        tar_file = BytesIO()
        with tqdm.tqdm(desc="Exporting rootfs", unit="B", unit_scale=True, unit_divisor=1024, total=total_size) as progress:
            for chunk in container.export():
                tar_file.write(chunk)
                progress.update(len(chunk))

        tar_file.seek(0)

        with TarFile(fileobj=tar_file) as tar:
            tar.extractall(os.path.join(os.getcwd(), 'rootfs/'))
        
        container.remove()

    def send_raw(self, data):
        return self.ql.os.stdin.write(data)
    
    def recv_raw(self, numb):
        return self.ql.os.stdout.read(numb)
    
    def can_recv_raw(self, timeout):
        return self.ql.os.stdout.readable()
    
    def shutdown(self, direction="send"):
        if direction == 'send':
            self.ql.os.stdin.close()
        else:
            self.ql.os.stdout.close()
        
        self.ql.stop()

    def close(self):
        self._stop = True
        return self.ql.stop()
    
    def find_free_port(self):
        """find a free port assigned by the os"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            _, port = s.getsockname()
            return '0.0.0.0', port

    def start_debugger(self):
        """start the debugger on a new free portsd"""
        host, port = self.find_free_port()
        debugger = QlGdb(self.ql, host, port)
        self.fire_and_forget(debugger.run)
        return (host, port)
        