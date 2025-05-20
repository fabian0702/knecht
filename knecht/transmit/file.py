from knecht.transmit.stager import Stager
from knecht.transmit.transmitter import Transmitter

from pwnlib.tubes.tube import tube
from pwnlib.log import getLogger

from typing import Optional

import os

log = getLogger(__name__)

class File:
    def __init__(self, client: tube, filename: str, remote_filename:Optional[str] = None, permissions: int = 0o644):
        self.client = client
        self.filename = filename
        self.permissions = permissions
        self.remote_filename = remote_filename or os.path.join('/tmp', os.path.basename(filename))

    def upload(self):
        self.stager = Stager(self.client)
        self.stager.upload()
        self.stager.launch()

        self.transmitter = Transmitter(self.client)
        self.transmitter.send_file(self.filename, self.remote_filename, self.permissions)


if __name__ == "__main__":
    from pwn import process

    client = process(['/bin/sh'])
    file = File(client, './test.png', './transmitted.png')
    file.upload()