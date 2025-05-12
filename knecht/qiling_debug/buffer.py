from pwnlib.tubes.buffer import Buffer

from queue import Queue

import traceback

import time

class FileBuffer:
    def __init__(self, buffer:Buffer=None):
        self.closed = False
        self.buffer = Buffer()
        self.name = 'some_name'

    def write(self, data:bytes) -> None:
        # print('write', data)
        if self.closed:
            raise ConnectionError('Buffer is already closed')
        self.buffer.add(data)

    def read(self, n:int) -> bytes:
        # print('read', n)
        if self.closed:
            raise ConnectionError('Buffer is already closed')
        while not self.buffer.size:
            time.sleep(0.1)
        return self.buffer.get(n)
    
    def close(self):
        self.closed = True
        
    def seek(self, offset: int, origin: int = 0) -> int:
        # Imitate os.lseek
        raise OSError("Illegal Seek")

    def seekable(self) -> bool:
        return False