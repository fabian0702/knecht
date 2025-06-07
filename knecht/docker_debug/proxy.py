import socket
from pwnlib.tubes.listen import listen
from threading import Thread

import struct

from knecht.docker_debug.utils import log

class proxy:
    def __init__(self, local_socket:socket.socket):
        self.server_socket = listen()
        self.remote = (self.server_socket.lhost, self.server_socket.lport)
        self.local_socket:socket.socket = local_socket

        self.running = True

        self.thread = Thread(target=self._run, daemon=True)
        self.thread.start()

    def parse_packet(self) -> tuple[int, bytes]:
        header = self.local_socket.recv(8)
        if not header:
            raise EOFError
        stream, data_length = struct.unpack('>BxxxL', header)
        return stream, self.local_socket.recv(data_length)
    
    def close(self):
        self.running = False
        if hasattr(self, 'local_socket'):
            self.local_socket.close()
        if hasattr(self, 'remote_socket'):
            self.remote_socket.close()
    
    def _recv_thread(self):
        try:
            while self.running:
                stream, data = self.parse_packet()
                if stream not in (0, 1):
                    log.warning(data)
                log.debug(f'proxy recv stream: {stream}, data: {data}')
                if not data: 
                    log.warning('No data received, closing gdbserver connection.')
                    self.running = False
                    break
                self.remote_socket.send(data)
            log.debug('Stopping proxy recv thread.')
        except (EOFError, OSError):
            log.warning('Closing gdbserver connection.')
            self.running = False
        finally:
            self.local_socket.close()
            self.remote_socket.close()


    def _run(self):
        self.remote_socket = self.server_socket.wait_for_connection()

        self.recv_thread = Thread(target=self._recv_thread, daemon=True)
        self.recv_thread.start()

        try:
            while self.running:
                data = self.remote_socket.recv(4096)
                log.debug(f'proxy send data: {data}')
                if not data: 
                    log.warning('No data received, closing gdbserver connection.')
                    self.running = False
                    break
                self.local_socket.send(data)
            log.debug('Stopping proxy send thread.')
        except (EOFError, OSError):
            log.warning('Closing gdbserver connection.')
            self.running = False
        finally:
            self.local_socket.close()
            self.remote_socket.close()