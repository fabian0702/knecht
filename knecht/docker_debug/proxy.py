import socket
from pwnlib.tubes.listen import listen
from threading import Thread

import struct

class proxy:
    def __init__(self, local_socket:socket.socket):
        self.server_socket = listen()
        self.remote = (self.server_socket.lhost, self.server_socket.lport)
        self.local_socket:socket.socket = local_socket

        self.running = True

        self.thread = Thread(target=self._run, daemon=True)
        self.thread.start()

    def parse_packet(self) -> bytes:
        header = self.local_socket.recv(8)
        if not header:
            raise EOFError
        stream, data_length = struct.unpack('>BxxxL', header)
        return stream, self.local_socket.recv(data_length)
    
    def close(self):
        self.running = False
        self.local_socket.close()
        self.remote_socket.close()
    
    def _recv_thread(self):
        try:
            while self.running:
                stream, data = self.parse_packet()
                # print('read', data)
                if not data: 
                    break
                self.remote_socket.send(data)
        except (EOFError, OSError):
            pass
        
        self.local_socket.close()
        self.remote_socket.close()


    def _run(self):
        self.remote_socket = self.server_socket.wait_for_connection()

        self.recv_thread = Thread(target=self._recv_thread, daemon=True)
        self.recv_thread.start()

        try:
            while self.running:
                data = self.remote_socket.recv(4096)
                # print('write', data)
                if not data: 
                    break
                self.local_socket.send(data)
        except (EOFError, OSError):
            pass

        self.local_socket.close()
        self.remote_socket.close()