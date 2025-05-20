import struct
import zlib
import base64

from secrets import token_hex

from pwnlib.tubes.tube import tube
from pwnlib.log import getLogger

from knecht.transmit.chunked import Chunked

log = getLogger(__name__)

RETRY_COUNT = 10
PACKET_SIZE = 500

def b64_to_size(size: int) -> int:
    """Calculate the base64-encoded size for a given byte size."""
    return ((size if size % 3 == 0 else 3 - (size % 3) + size) // 3) * 4

class Transmitter:
    def __init__(self, client: tube):
        self.client = client

    def wait_for_ack(self, requested_seq_num: int, end_of_transmission:bool = False) -> bool:
        """Wait for an acknowledgment from the server."""
        encoded_header = self.client.recv(12)
        decoded_header = base64.b64decode(encoded_header)
        msg_len, seq_num = struct.unpack('<Ii', decoded_header)

        encoded_msg = self.client.recv(b64_to_size(msg_len))
        decoded_msg = base64.b64decode(encoded_msg).decode()

        if decoded_msg == '[+] success':
            if seq_num == requested_seq_num:
                return True
            log.error(f'got out of sync, server at {seq_num}, client at {requested_seq_num}')
        elif decoded_msg == '[+] finished transmition':
            log.debug('got end of transmition')
            if end_of_transmission:
                return True
            raise EOFError('transmition finished')
        elif decoded_msg.startswith('[!]'):
            print(f'got recoverable error: {decoded_msg}')
            return False
        else:
            log.error(f'unknown msg: {decoded_msg}')

    def send_init_packet(self, filename: str, permissions: int = 0o644):
        """Send the initial packet with filename and permissions."""
        header = struct.pack('<III', len(filename), permissions, zlib.crc32(filename.encode()))
        encoded_header = base64.b64encode(header)
        encoded_payload = base64.b64encode(filename.encode())
        self.client.send(encoded_header + encoded_payload)

    def init_packet(self, filename: str, permissions: int = 0o644):
        """Initialize the file transfer with retries."""
        for _ in range(RETRY_COUNT):
            self.send_init_packet(filename, permissions)
            if self.wait_for_ack(-1):
                return
        log.error("retries exhausted")

    def send_packet(self, data: bytes, seq_num: int):
        """Send a data packet."""
        header = struct.pack('<IiI', len(data), seq_num, zlib.crc32(data))
        encoded_header = base64.b64encode(header)
        encoded_payload = base64.b64encode(data)
        self.client.send(encoded_header + encoded_payload)

    def packet(self, data: bytes, seq_num: int):
        """Send a packet with retries."""
        log.debug(f'sending packet {seq_num}')

        for current_retry in range(RETRY_COUNT):
            self.send_packet(data, seq_num)
            if self.wait_for_ack(seq_num):
                return True
            log.debug(f'packet {seq_num} failed, still {RETRY_COUNT - (current_retry) - 1} retries left')
        log.error("retries exhausted")

    def send_end_of_transmission(self):
        """Send the end-of-transmission packet."""
        log.debug('sending end of transmition')
        self.send_packet(b'', -1)
        if not self.wait_for_ack(-1, True):
            log.error('transmition failed to properly teardown')
        log.info('transmition finished')

    def send_file(self, filename: str, remote_filename: str = './out', permissions: int = 0o644):
        """Send a file to the remote."""
        self.init_packet(remote_filename, permissions)
        log.info('initialzation complete')

        with open(filename, 'rb') as f:
            content = f.read()
            
            for sequence_number, chunk in Chunked(content, PACKET_SIZE):
                self.packet(chunk, sequence_number)

        self.send_end_of_transmission()

if __name__ == "__main__":
    from pwn import process

    client = process(['./bin/client'])

    transmitter = Transmitter(client)
    transmitter.send_file('./main')