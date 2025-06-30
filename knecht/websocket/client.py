from websockets.sync import client as ws_client
from pwnlib.tubes.tube import tube
from websockets.exceptions import ConnectionClosedError, ConnectionClosedOK

class client(tube):
    """A WebSocket server that listens for incoming connections."""

    def __init__(self, uri:str, *args, **kwargs):
        super().__init__()
        self.connection = ws_client.connect(uri=uri, *args, **kwargs)
    
    def recv_raw(self, numb):
        """Receive data from the WebSocket connection."""
        if not self.connection:
            raise RuntimeError("Connection is not established")
        
        try:
            return self.connection.recv(self._timeout)
        except TimeoutError:
            return None
        except ConnectionClosedOK:
            raise EOFError("Connection closed")
        except ConnectionClosedError as e:
            raise EOFError("Connection closed unexpectedly with error: %s" % e)
        
    def send_raw(self, data):
        """Send data over the WebSocket connection."""
        if not self.connection:
            raise RuntimeError("Connection is not established")
        
        try:
            self.connection.send(data)
        except ConnectionClosedOK:
            raise EOFError("Connection closed")
        except ConnectionClosedError as e:
            raise EOFError("Connection closed unexpectedly with error: %s" % e)
        
    def close(self):
        """Close the WebSocket connection."""
        if not hasattr(self, 'connection') or not self.connection:
            return
        self.connection.close()

    def fileno(self):
        """Return the file descriptor for the WebSocket connection."""
        if not self.connection:
            raise RuntimeError("Connection is not established")
        
        return self.connection.socket.fileno()
    

if __name__ == "__main__":
    c = client("ws://localhost:8000")

    c.interactive()