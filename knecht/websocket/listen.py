from websockets.sync import server
from websockets.frames import CloseCode
from websockets.exceptions import ConnectionClosedOK, ConnectionClosedError
from pwnlib.tubes.tube import tube
from pwnlib.timeout import Timeout

from threading import Event, Thread

from pwnlib import context

context.context.log_level = 'info'

class listen(tube):
    """A WebSocket server that listens for incoming connections."""

    def __init__(self, host, port, ssl=None, timeout=Timeout.default, **kwargs):
        super().__init__(timeout=timeout)
        self.host = host
        self.port = port

        self.timeout = None

        self.connection_estabilished_event = Event()
        self.connection_closed_event = Event()

        self.server = server.serve(self.handle_connection, self.host, self.port, ssl=ssl, **kwargs)

        p = self.waitfor(f'Waiting for WebSocket connection on {"wss" if ssl else "ws"}://{host}:{port}/')

        self.start_server()

        self.connection_estabilished_event.wait()

        p.success(f'WebSocket connection established')

    def start_server(self):
        """Start the WebSocket server in a separate thread."""
        if self.server is None:
            raise RuntimeError("Server is not running")
        
        self.server_thread = Thread(target=self.server.serve_forever)
        self.server_thread.start()

    def handle_connection(self, connection: server.ServerConnection):
        """Handle incoming WebSocket connections."""
        if self.server is None:
            raise RuntimeError("Server is not running")
        
        if self.connection_estabilished_event.set():
            connection.close(CloseCode.GOING_AWAY, "Listen is already serving a connection")

        self.connection = connection
        self.connection_estabilished_event.set()

        self.connection_closed_event.wait()

    def recv_raw(self, numb):
        if not self.server or not self.connection:
            raise RuntimeError("Server is not running or no connection established")
        
        if self.connection_closed_event.is_set():
            raise EOFError("Connection closed")
        
        try:
            return self.connection.recv(self.timeout)
        except TimeoutError:
            return None
        except ConnectionClosedOK:
            self.connection_closed_event.set()
            raise EOFError("Connection closed gracefully")
        except ConnectionClosedError as e:
            self.connection_closed_event.set()
            raise EOFError(f"Connection closed with error: {e}")
        
    def send_raw(self, data):
        if not self.server or not self.connection:
            raise RuntimeError("Server is not running or no connection established")
        
        if self.connection_closed_event.is_set():
            raise EOFError("Connection closed")
        
        try:
            self.connection.send(data)
        except ConnectionClosedError as e:
            self.connection_closed_event.set()
            raise EOFError(f"Connection closed with error: {e}")
        except Exception as e:
            raise RuntimeError(f"Failed to send data: {e}")
        
    def close(self):
        """Close the WebSocket server and connection."""

        self.connection_closed_event.set()

        if self.connection:
            self.connection.close()

        if self.server:
            self.server.shutdown()
                
        if hasattr(self, 'server_thread'):
            self.server_thread.join()
            del self.server_thread

    def can_recv_raw(self):
        """Check if data can be received."""
        return not self.connection_closed_event.is_set() and self.connection is not None
    
    def can_send_raw(self):
        """Check if data can be sent."""
        return not self.connection_closed_event.is_set() and self.connection is not None
    
    def fileno(self):
        """Return the file descriptor for the WebSocket connection."""
        if self.connection is None:
            raise RuntimeError("No connection established")
        
        return self.connection.socket.fileno()
    
    def shutdown_raw(self, direction):
        """Shutdown the WebSocket connection."""
        if not self.connection:
            raise RuntimeError("No connection established")
    
        self.close()


if __name__ == "__main__":
    ws = listen(host='localhost', port=8000)

    print(f"WebSocket server started at ws://{ws.host}:{ws.port}")

    ws.interactive()