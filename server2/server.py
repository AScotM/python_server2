import logging
import json
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import os
from typing import Dict
import time

# --- Configuration ---
HOST = os.environ.get("TCP_SERVER_HOST", "0.0.0.0")
PORT = int(os.environ.get("TCP_SERVER_PORT", 3333))
# Define the directory to serve static files from.
# It's good practice to make this configurable, e.g., via an environment variable.
STATIC_DIR = os.environ.get("STATIC_CONTENT_DIR", ".") # Default to current directory

TCP_STATES = {
    '01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV',
    '04': 'FIN_WAIT1', '05': 'FIN_WAIT2', '06': 'TIME_WAIT',
    '07': 'CLOSE', '08': 'CLOSE_WAIT', '09': 'LAST_ACK',
    '0A': 'LISTEN', '0B': 'CLOSING'
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# --- TCP State Parsing (remains the same) ---
def parse_tcp_states() -> Dict[str, int]:
    """Parse /proc/net/tcp and return a count of TCP connection states."""
    state_count = {name: 0 for name in TCP_STATES.values()}
    try:
        with open("/proc/net/tcp", "r") as f:
            lines = f.readlines()[1:]  # Skip header
            for line in lines:
                parts = line.strip().split()
                if len(parts) < 4:
                    logging.warning(f"Skipping malformed line in /proc/net/tcp: {line}")
                    continue
                state_code = parts[3]
                state_name = TCP_STATES.get(state_code, "UNKNOWN")
                state_count[state_name] = state_count.get(state_name, 0) + 1
    except FileNotFoundError:
        logging.error("/proc/net/tcp not found. Are you running on Linux?")
    except Exception as e:
        logging.error(f"Failed to parse /proc/net/tcp: {e}")
    return state_count

# --- Custom HTTP Request Handler ---
class CustomHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Change the current working directory to the STATIC_DIR
        # This makes SimpleHTTPRequestHandler serve files from that directory
        # by default when its do_GET is called.
        self.directory = STATIC_DIR
        super().__init__(*args, **kwargs)

    def do_GET(self):
        logging.info(f"GET {self.path} from {self.client_address[0]}:{self.client_address[1]}")

        # Handle specific API paths first
        if self.path == "/tcpstates":
            self.handle_tcpstates()
        elif self.path == "/health": # No need for explicit "/" for health if static "/" works
            self.handle_health_check()
        else:
            # For all other paths, let the base SimpleHTTPRequestHandler serve the file.
            # It will automatically look for the file in the directory set in __init__.
            try:
                super().do_GET()
            except Exception as e:
                # Catch potential errors from SimpleHTTPRequestHandler, e.g., file not found (404)
                # or other server errors. SimpleHTTPRequestHandler handles 404s by itself,
                # but this is for unexpected errors.
                if not self.headers_sent: # Avoid trying to send error if headers already sent
                    self.send_error(500, "Internal Server Error")
                logging.error(f"Error serving static GET request for {self.path}: {e}")

    def handle_tcpstates(self):
        state_data = parse_tcp_states()
        response = {
            "timestamp": int(time.time()),
            "tcp_states": state_data
        }
        self._send_json_response(response)

    def handle_health_check(self):
        response = {"status": "ok", "message": "Server is running"}
        self._send_json_response(response)

    def _send_json_response(self, data: Dict):
        response_body = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

# --- Main execution ---
if __name__ == "__main__":
    # Ensure the static directory exists, otherwise the server won't start correctly
    if not os.path.isdir(STATIC_DIR):
        logging.critical(f"Static content directory '{STATIC_DIR}' does not exist or is not a directory. Exiting.")
        exit(1)

    logging.info(f"Serving static content from: {os.path.abspath(STATIC_DIR)}")
    logging.info(f"API endpoints: /tcpstates, /health")

    server = ThreadingHTTPServer((HOST, PORT), CustomHandler)
    logging.info(f"Server listening on http://{HOST}:{PORT}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down server (keyboard interrupt)...")
        server.shutdown()
        server.server_close()
    except Exception as e:
        logging.error(f"Server error: {e}")
