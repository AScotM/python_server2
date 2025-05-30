import logging
import json
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import os
from typing import Dict
import time

# --- Configuration ---
HOST = os.environ.get("TCP_SERVER_HOST", "0.0.0.0")
PORT = int(os.environ.get("TCP_SERVER_PORT", 3333))
STATIC_DIR = os.environ.get("STATIC_CONTENT_DIR", ".")  # Default: current directory

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

# --- TCP State Parsing ---
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
        self.static_dir = STATIC_DIR
        super().__init__(*args, directory=self.static_dir, **kwargs)

    def do_GET(self):
        logging.info(f"GET {self.path} from {self.client_address[0]}")

        # Route API endpoints
        if self.path == "/tcpstates":
            self.handle_tcpstates()
        elif self.path == "/health":
            self.handle_health_check()
        else:
            # Serve static files (including index.html for "/")
            self.handle_static()

    def handle_tcpstates(self):
        state_data = parse_tcp_states()
        self._send_json_response({
            "timestamp": int(time.time()),
            "tcp_states": state_data
        })

    def handle_health_check(self):
        self._send_json_response({"status": "ok"})

    def handle_static(self):
        # Redirect root ("/") to index.html if it exists
        if self.path == "/":
            self.path = "/index.html"

        # Let SimpleHTTPRequestHandler handle the file serving
        try:
            super().do_GET()
        except Exception as e:
            logging.error(f"Failed to serve {self.path}: {e}")
            if not self.headers_sent:
                self.send_error(500, "Internal Server Error")

    def _send_json_response(self, data: Dict):
        response_body = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

# --- Main Execution ---
if __name__ == "__main__":
    if not os.path.isdir(STATIC_DIR):
        logging.critical(f"Static directory '{STATIC_DIR}' not found!")
        exit(1)

    logging.info(f"Serving static files from: {os.path.abspath(STATIC_DIR)}")
    logging.info(f"Endpoints: /tcpstates, /health")
    logging.info(f"Server running on http://{HOST}:{PORT}")

    server = ThreadingHTTPServer((HOST, PORT), CustomHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down...")
        server.shutdown()
