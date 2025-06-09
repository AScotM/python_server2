import logging
import json
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import os
from typing import Dict, Optional
import time
from pathlib import Path

# --- Configuration ---
class Config:
    HOST = os.environ.get("TCP_SERVER_HOST", "0.0.0.0")
    PORT = int(os.environ.get("TCP_SERVER_PORT", 3333))
    STATIC_DIR = os.environ.get("STATIC_CONTENT_DIR", os.path.dirname(__file__))
    CORS_ALLOWED_ORIGIN = os.environ.get("CORS_ALLOWED_ORIGIN", "*")

TCP_STATES = {
    '01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV',
    '04': 'FIN_WAIT1', '05': 'FIN_WAIT2', '06': 'TIME_WAIT',
    '07': 'CLOSE', '08': 'CLOSE_WAIT', '09': 'LAST_ACK',
    '0A': 'LISTEN', '0B': 'CLOSING'
}

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("server.log")
    ]
)

# --- TCP State Parsing ---
def parse_tcp_states() -> Dict[str, int]:
    """
    Parse /proc/net/tcp and return a count of TCP connection states.
    
    Returns:
        Dictionary with TCP state counts (e.g., {'ESTABLISHED': 5, 'LISTEN': 3})
    """
    state_count = {name: 0 for name in TCP_STATES.values()}
    try:
        with open("/proc/net/tcp", "r") as f:
            for line in f.readlines()[1:]:  # Skip header
                parts = line.strip().split()
                if len(parts) < 4:
                    continue
                state_code = parts[3]
                state_name = TCP_STATES.get(state_code, "UNKNOWN")
                state_count[state_name] += 1
    except FileNotFoundError:
        logging.error("/proc/net/tcp not found - are you on Linux?")
    except Exception as e:
        logging.error(f"Error parsing /proc/net/tcp: {str(e)}")
    return state_count

# --- Custom HTTP Request Handler ---
class TCPMonitoringHandler(SimpleHTTPRequestHandler):
    """Enhanced HTTP handler for TCP monitoring and static file serving."""
    
    def __init__(self, *args, **kwargs):
        self.static_dir = Path(Config.STATIC_DIR)
        super().__init__(*args, directory=str(self.static_dir), **kwargs)
    
    def end_headers(self):
        """Add CORS headers to all responses."""
        self.send_header("Access-Control-Allow-Origin", Config.CORS_ALLOWED_ORIGIN)
        super().end_headers()
    
    def do_GET(self):
        """Route incoming GET requests to appropriate handlers."""
        client_ip = self.client_address[0]
        logging.info(f"GET {self.path} from {client_ip}")
        
        try:
            if self.path == "/tcpstates":
                self._handle_tcp_states()
            elif self.path == "/health":
                self._handle_health_check()
            else:
                self._handle_static()
        except Exception as e:
            logging.error(f"Error handling request: {str(e)}")
            self.send_error(500, "Internal Server Error")

    def _handle_tcp_states(self):
        """Handle requests for TCP state information."""
        state_data = parse_tcp_states()
        self._send_json_response({
            "timestamp": int(time.time()),
            "tcp_states": state_data,
            "server": "TCP Monitoring Service"
        })

    def _handle_health_check(self):
        """Perform system health check."""
        try:
            # Test critical functionality
            states = parse_tcp_states()
            self._send_json_response({
                "status": "healthy",
                "timestamp": int(time.time()),
                "tcp_connections": sum(states.values())
            })
        except Exception as e:
            self.send_error(503, f"Service Unavailable: {str(e)}")

    def _handle_static(self):
        """Serve static files with security checks."""
        # Security: Prevent path traversal
        requested_path = Path(self.path.lstrip("/"))
        if ".." in requested_path.parts:
            self.send_error(403, "Forbidden: Path traversal not allowed")
            return
        
        # Default to index.html for root
        if self.path == "/":
            self.path = "/index.html"
        
        # Check if file exists before serving
        full_path = self.static_dir / self.path.lstrip("/")
        if not full_path.exists():
            self.send_error(404, "File not found")
            return
            
        super().do_GET()

    def _send_json_response(self, data: Dict, status: int = 200):
        """Send JSON response with proper headers."""
        response = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

# --- Main Execution ---
def main():
    """Start the monitoring server."""
    # Validate static directory
    if not Path(Config.STATIC_DIR).is_dir():
        logging.critical(f"Static directory not found: {Config.STATIC_DIR}")
        return os.EX_CONFIG
    
    logging.info(f"""
    TCP Monitoring Server Starting...
    Address: http://{Config.HOST}:{Config.PORT}
    Static files: {Config.STATIC_DIR}
    Endpoints:
      /tcpstates - TCP connection states
      /health - Service health check
    """)
    
    try:
        server = ThreadingHTTPServer((Config.HOST, Config.PORT), TCPMonitoringHandler)
        logging.info("Server started. Press Ctrl+C to stop.")
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Server shutting down...")
    except Exception as e:
        logging.critical(f"Server failed: {str(e)}")
        return os.EX_SOFTWARE
    finally:
        server.shutdown()
    return os.EX_OK

if __name__ == "__main__":
    exit(main())
