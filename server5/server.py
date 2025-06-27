#!/usr/bin/env python3
"""TCP Connection Monitoring Server with Static File Serving"""

import json
import logging
import os
import time
from dataclasses import dataclass
from functools import lru_cache
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Optional, Tuple

# --- Constants ---
TCP_STATES = {
    '01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV',
    '04': 'FIN_WAIT1', '05': 'FIN_WAIT2', '06': 'TIME_WAIT',
    '07': 'CLOSE', '08': 'CLOSE_WAIT', '09': 'LAST_ACK',
    '0A': 'LISTEN', '0B': 'CLOSING'
}

DEFAULT_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

# --- Configuration ---
@dataclass(frozen=True)
class Config:
    """Server configuration with validation"""
    host: str = os.getenv("TCP_SERVER_HOST", "0.0.0.0")
    port: int = int(os.getenv("TCP_SERVER_PORT", "3333"))
    static_dir: Path = Path(os.getenv("STATIC_CONTENT_DIR", DEFAULT_STATIC_DIR))
    cors_origin: str = os.getenv("CORS_ALLOWED_ORIGIN", "*")
    max_request_size: int = 1024 * 1024  # 1MB
    allowed_extensions: Tuple[str, ...] = ('.html', '.js', '.css', '.png', '.ico', '.json')
    
    def __post_init__(self):
        if not self.static_dir.is_dir():
            raise ValueError(f"Static directory not found: {self.static_dir}")
        if not 0 < self.port <= 65535:
            raise ValueError(f"Invalid port number: {self.port}")

# --- TCP State Parsing ---
@lru_cache(maxsize=1)
def parse_tcp_states() -> Dict[str, int]:
    """Parse /proc/net/tcp with cached results (1 second TTL)"""
    state_count = {name: 0 for name in TCP_STATES.values()}
    state_count["UNKNOWN"] = 0
    
    try:
        with open("/proc/net/tcp", "r", encoding="utf-8") as f:
            for line in f.readlines()[1:]:  # Skip header
                parts = line.strip().split()
                if len(parts) < 4:
                    continue
                state_code = parts[3]
                state_name = TCP_STATES.get(state_code, "UNKNOWN")
                state_count[state_name] += 1
    except FileNotFoundError:
        logging.error("/proc/net/tcp not found - Linux only feature")
    except Exception as e:
        logging.error(f"TCP state parsing error: {str(e)}")
    
    return state_count

# --- HTTP Handler ---
class TCPMonitoringHandler(SimpleHTTPRequestHandler):
    """Enhanced handler with security and monitoring features"""
    
    def __init__(self, *args, **kwargs):
        try:
            self.config = Config()
            super().__init__(*args, directory=str(self.config.static_dir), **kwargs)
        except Exception as e:
            logging.critical(f"Handler initialization failed: {str(e)}")
            raise

    def _send_response(self, content: bytes, content_type: str = "application/json", status: int = 200):
        """Unified response sender with security headers"""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Access-Control-Allow-Origin", self.config.cors_origin)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(content)

    def _handle_error(self, status: int, message: str):
        """Standard error handler"""
        error_data = json.dumps({
            "error": message,
            "status": status,
            "timestamp": int(time.time())
        }).encode("utf-8")
        self._send_response(error_data, status=status)

    def do_GET(self):
        """Route GET requests with security checks"""
        try:
            # Security checks
            if len(self.path) > 256:
                return self._handle_error(414, "Request URI too long")
            
            if self.path == "/tcpstates":
                self._handle_tcp_states()
            elif self.path == "/health":
                self._handle_health_check()
            else:
                self._handle_static()
        except Exception as e:
            logging.exception("Request processing failed")
            self._handle_error(500, "Internal server error")

    def _handle_tcp_states(self):
        """Handle TCP state monitoring endpoint"""
        stats = parse_tcp_states()
        response = json.dumps({
            "timestamp": int(time.time()),
            "tcp_states": stats,
            "server": "TCP Monitoring Service"
        }).encode("utf-8")
        self._send_response(response)

    def _handle_health_check(self):
        """System health check endpoint"""
        try:
            stats = parse_tcp_states()
            response = json.dumps({
                "status": "healthy",
                "timestamp": int(time.time()),
                "tcp_connections": sum(stats.values())
            }).encode("utf-8")
            self._send_response(response)
        except Exception as e:
            self._handle_error(503, f"Service unavailable: {str(e)}")

    def _handle_static(self):
        """Secure static file handler"""
        try:
            requested_path = Path(self.path.lstrip("/")).resolve()
            static_dir = self.config.static_dir.resolve()

            # Security checks
            if not str(requested_path).startswith(str(static_dir)):
                return self._handle_error(403, "Access denied")
                
            if not requested_path.suffix in self.config.allowed_extensions:
                return self._handle_error(403, "File type not allowed")

            # Default to index.html if path is directory
            if requested_path.is_dir():
                self.path = "/index.html"
                requested_path = static_dir / "index.html"

            if not requested_path.is_file():
                return self._handle_error(404, "File not found")

            super().do_GET()
        except Exception as e:
            logging.error(f"Static file handling error: {str(e)}")
            self._handle_error(500, "Internal server error")

# --- Main Execution ---
def configure_logging():
    """Set up logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("server.log")
        ]
    )

def run_server():
    """Start and manage the server lifecycle"""
    configure_logging()
    logger = logging.getLogger(__name__)
    
    try:
        config = Config()
    except ValueError as e:
        logger.critical(f"Configuration error: {str(e)}")
        return 1

    try:
        server = ThreadingHTTPServer((config.host, config.port), TCPMonitoringHandler)
        logger.info(f"Server started on http://{config.host}:{config.port}")
        logger.info(f"Serving static files from: {config.static_dir}")
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server received shutdown signal")
    except Exception as e:
        logger.critical(f"Server failure: {str(e)}")
        return 1
    finally:
        server.shutdown()
        server.server_close()
    return 0

if __name__ == "__main__":
    exit(run_server())
