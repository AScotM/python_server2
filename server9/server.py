#!/usr/bin/env python3
import json
import logging
import os
import time
import asyncio
import websockets
import psutil
from dataclasses import dataclass
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Optional, Tuple
from collections import defaultdict
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
import re

TCP_STATES = {
    '01': 'ESTABLISHED',
    '02': 'SYN_SENT',
    '03': 'SYN_RECV',
    '04': 'FIN_WAIT1',
    '05': 'FIN_WAIT2',
    '06': 'TIME_WAIT',
    '07': 'CLOSE',
    '08': 'CLOSE_WAIT',
    '09': 'LAST_ACK',
    '0A': 'LISTEN',
    '0B': 'CLOSING'
}

@dataclass(frozen=True)
class Config:
    """Configuration for the TCP monitoring server."""
    host: str = os.getenv("TCP_SERVER_HOST", "0.0.0.0")
    port: int = int(os.getenv("TCP_SERVER_PORT", "3333"))
    ws_port: int = int(os.getenv("WS_PORT", "3334"))
    static_dir: Path = Path(".")
    cors_origin: str = os.getenv("CORS_ALLOWED_ORIGIN", "*")
    max_request_size: int = 1024 * 1024
    allowed_extensions: Tuple[str, ...] = ('.html', '.js', '.css', '.png', '.ico', '.json')
    rate_limit_requests: int = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
    rate_limit_window: int = int(os.getenv("RATE_LIMIT_WINDOW", "60"))
    server_version: str = os.getenv("SERVER_VERSION", "2.0.0")
    ws_rate_limit_requests: int = int(os.getenv("WS_RATE_LIMIT_REQUESTS", "10"))
    ws_rate_limit_window: int = int(os.getenv("WS_RATE_LIMIT_WINDOW", "60"))

    def __post_init__(self):
        """Validate configuration parameters."""
        if not 0 < self.port <= 65535 or not 0 < self.ws_port <= 65535:
            raise ValueError(f"Invalid port number: {self.port} or {self.ws_port}")
        if not self.static_dir.exists() or not self.static_dir.is_dir():
            raise ValueError(f"Static directory {self.static_dir} does not exist or is not a directory")
        if self.cors_origin != "*" and not re.match(r'^https?://[\w\-\.]+(:\d+)?$', self.cors_origin):
            raise ValueError(f"Invalid CORS origin: {self.cors_origin}")

class RateLimiter:
    """Rate limiter for HTTP and WebSocket requests."""
    def __init__(self, requests: int, window: int):
        self.requests = requests
        self.window = window
        self.clients: Dict[str, list] = defaultdict(list)

    def is_allowed(self, client_ip: str) -> bool:
        """Check if a client is allowed to make a request."""
        now = datetime.now()
        self.clients[client_ip] = [
            t for t in self.clients[client_ip]
            if now - t < timedelta(seconds=self.window)
        ]
        if len(self.clients[client_ip]) >= self.requests:
            return False
        self.clients[client_ip].append(now)
        return True

def parse_tcp_states() -> Dict[str, int]:
    """Parse TCP states from /proc/net/tcp and /proc/net/tcp6."""
    files = ["/proc/net/tcp", "/proc/net/tcp6"]
    state_count = {name: 0 for name in TCP_STATES.values()}
    state_count["UNKNOWN"] = 0

    for file in files:
        try:
            with open(file, "r", encoding="utf-8") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) < 4 or not re.match(r'^[0-9A-F]{2}$', parts[3]):
                        logging.warning(f"Invalid line format in {file}: {line.strip()}")
                        continue
                    state_code = parts[3]
                    state_name = TCP_STATES.get(state_code, "UNKNOWN")
                    state_count[state_name] += 1
        except FileNotFoundError:
            logging.warning(f"{file} not found")
        except Exception as e:
            logging.error(f"Error parsing {file}: {str(e)}")
    return state_count

class TCPMonitoringHandler(SimpleHTTPRequestHandler):
    """HTTP request handler for TCP monitoring and static file serving."""
    def __init__(self, *args, **kwargs):
        try:
            self.config = config
            self.rate_limiter = RateLimiter(
                self.config.rate_limit_requests,
                self.config.rate_limit_window
            )
            super().__init__(*args, directory=str(self.config.static_dir), **kwargs)
        except Exception as e:
            logging.critical(f"Handler initialization failed: {str(e)}")
            raise

    def _send_response(self, content: bytes, content_type: str = "application/json", status: int = 200):
        """Send HTTP response with security headers."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Access-Control-Allow-Origin", self.config.cors_origin)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("Cache-Control", "no-store, no-cache")
        self.end_headers()
        self.wfile.write(content)

    def _handle_error(self, status: int, message: str, details: Optional[str] = None):
        """Send error response with details."""
        error_data = {
            "error": message,
            "status": status,
            "timestamp": int(time.time()),
            "details": details or "No additional details available"
        }
        self._send_response(json.dumps(error_data).encode("utf-8"), status=status)

    def do_GET(self):
        """Handle GET requests for TCP states, health checks, or static files."""
        try:
            if not self.rate_limiter.is_allowed(self.client_address[0]):
                return self._handle_error(429, "Too Many Requests", 
                    f"Rate limit exceeded: {self.config.rate_limit_requests} requests per {self.config.rate_limit_window} seconds")
            if len(self.path) > 256:
                return self._handle_error(414, "Request URI too long")
            if self.command == "GET" and len(self.headers.get("Content-Length", "0")) > self.config.max_request_size:
                return self._handle_error(413, "Request entity too large")
            if self.path == "/tcpstates":
                self._handle_tcp_states()
            elif self.path == "/health":
                self._handle_health_check()
            else:
                self._handle_static()
        except Exception as e:
            logging.exception(f"Request processing failed for {self.client_address[0]}")
            self._handle_error(500, "Internal server error", str(e))

    def _handle_tcp_states(self):
        """Handle TCP states request."""
        stats = parse_tcp_states()
        response = json.dumps({
            "timestamp": int(time.time()),
            "tcp_states": stats,
            "server": "TCP Monitoring Service",
            "version": self.config.server_version
        }).encode("utf-8")
        self._send_response(response)

    def _handle_health_check(self):
        """Handle health check request."""
        try:
            stats = parse_tcp_states()
            response = json.dumps({
                "status": "healthy",
                "timestamp": int(time.time()),
                "tcp_connections": sum(stats.values()),
                "memory_usage": f"{psutil.virtual_memory().percent}%",
                "uptime": int(time.time() - server_start_time)
            }).encode("utf-8")
            self._send_response(response)
        except Exception as e:
            self._handle_error(503, "Service unavailable", str(e))

    def _handle_static(self):
        """Handle static file requests."""
        try:
            requested_path = (self.config.static_dir / self.path.lstrip("/")).resolve(strict=False)
            static_dir = self.config.static_dir.resolve()
            if not requested_path.suffix and requested_path != static_dir:
                requested_path = static_dir / "index.html"
                self.path = "/index.html"
            if not str(requested_path).startswith(str(static_dir)):
                return self._handle_error(403, "Access denied", "Path traversal attempt detected")
            if requested_path.suffix and not requested_path.suffix in self.config.allowed_extensions:
                return self._handle_error(403, "File type not allowed", f"Extension {requested_path.suffix} not permitted")
            if requested_path.is_dir():
                self.path = "/index.html"
                requested_path = static_dir / "index.html"
            if not requested_path.is_file():
                return self._handle_error(404, "File not found", f"Requested path: {self.path}")
            super().do_GET()
        except Exception as e:
            logging.error(f"Static file handling error for {self.client_address[0]}: {str(e)}")
            self._handle_error(500, "Internal server error", str(e))

async def websocket_handler(websocket, path):
    """Handle WebSocket connections for real-time TCP state updates."""
    logging.info(f"WebSocket client connected: {websocket.remote_address}")
    try:
        if path != "/ws/tcpstates":
            await websocket.send(json.dumps({"error": "Invalid WebSocket path"}))
            return
        ws_rate_limiter = RateLimiter(config.ws_rate_limit_requests, config.ws_rate_limit_window)
        if not ws_rate_limiter.is_allowed(websocket.remote_address[0]):
            await websocket.send(json.dumps({
                "error": "Too Many Requests",
                "details": f"WebSocket rate limit exceeded: {config.ws_rate_limit_requests} connections per {config.ws_rate_limit_window} seconds"
            }))
            return
        while True:
            stats = parse_tcp_states()
            response = json.dumps({ 
                "timestamp": int(time.time()), 
                "tcp_states": stats, 
                "type": "tcp_state_update" 
            })
            await websocket.send(response)
            await asyncio.sleep(1)
    except websockets.exceptions.ConnectionClosed:
        logging.info(f"WebSocket connection closed: {websocket.remote_address}")
    except Exception as e:
        logging.error(f"WebSocket error for {websocket.remote_address}: {str(e)}")

def configure_logging():
    """Configure logging with rotation."""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    
    file_handler = RotatingFileHandler(
        "server.log",
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(formatter)
    
    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)

server_start_time = time.time()
config = Config()

async def run_server():
    """Run the HTTP and WebSocket servers."""
    configure_logging()
    logger = logging.getLogger(__name__)
    try:
        http_server = ThreadingHTTPServer((config.host, config.port), TCPMonitoringHandler)
        logger.info(f"HTTP Server started on http://{config.host}:{config.port}")
        logger.info(f"Serving static files from: {config.static_dir}")
        ws_server = await websockets.serve(
            websocket_handler, 
            config.host, 
            config.ws_port, 
            ping_interval=20, 
            ping_timeout=60 
        )
        logger.info(f"WebSocket Server started on ws://{config.host}:{config.ws_port}")
        loop = asyncio.get_event_loop()
        http_task = loop.run_in_executor(None, http_server.serve_forever)
        try:
            await asyncio.gather(http_task)
        except KeyboardInterrupt:
            logger.info("Server received shutdown signal")
        finally:
            http_server.shutdown()
            http_server.server_close()
            ws_server.close()
            await ws_server.wait_closed()
    except Exception as e:
        logger.critical(f"Server failure: {str(e)}")
        return 1
    return 0

if __name__ == "__main__":
    exit(asyncio.run(run_server()))
