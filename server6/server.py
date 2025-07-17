#!/usr/bin/env python3
import json
import logging
import os
import time
import asyncio
import websockets
from dataclasses import dataclass
from functools import lru_cache
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Optional, Tuple
from collections import defaultdict
from datetime import datetime, timedelta

TCP_STATES = {
    '01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV',
    '04': 'FIN_WAIT1', '05': 'FIN_WAIT2', '06': 'TIME_WAIT',
    '07': 'CLOSE', '08': 'CLOSE_WAIT', '09': 'LAST_ACK',
    '0A': 'LISTEN', '0B': 'CLOSING'
}

@dataclass(frozen=True)
class Config:
    host: str = os.getenv("TCP_SERVER_HOST", "0.0.0.0")
    port: int = int(os.getenv("TCP_SERVER_PORT", "3333"))
    ws_port: int = int(os.getenv("WS_PORT", "3334"))
    static_dir: Path = Path(".")
    cors_origin: str = os.getenv("CORS_ALLOWED_ORIGIN", "*")
    max_request_size: int = 1024 * 1024
    allowed_extensions: Tuple[str, ...] = ('.html', '.js', '.css', '.png', '.ico', '.json')
    rate_limit_requests: int = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
    rate_limit_window: int = int(os.getenv("RATE_LIMIT_WINDOW", "60"))
    
    def __post_init__(self):
        if not 0 < self.port <= 65535 or not 0 < self.ws_port <= 65535:
            raise ValueError(f"Invalid port number: {self.port} or {self.ws_port}")

class RateLimiter:
    def __init__(self, requests: int, window: int):
        self.requests = requests
        self.window = window
        self.clients: Dict[str, list] = defaultdict(list)

    def is_allowed(self, client_ip: str) -> bool:
        now = datetime.now()
        self.clients[client_ip] = [
            t for t in self.clients[client_ip]
            if now - t < timedelta(seconds=self.window)
        ]
        if len(self.clients[client_ip]) >= self.requests:
            return False
        self.clients[client_ip].append(now)
        return True

@lru_cache(maxsize=1)
def parse_tcp_states() -> Dict[str, int]:
    state_count = {name: 0 for name in TCP_STATES.values()}
    state_count["UNKNOWN"] = 0
    try:
        with open("/proc/net/tcp", "r", encoding="utf-8") as f:
            for line in f.readlines()[1:]:
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

class TCPMonitoringHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        try:
            self.config = Config()
            self.rate_limiter = RateLimiter(
                self.config.rate_limit_requests,
                self.config.rate_limit_window
            )
            super().__init__(*args, directory=str(self.config.static_dir), **kwargs)
        except Exception as e:
            logging.critical(f"Handler initialization failed: {str(e)}")
            raise

    def _send_response(self, content: bytes, content_type: str = "application/json", status: int = 200):
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
        error_data = {
            "error": message,
            "status": status,
            "timestamp": int(time.time()),
            "details": details or "No additional details available"
        }
        self._send_response(json.dumps(error_data).encode("utf-8"), status=status)

    def do_GET(self):
        try:
            if not self.rate_limiter.is_allowed(self.client_address[0]):
                return self._handle_error(429, "Too Many Requests", 
                    f"Rate limit exceeded: {self.config.rate_limit_requests} requests per {self.config.rate_limit_window} seconds")
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
            self._handle_error(500, "Internal server error", str(e))

    def _handle_tcp_states(self):
        stats = parse_tcp_states()
        response = json.dumps({
            "timestamp": int(time.time()),
            "tcp_states": stats,
            "server": "TCP Monitoring Service",
            "version": "2.0.0"
        }).encode("utf-8")
        self._send_response(response)

    def _handle_health_check(self):
        try:
            stats = parse_tcp_states()
            response = json.dumps({
                "status": "healthy",
                "timestamp": int(time.time()),
                "tcp_connections": sum(stats.values()),
                "memory_usage": "N/A",
                "uptime": int(time.time() - server_start_time)
            }).encode("utf-8")
            self._send_response(response)
        except Exception as e:
            self._handle_error(503, "Service unavailable", str(e))

    def _handle_static(self):
        try:
            requested_path = Path(self.path.lstrip("/")).resolve()
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
            logging.error(f"Static file handling error: {str(e)}")
            self._handle_error(500, "Internal server error", str(e))

async def websocket_handler(websocket, path):
    try:
        config = Config()
        while True:
            if path == "/ws/tcpstates":
                stats = parse_tcp_states()
                response = json.dumps({
                    "timestamp": int(time.time()),
                    "tcp_states": stats,
                    "type": "tcp_state_update"
                })
                await websocket.send(response)
                await asyncio.sleep(1)
            else:
                await websocket.send(json.dumps({"error": "Invalid WebSocket path"}))
                break
    except websockets.exceptions.ConnectionClosed:
        logging.info("WebSocket connection closed")
    except Exception as e:
        logging.error(f"WebSocket error: {str(e)}")

def configure_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("server.log")
        ]
    )

server_start_time = time.time()

async def run_server():
    configure_logging()
    logger = logging.getLogger(__name__)
    try:
        config = Config()
    except ValueError as e:
        logger.critical(f"Configuration error: {str(e)}")
        return 1
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
