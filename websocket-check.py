#!/usr/bin/env python3
import base64
import hashlib
import os
import socket
import ssl
import struct
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def log(message, error=False):
    print(f"{timestamp()} {message}", file=sys.stderr if error else sys.stdout, flush=True)


def recv_until(sock, marker, limit=65536):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            raise RuntimeError("handshake response too large")
    return data


def recv_exact(sock, length):
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise RuntimeError("connection closed")
        data += chunk
    return data


def send_frame(sock, opcode, payload=b""):
    if isinstance(payload, str):
        payload = payload.encode("utf-8")

    first_byte = 0x80 | opcode
    length = len(payload)
    mask_key = os.urandom(4)

    if length <= 125:
        header = struct.pack("!BB", first_byte, 0x80 | length)
    elif length <= 65535:
        header = struct.pack("!BBH", first_byte, 0x80 | 126, length)
    else:
        header = struct.pack("!BBQ", first_byte, 0x80 | 127, length)

    masked_payload = bytes(byte ^ mask_key[index % 4] for index, byte in enumerate(payload))
    sock.sendall(header + mask_key + masked_payload)


def recv_frame(sock):
    first, second = recv_exact(sock, 2)
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F

    if length == 126:
        length = struct.unpack("!H", recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", recv_exact(sock, 8))[0]

    mask_key = recv_exact(sock, 4) if masked else b""
    payload = recv_exact(sock, length) if length else b""

    if masked:
        payload = bytes(byte ^ mask_key[index % 4] for index, byte in enumerate(payload))

    return opcode, payload


def open_websocket(url, timeout):
    parsed = urlparse(url)
    if parsed.scheme not in ("ws", "wss"):
        raise RuntimeError("CHECK_URL must start with ws:// or wss://")
    if not parsed.hostname:
        raise RuntimeError("CHECK_URL is missing a hostname")

    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "wss" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    raw_sock = socket.create_connection((host, port), timeout=timeout)
    raw_sock.settimeout(timeout)
    raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    if parsed.scheme == "wss":
        context = ssl.create_default_context()
        sock = context.wrap_socket(raw_sock, server_hostname=host)
    else:
        sock = raw_sock

    sec_key = base64.b64encode(os.urandom(16)).decode("ascii")
    host_header = host if parsed.port is None else f"{host}:{port}"
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {sec_key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "User-Agent: websocket-check/1.0\r\n"
        "\r\n"
    ).encode("ascii")
    sock.sendall(request)

    response = recv_until(sock, b"\r\n\r\n")
    header_bytes = response.split(b"\r\n\r\n", 1)[0]
    header_text = header_bytes.decode("iso-8859-1", errors="replace")
    lines = header_text.split("\r\n")
    status_line = lines[0] if lines else ""
    parts = status_line.split(" ", 2)
    status_code = parts[1] if len(parts) > 1 else "unknown"

    if status_code != "101":
        raise RuntimeError(f"handshake_status={status_code} status_line={status_line!r}")

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()

    expected_accept = base64.b64encode(hashlib.sha1((sec_key + GUID).encode("ascii")).digest()).decode("ascii")
    actual_accept = headers.get("sec-websocket-accept")
    if actual_accept != expected_accept:
        raise RuntimeError("invalid Sec-WebSocket-Accept in handshake response")

    return sock


def wait_for_matching_pong(sock, ping_payload):
    while True:
        opcode, payload = recv_frame(sock)
        if opcode == 0xA and payload == ping_payload:
            return
        if opcode == 0x9:
            send_frame(sock, 0xA, payload)
            continue
        if opcode == 0x8:
            raise RuntimeError("server closed websocket")


def run_connection(url, timeout, interval, print_success, ping_payload):
    connected_at = time.monotonic()
    sock = open_websocket(url, timeout)
    handshake_ms = int((time.monotonic() - connected_at) * 1000)
    log(f"websocket connected: handshake_ms={handshake_ms} url={url}")

    try:
        while True:
            started = time.monotonic()
            send_frame(sock, 0x9, ping_payload)
            wait_for_matching_pong(sock, ping_payload)
            total_ms = int((time.monotonic() - started) * 1000)
            uptime_seconds = int(time.monotonic() - connected_at)

            if print_success:
                log(
                    "websocket check result: connection=alive ping=ok pong=true "
                    f"ping_ms={total_ms} uptime_seconds={uptime_seconds} url={url}"
                )

            time.sleep(interval)
    finally:
        try:
            send_frame(sock, 0x8, b"")
        except Exception:
            pass
        try:
            sock.close()
        except OSError:
            pass


def main():
    url = os.environ.get("CHECK_URL", "wss://vvn2-2w2evypk.b4a.run/chat")
    interval = float(os.environ.get("CHECK_INTERVAL_SECONDS", "300"))
    timeout = float(os.environ.get("CHECK_TIMEOUT_SECONDS", "10"))
    retry_seconds = float(os.environ.get("CHECK_RETRY_SECONDS", "5"))
    print_success = os.environ.get("CHECK_PRINT_SUCCESS", "0") == "1"
    ping_payload = os.environ.get("CHECK_PING_PAYLOAD", "websocket-check").encode("utf-8")

    while True:
        started = time.monotonic()
        try:
            run_connection(url, timeout, interval, print_success, ping_payload)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            log(f"websocket check failed: {exc} connected_or_attempt_ms={elapsed_ms} retry_seconds={retry_seconds} url={url}", error=True)
            time.sleep(retry_seconds)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
