"""Forward proxy that keeps the browser off private, loopback and metadata addresses.

Chrome is pointed at it with --proxy-server, so every request a page makes (scripts,
subresources, workers, tunnelled HTTPS) arrives here first. Each destination is
resolved, refused if any address is forbidden, and then connected by the address
that was checked, so DNS cannot answer differently between the check and the dial.
"""

import asyncio
import ipaddress
import logging
import socket
import threading
import urllib.parse

# Tests serve their fixture pages from 127.0.0.1; production never sets this.
allow_loopback = False

_READ_LIMIT = 64 * 1024
_HEADER_TIMEOUT = 30

_lock = threading.Lock()
_port = None


def is_forbidden_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if allow_loopback and ip.is_loopback:
        return False
    return not ip.is_global or ip.is_multicast


def resolve_allowed(host: str, port: int) -> str:
    """Returns an address to dial for host, or raises PermissionError if any is forbidden."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = [info[4][0] for info in infos]
    if not addresses:
        raise OSError(f"{host} did not resolve")
    forbidden = [a for a in addresses if is_forbidden_ip(a)]
    if forbidden:
        raise PermissionError(f"{host} resolves to a forbidden address ({forbidden[0]})")
    return addresses[0]


def _split_host_port(authority: str, default_port: int):
    parsed = urllib.parse.urlsplit('//' + authority)
    return parsed.hostname, parsed.port or default_port


async def _pipe(reader, writer):
    try:
        while True:
            chunk = await reader.read(_READ_LIMIT)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def _refuse(writer, reason: str):
    logging.info("Egress guard refused: %s", reason)
    body = reason.encode()
    writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n"
                 b"Connection: close\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
    await writer.drain()
    writer.close()


async def _handle(client_reader, client_writer):
    try:
        head = await asyncio.wait_for(client_reader.readuntil(b"\r\n\r\n"), _HEADER_TIMEOUT)
    except Exception:
        client_writer.close()
        return
    request_line, _, rest = head.partition(b"\r\n")
    try:
        method, target, version = request_line.decode('latin-1').split(' ', 2)
    except ValueError:
        client_writer.close()
        return

    if method.upper() == 'CONNECT':
        host, port = _split_host_port(target, 443)
        forward = None
    else:
        url = urllib.parse.urlsplit(target)
        if url.scheme != 'http' or not url.hostname:
            await _refuse(client_writer, f"unsupported proxy request: {target}")
            return
        host, port = url.hostname, url.port or 80
        path = urllib.parse.urlunsplit(('', '', url.path or '/', url.query, ''))
        forward = f"{method} {path} {version}\r\n".encode('latin-1') + rest

    loop = asyncio.get_running_loop()
    try:
        address = await loop.run_in_executor(None, resolve_allowed, host, port)
    except PermissionError as e:
        await _refuse(client_writer, str(e))
        return
    except OSError as e:
        await _refuse(client_writer, f"cannot resolve {host}: {e}")
        return

    try:
        upstream_reader, upstream_writer = await asyncio.open_connection(address, port)
    except OSError as e:
        await _refuse(client_writer, f"cannot connect to {host}: {e}")
        return

    if forward is None:
        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()
    else:
        upstream_writer.write(forward)
        await upstream_writer.drain()

    await asyncio.gather(_pipe(client_reader, upstream_writer),
                         _pipe(upstream_reader, client_writer))


def _serve(ready: threading.Event, holder: list):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    server = loop.run_until_complete(asyncio.start_server(_handle, '127.0.0.1', 0))
    holder.append(server.sockets[0].getsockname()[1])
    ready.set()
    loop.run_forever()


def ensure_started() -> int:
    """Starts the guard once per process and returns the port it listens on."""
    global _port
    with _lock:
        if _port is None:
            ready = threading.Event()
            holder = []
            threading.Thread(target=_serve, args=(ready, holder), daemon=True,
                             name='egress-guard').start()
            ready.wait()
            _port = holder[0]
            logging.debug("Egress guard listening on 127.0.0.1:%d", _port)
        return _port


def chrome_arguments(port: int) -> list:
    """Flags that route all of Chrome's traffic through the guard."""
    return [
        '--proxy-server=http://127.0.0.1:%d' % port,
        # Chrome bypasses any proxy for loopback unless told not to.
        '--proxy-bypass-list=<-loopback>',
        # WebRTC UDP would otherwise leave outside the proxy.
        '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
    ]
