import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import egress_guard


class _Hello(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"hello"
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _proxy_exchange(request: bytes) -> bytes:
    port = egress_guard.ensure_started()
    with socket.create_connection(('127.0.0.1', port), timeout=10) as sock:
        sock.sendall(request)
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            if request.startswith(b'CONNECT') and b'\r\n\r\n' in b''.join(chunks):
                break
        return b''.join(chunks)


class TestForbiddenAddresses(unittest.TestCase):

    def tearDown(self):
        egress_guard.allow_loopback = False

    def test_private_loopback_and_metadata_addresses_are_forbidden(self):
        for address in ['127.0.0.1', '10.0.0.1', '172.16.0.1', '192.168.1.1', '169.254.169.254',
                        '100.64.0.1', '0.0.0.0', '224.0.0.1', '::1', 'fe80::1', 'fc00::1',
                        '::ffff:10.0.0.1', '::ffff:127.0.0.1']:
            self.assertTrue(egress_guard.is_forbidden_ip(address), address)

    def test_public_addresses_are_allowed(self):
        for address in ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']:
            self.assertFalse(egress_guard.is_forbidden_ip(address), address)

    def test_the_test_switch_exempts_loopback_only(self):
        egress_guard.allow_loopback = True
        self.assertFalse(egress_guard.is_forbidden_ip('127.0.0.1'))
        self.assertFalse(egress_guard.is_forbidden_ip('::1'))
        self.assertTrue(egress_guard.is_forbidden_ip('10.0.0.1'))
        self.assertTrue(egress_guard.is_forbidden_ip('169.254.169.254'))


class TestProxy(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), _Hello)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def tearDown(self):
        egress_guard.allow_loopback = False

    def test_a_tunnel_to_a_forbidden_address_is_refused(self):
        response = _proxy_exchange(b'CONNECT 169.254.169.254:443 HTTP/1.1\r\n'
                                   b'Host: 169.254.169.254:443\r\n\r\n')
        self.assertTrue(response.startswith(b'HTTP/1.1 403'), response)

    def test_a_plain_request_to_loopback_is_refused_by_default(self):
        response = _proxy_exchange(
            b'GET http://127.0.0.1:%d/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n' % self.port)
        self.assertTrue(response.startswith(b'HTTP/1.1 403'), response)
        self.assertNotIn(b'hello', response)

    def test_an_allowed_plain_request_is_forwarded(self):
        egress_guard.allow_loopback = True
        response = _proxy_exchange(
            b'GET http://127.0.0.1:%d/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'
            % self.port)
        self.assertTrue(response.startswith(b'HTTP/1.0 200') or response.startswith(b'HTTP/1.1 200'),
                        response)
        self.assertTrue(response.endswith(b'hello'), response)

    def test_an_allowed_tunnel_is_established(self):
        egress_guard.allow_loopback = True
        response = _proxy_exchange(b'CONNECT 127.0.0.1:%d HTTP/1.1\r\n'
                                   b'Host: 127.0.0.1\r\n\r\n' % self.port)
        self.assertTrue(response.startswith(b'HTTP/1.1 200'), response)

    def test_chrome_routes_loopback_through_the_guard(self):
        arguments = egress_guard.chrome_arguments(1234)
        self.assertIn('--proxy-server=http://127.0.0.1:1234', arguments)
        self.assertIn('--proxy-bypass-list=<-loopback>', arguments)


if __name__ == '__main__':
    unittest.main()
