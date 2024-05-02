from __future__ import print_function

import os
from ssl import CertificateError
from unittest import TestCase

try:
    # noinspection PyCompatibility
    from urllib2 import urlopen, URLError
except ImportError:
    # noinspection PyCompatibility
    from urllib.request import urlopen
    # noinspection PyCompatibility
    from urllib.error import URLError

testport = 8443


class TestLiveHTTPS_Server(TestCase):
    def setUp(self):
        from src.pytest_livehttps import create_self_certificate, mk_ssl_context
        self.cert, self.key = create_self_certificate('cert')
        self.ssl_context = mk_ssl_context(certfile=self.cert, keyfile=self.key)

    def tearDown(self):
        for f in (self.cert, self.key):
            try:
                os.unlink(f)
                pass
            except IOError:
                pass  # it's ok.

    def _make_server(self, port=testport):
        from src.pytest_livehttps import LiveHTTPS_Server
        server = LiveHTTPS_Server(port=testport,
                                  ssl_context=self.ssl_context)
        return server

    def test_url(self):
        server = self._make_server()

        assert server.url() == 'https://localhost:{}'.format(testport)
        assert server.url('/testpath') == 'https://localhost:{}/testpath'.format(testport)

    def test_run(self):
        server = self._make_server()
        server.run()

        cafile = self.cert

        assert server._process
        assert urlopen('https://localhost:{}'.format(testport),
                       cafile=cafile)

    def test_end(self):
        server = self._make_server()
        server.run()
        assert server._process

        cafile = self.cert

        server.stop()
        with self.assertRaises(URLError):
            # when server is destroyed, process should terminate
            urlopen('https://localhost:{}'.format(testport), cafile=cafile, timeout=1)

    def test_default_ssl_context(self):
        from src.pytest_livehttps import LiveHTTPS_Server
        (cert, key) = LiveHTTPS_Server.default_ssl_context()

        assert cert.endswith('cert.crt')
        assert key.endswith('cert.key')

    def test_host_mismatch(self):
        from src.pytest_livehttps import \
            LiveHTTPS_Server, \
            mk_ssl_context, \
            create_self_certificate
        cert, key = create_self_certificate('badname', cert_data={'CN': 'badname'})
        ssl_context = mk_ssl_context(certfile=cert, keyfile=key)
        server = LiveHTTPS_Server(port=testport, ssl_context=ssl_context)

        server.run()
        with self.assertRaises(CertificateError):
            # should be a cert error
            urlopen('https://localhost:{}'.format(testport),
                    cafile=cert,
                    timeout=1)

        for f in cert, key:
            try:
                os.unlink(f)
            except IOError:
                pass  # it's ok, they might not have existed
