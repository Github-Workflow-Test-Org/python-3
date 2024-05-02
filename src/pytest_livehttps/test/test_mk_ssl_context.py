from unittest import TestCase
import os


class TestMk_ssl_context(TestCase):
    def setUp(self):
        from src.pytest_livehttps import create_self_certificate
        self.cert, self.key = create_self_certificate('test')

    def tearDown(self):
        for f in (self.cert, self.key):
            try:
                os.unlink(f)
            except IOError:
                pass  # it's ok.

    def test_mk_ssl_context(self):
        from src.pytest_livehttps import mk_ssl_context, create_self_certificate
        with self.assertRaises(IOError):
            ssl_context = mk_ssl_context('none', 'none')

        ssl_context = mk_ssl_context(self.cert, self.key)
        self.assertEquals(self.cert, ssl_context[0])
        self.assertEquals(self.key, ssl_context[1])
