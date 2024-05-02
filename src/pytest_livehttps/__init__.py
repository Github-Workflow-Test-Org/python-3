import multiprocessing
import ssl

import time

# load the right lib for urlopen/URLError based on py2 or 3.
try:
    # noinspection PyCompatibility
    from urllib2 import urlopen, URLError
except ImportError:
    # noinspection PyCompatibility
    from urllib.request import urlopen
    # noinspection PyCompatibility
    from urllib.error import URLError

from flask import Flask
import os

import logging

logger = logging.getLogger(__name__)


def create_self_certificate(basename='cert', single_file=False, cert_data=None, option=None):
    from OpenSSL import crypto, SSL

    if option is None:
        option = {}

    opt = {
        'algo': crypto.TYPE_RSA,
        'bits': 4096,
        'valid_days': 30,
        'sign': 'sha512'
    }

    for key in option:
        if key in opt:
            opt[key] = option[key]
        else:
            logger.warning("create_certificate option '{}' is invalid, skipping".format(key))

    cert_file = '{}.crt'.format(basename)
    key_file = '{}.key'.format(basename)

    if single_file:
        key_file = None
        cert_file = '{}.pem'.format(basename)

    # generate a key pair
    kp = crypto.PKey()
    kp.generate_key(opt['algo'], opt['bits'])

    # container for the certificate
    # TODO: specify metadata in argument
    cert = crypto.X509()

    certdata = {
        'countryName': "US",
        'stateOrProvinceName': "Massachusets",
        'localityName': "Burlington",
        'organizationName': "Veracode Inc. SELF-SIGNING TEST CERT",
        'organizationalUnitName': "Testing Certificate",
        'emailAddress': "testing_only@veracode.com",
        'CN': "localhost"
    }

    if cert_data is not None:
        for key in cert_data:
            if key not in certdata:
                raise AttributeError("certificate data element '{}' unknown".format(key))

        # noinspection PyUnboundLocalVariable
        certdata[key] = cert_data[key]

    cert_meta = cert.get_subject()
    cert_meta.countryName = certdata['countryName']
    cert_meta.stateOrProvinceName = certdata['stateOrProvinceName']
    cert_meta.localityName = certdata['localityName']
    cert_meta.organizationName = certdata['organizationName']
    cert_meta.organizationalUnitName = certdata['organizationalUnitName']
    cert_meta.emailAddress = certdata['emailAddress']
    cert_meta.CN = certdata['CN']

    cert.set_subject(cert_meta)
    cert.set_issuer(cert.get_subject())  # self-signed!
    cert.set_pubkey(kp)

    # set expiration and serial
    now = int(time.time())
    cert.set_serial_number(now)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(opt['valid_days'] * 86400)  # 86400 seconds in a day

    cert.sign(kp, opt['sign'])

    # write to files
    with open(cert_file, "wt") as cf:
        cf.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('ascii'))
        logger.info("Wrote cert to '{}'".format(cert_file))
        if single_file or (key_file is None):
            cf.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, kp).decode('ascii'))
            logger.warn("Added private key to certificate file '{}'".format(cert_file))
        else:
            with open(key_file, "wt") as kf:
                kf.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, kp).decode('ascii'))
                logger.info("Wrote private key to '{}'".format(cert_file))

    return cert_file, key_file


def mk_ssl_context(certfile, keyfile):
    """helper method to have clearer ssl_context tuple creation

    uses e.g. ``context = mk_ssl_context(certfile="certfile", keyfile="keyfile")``

    :param certfile: path to certificate file
    :param keyfile: path to key file associated with certfile
    :return: tuple suitable for ssl_context
    """
    if not os.path.exists(certfile):
        raise IOError('"{}" is not a valid path for certfile'.format(certfile))

    if not os.path.exists(keyfile):
        raise IOError('"{}" is not a valid path for keyfile'.format(keyfile))

    retval = (certfile, keyfile)  # tuple
    return retval


class LiveHTTPS_Server(object):

    def __init__(self, app=None, port=8443, ssl_context=None):
        self.app = app
        self.port = port
        self.ssl_context = ssl_context
        self.server_start_timeout = 5

        if self.app is None:
            self.app = Flask(__name__)

            @self.app.route('/')
            def _default_route():
                return 'ok'

        if self.ssl_context is None:
            self.ssl_context = self.default_ssl_context()

        self._process = None

    @staticmethod
    def default_ssl_context():
        path = os.path.dirname(os.path.realpath(__file__))
        try:
            context = mk_ssl_context(certfile=os.path.join(path, 'cert.crt'),
                                     keyfile=os.path.join(path, 'cert.key'))
        except IOError:
            # generate the keys and try again
            cert, key = create_self_certificate()
            context = mk_ssl_context(certfile=cert, keyfile=key)

        return context

    def run(self):
        def app_worker(app, port, ssl_context):
            app.run(port=port,
                    use_reloader=False,
                    threaded=True,
                    ssl_context=ssl_context)

        self._process = multiprocessing.Process(
            target=app_worker,
            args=(self.app, self.port, self.ssl_context)
        )
        self._process.start()

        timeout = self.server_start_timeout
        sleep_inc = 0.2

        # We don't want to do SSL verification here, in case consumers
        # want to handle things "by hand"
        ping_context = ssl.create_default_context()
        ping_context.check_hostname = False
        ping_context.verify_mode = ssl.CERT_NONE

        while timeout > 0:
            time.sleep(sleep_inc)
            try:
                urlopen(self.url(), context=ping_context)
                timeout = 0
            except URLError:
                timeout -= sleep_inc

        return self._process

    def __del__(self):
        if self._process:
            self._process.terminate()

    def stop(self):
        if self._process:
            self._process.terminate()

    def url(self, path=''):
        return "https://localhost:{}{}".format(self.port, path)
