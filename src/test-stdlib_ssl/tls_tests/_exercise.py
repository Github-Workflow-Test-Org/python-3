from __future__ import print_function

from tls_tests import libssl_connect_all, connect_with
from tls_tests.libssl_connect_all import DEFAULT_TLS_PORT

from pytest_livehttps import LiveHTTPS_Server, mk_ssl_context, create_self_certificate

from inspect import getmembers, isfunction, getargspec
from os import unlink
import traceback
import logging
import ssl


TEST_BASE_PORT = DEFAULT_TLS_PORT
TEST_HOSTS = [
    {'name': 'good',
     'realhost': 'localhost',
     'cn': 'localhost'},
    {'name': 'badhost',
     'realhost': 'localhost',
     'cn': 'badhostname'}
]

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
LOG = logging.getLogger(__name__)

for i in range(0, len(TEST_HOSTS)):
    TEST_HOSTS[i]['port'] = TEST_BASE_PORT + i

    (cert, key) = create_self_certificate(
        basename=TEST_HOSTS[i]['name'],
        cert_data={'CN': TEST_HOSTS[i]['cn']})

    TEST_HOSTS[i]['context'] = mk_ssl_context(cert, key)
    LOG.info("Starting server '{name}' on '{port}'".format(
        name=TEST_HOSTS[i]['name'],
        port=TEST_HOSTS[i]['port']))

    TEST_HOSTS[i]['server'] = LiveHTTPS_Server(
        port=TEST_HOSTS[i]['port'],
        ssl_context=TEST_HOSTS[i]['context'])

    TEST_HOSTS[i]['server'].run()


functions = []

for func in [o for o in getmembers(libssl_connect_all) if isfunction(o[1])]:
    # TODO set up functioning CA cert
    # TODO use cadata (bytes of cert chain) instead
    # print(func)
    (funcname, connector) = func
    for h in range(0, len(TEST_HOSTS)):
        host = TEST_HOSTS[h]
        certfile = host['context'][0]
        try:
            socket = connect_with(
                connector=connector,
                host=host['realhost'], port=host['port'],
                cafile=certfile)
            socket.do_handshake()
        except Exception as e:
            LOG.info("'{}' produced '{}' when using '{}'".format(
                funcname, type(e).__name__, host['name']))

            if funcname.startswith('cwe297') and isinstance(e, ssl.CertificateError):
                traceback.print_exc(e)
                raise e

            if isinstance(e, ssl.CertificateError):
                LOG.info("'{}' completed on '{}' (Cert verification failed)".format(funcname, host['name']))
            else:
                traceback.print_exc(e)
                LOG.error("'{}' FAILED on '{}'".format(funcname, host['name']))

    args = getargspec(connector)
    functions.append({'name': funcname, 'args': args})


LOG.info("Completed run, shutting down servers")
for host in TEST_HOSTS:
    host['server'].stop()
    for f in host['context']:
        LOG.info("Removing '{}'".format(f))
        try:
            unlink(f)
        except IOError as e:
            LOG.warning("IO Error removing '{}'".format(f))


for f in functions:
    print("{}({})".format(
        f['name'],
        ", ".join(f['args'][0])))

