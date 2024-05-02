from __future__ import print_function

from tls_tests.libssl_connect_all import *

from pytest_livehttps import LiveHTTPS_Server, mk_ssl_context, create_self_certificate

import ssl
import os

# set up a couple of certificates
(good_cert_file, good_key_file) = create_self_certificate('good', cert_data={'CN': 'localhost'})
(bad_cert_file, bad_key_file) = create_self_certificate('badhostname', cert_data={'CN': 'veracode.com'})

# set up servers to test against
GOOD_TEST_PORT = 8443
good_server = LiveHTTPS_Server(port=GOOD_TEST_PORT, ssl_context=mk_ssl_context(good_cert_file, good_key_file))

BAD_TEST_PORT = GOOD_TEST_PORT + 1
bad_server = LiveHTTPS_Server(port=BAD_TEST_PORT, ssl_context=mk_ssl_context(bad_cert_file, bad_key_file))

#----------
# try conneting to servers
good_server.run()
hostname='localhost'
port=GOOD_TEST_PORT
cafile=good_cert_file

assert isinstance(cwe295_tls_connect_certdisabled(hostname, port, cafile), ssl.SSLSocket)
assert isinstance(cwe295_tls_connect_certdisabled_manual(hostname, port, cafile), ssl.SSLSocket)

assert isinstance(cwe297_tls_connect_disable_check_hostname(hostname, port, cafile), ssl.SSLSocket)
assert isinstance(cwe297_tls_connect_disable_check_hostname_manual(hostname, port, cafile), ssl.SSLSocket)

assert isinstance(cwe326_tls_connect_oldssl_version(hostname, port, cafile), ssl.SSLSocket)
assert isinstance(cwe326_tls_connect_oldssl_version_manual(hostname, port, cafile), ssl.SSLSocket)

assert isinstance(cwe326_tls_connect_weak_ciphers_not_excluded(hostname, port, cafile), ssl.SSLSocket)
assert isinstance(cwe326_tls_connect_weak_ciphers_not_excluded_manual(hostname, port, cafile), ssl.SSLSocket)

assert isinstance(safe_tls_connect(hostname, port, cafile), ssl.SSLSocket)
assert isinstance(safe_tls_connect_manual(hostname, port, cafile), ssl.SSLSocket)

good_server.stop()
os.unlink(good_cert_file)
os.unlink(good_key_file)

#-----------
# try connecting to servers with bad hosts
bad_server.run()
port=BAD_TEST_PORT
cafile=bad_cert_file

# this is safe, so connecting to a bad cert should raise an error
try:
    safe_tls_connect(hostname, port, cafile)
    raise RuntimeError("Shouldn't get here with bad hostname")  # raises an error if safe thing works, it shouldn't
except ssl.CertificateError as e:
    # This _should_ be raised, so we pass
    pass

# this is safe, so connecting to a bad cert should raise an error
try:
    safe_tls_connect_manual(hostname, port, cafile)
    raise RuntimeError("Shouldn't get here with bad hostname")  # raises an error if safe thing works, it shouldn't
except ssl.CertificateError as e:
    # This _should_ be raised, so we pass
    pass

# These should connect ok to the bad host because they don't properly verify the cert in some way
cwe295_tls_connect_certdisabled(hostname, port, cafile)
cwe295_tls_connect_certdisabled_manual(hostname, port, cafile)

cwe297_tls_connect_disable_check_hostname(hostname, port, cafile)
cwe297_tls_connect_disable_check_hostname_manual(hostname, port, cafile)

bad_server.stop()
os.unlink(bad_cert_file)
os.unlink(bad_key_file)