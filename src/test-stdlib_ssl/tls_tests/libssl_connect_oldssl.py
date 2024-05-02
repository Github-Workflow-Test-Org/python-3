from libssl_connect import *


def cwe326_tls_connect_oldssl_version(hostname=DEFAULT_TLS_HOST, port=DEFAULT_TLS_PORT, cafile=None):
    """Exercise CWE-326 (Inadequate encryption strength) by using outdated/risky SSL versions

    Defaults as of 2.7.9 are reasonable, but SSLv3 and SSLv2 can be explicitly enabled, which
    is a flaw

    """
    ssl_context = ssl.create_default_context(cafile=cafile)
    ssl_context.set_ciphers(ssl._DEFAULT_CIPHERS + ':!RC4:!3DES')

    # The lines below _enable_ SSLv3 and SSLv2, respectively; these are outdated and should
    # not be in use any longer.
    ssl_context.options &= ~ssl.OP_NO_SSLv3  # CWE-326 first source
    ssl_context.options &= ~ssl.OP_NO_SSLv2  # CWE-326 second source

    ssl_socket = ssl_context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname)

    ssl_socket.connect((hostname, port))  # CWEID 326
    return ssl_socket


def cwe326_tls_connect_oldssl_version_manual(hostname=DEFAULT_TLS_HOST, port=DEFAULT_TLS_PORT, cafile=None):
    """Same as above, with manual SSLContext
    """
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)  # in newer Pythons, ssl.PROTOCOL_TLS is the same
    # note that SSLv2 and SSLv3 are not disabled! Some newer Pythons do by default, but not our targets

    ssl_context.verify_mode = ssl.CERT_REQUIRED  # ssl.CERT_OPTIONAL is ok too
    ssl_context.check_hostname = True
    ssl_context.load_verify_locations(cafile)

    # noinspection PyProtectedMember
    ssl_context.set_ciphers(ssl._DEFAULT_CIPHERS + ':!RC4:!3DES')

    ssl_socket = ssl_context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname)

    ssl_socket.connect((hostname, port))  # CWEID 326
    return ssl_socket