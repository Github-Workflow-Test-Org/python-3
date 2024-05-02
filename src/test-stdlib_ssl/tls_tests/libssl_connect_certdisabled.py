from libssl_connect import *


def cwe295_tls_connect_certdisabled(hostname=DEFAULT_TLS_HOST, port=DEFAULT_TLS_PORT, cafile=None):
    """Exercise CWE-297 (improper host check for cert validation) with ``ssl`` module
    using the default context but making certificate checks optional or none

    Params:
        :hostname (str optional): hostname to connect to/verify
        :port (int optional): port to connect to for TLS handshake
    """
    ssl_context = ssl.create_default_context(cafile=cafile)
    ssl_context.set_ciphers(ssl._DEFAULT_CIPHERS + ':!RC4:!3DES')
    ssl_context.check_hostname = False  # source of CWE-297
    ssl_context.verify_mode = ssl.CERT_NONE  # source of CWE-295

    ssl_socket = ssl_context.wrap_socket(  # propagates CERT_NONE to .connect() below
        socket.socket(socket.AF_INET),
        server_hostname=hostname)

    # This doesn't verify the hostname, because cert checking is disabled above
    ssl_socket.connect((hostname, port))  # CWEID 297  # CWEID 295
    return ssl_socket


def cwe295_tls_connect_certdisabled_manual(hostname=DEFAULT_TLS_HOST, port=DEFAULT_TLS_PORT, cafile=None):
    """Same as above, except with manual SSLContext
    """
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)  # in newer Pythons, ssl.PROTOCOL_TLS is the same
    ssl_context.options |= ssl.OP_NO_SSLv2  # required to disable SSL 2.x
    ssl_context.options |= ssl.OP_NO_SSLv3  # required to disable SSL 3.x

    ssl_context.load_verify_locations(cafile)

    # noinspection PyProtectedMember
    ssl_context.set_ciphers(ssl._DEFAULT_CIPHERS + ':!RC4:!3DES')

    ssl_socket = ssl_context.wrap_socket(  # propagates CERT_NONE to .connect() below
        socket.socket(socket.AF_INET),
        server_hostname=hostname)

    # This doesn't verify the hostname, because cert checking is disabled by default
    # verify_hostname also has to be set False for this not to raise an exception, but
    # that's ok, that's the default too
    ssl_socket.connect((hostname, port))  # CWEID 297  # CWEID 295
    return ssl_socket
