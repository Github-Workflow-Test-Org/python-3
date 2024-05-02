from libssl_connect import *


def cwe297_tls_connect_disable_check_hostname(hostname=DEFAULT_TLS_HOST, port=DEFAULT_TLS_PORT, cafile=None):
    """Exercise CWE-297 (improper host check for cert validation) with ``ssl`` module
    using the default context but without properly specifying hostname for validation

    Params:
        :hostname (str optional): hostname to connect to/verify
        :port (int optional): port to connect to for TLS handshake
    """
    ssl_context = ssl.create_default_context(cafile=cafile)
    ssl_context.set_ciphers(ssl._DEFAULT_CIPHERS + ':!RC4:!3DES')

    # Flag on wrap_socket, even though the error itself is in the check_hostname setting line
    # this is because it's not a flaw until you've created a socket to use
    # arguably, it's not a flaw until connect, but...
    ssl_context.check_hostname = False  # Source of CWE-297 below
    ssl_socket = ssl_context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)

    ssl_socket.connect((hostname, port))  # CWEID 297
    return ssl_socket


def cwe297_tls_connect_disable_check_hostname_manual(hostname=DEFAULT_TLS_HOST, port=DEFAULT_TLS_PORT, cafile=None):
    """Same as above, but with manual SSL context
    """
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)  # in newer Pythons, ssl.PROTOCOL_TLS is the same
    ssl_context.options |= ssl.OP_NO_SSLv2  # required to disable SSL 2.x
    ssl_context.options |= ssl.OP_NO_SSLv3  # required to disable SSL 3.x

    # note that check_hostname isn't being set in this block
    ssl_context.verify_mode = ssl.CERT_REQUIRED  # ssl.CERT_OPTIONAL is ok too
    ssl_context.load_verify_locations(cafile)

    # noinspection PyProtectedMember
    ssl_context.set_ciphers(ssl._DEFAULT_CIPHERS + ':!RC4:!3DES')

    # Flag on wrap_socket, even though the error itself is in the check_hostname setting line
    # this is because it's not a flaw until you've created a socket to use
    # arguably, it's not a flaw until connect, but...
    ssl_socket = ssl_context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)

    # This is because check_hostname is False by default, which means host won't be verified.
    ssl_socket.connect((hostname, port))  # CWEID 297
    return ssl_socket