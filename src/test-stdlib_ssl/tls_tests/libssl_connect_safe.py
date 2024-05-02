from libssl_connect import *


def safe_tls_connect(hostname=DEFAULT_TLS_HOST, port=DEFAULT_TLS_PORT, cafile=None):
    ssl_context = ssl.create_default_context(cafile=cafile)

    # we assume 2.7.9 version of create_default_context, so we have to remove:
    # - RC4, which was removed in 2.7.10
    # - 3DES, which was removed in 2.7.13
    # See the `set_ciphers` section of notes.rst for details about scanning and
    # scrubbing

    # noinspection PyProtectedMember
    ssl_context.set_ciphers(ssl._DEFAULT_CIPHERS + ':!RC4:!3DES')

    # wrap a stream socket with the configured context to create an SSLContext
    ssl_socket = ssl_context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname)

    # attempt the connection. As of 2.7.9, when context.set_hostname is True,
    # calling .connect() will verify the hostname.
    ssl_socket.connect((hostname, port))
    return ssl_socket


def safe_tls_connect_manual(hostname=DEFAULT_TLS_HOST, port=DEFAULT_TLS_PORT, cafile=None):
    """Same as `safe_tls_connect` but with a manual SSLContext
    """
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)  # in newer Pythons, ssl.PROTOCOL_TLS is the same
    ssl_context.options |= ssl.OP_NO_SSLv2  # required to disable SSL 2.x
    ssl_context.options |= ssl.OP_NO_SSLv3  # required to disable SSL 3.x

    ssl_context.verify_mode = ssl.CERT_REQUIRED  # ssl.CERT_OPTIONAL is ok too
    ssl_context.check_hostname = True
    ssl_context.load_verify_locations(cafile)

    # noinspection PyProtectedMember
    ssl_context.set_ciphers(ssl._DEFAULT_CIPHERS + ':!RC4:!3DES')

    ssl_socket = ssl_context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname)

    # attempt the connection. As of 2.7.9, when context.set_hostname is True,
    # calling .connect() will verify the hostname.
    ssl_socket.connect((hostname, port))
    return ssl_socket
